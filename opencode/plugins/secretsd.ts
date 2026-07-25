import { randomBytes } from "crypto";
import { chmodSync, mkdirSync, renameSync, rmSync, writeFileSync } from "fs";
import { tool } from "@opencode-ai/plugin";
import { join } from "path";

// allow: SIZE_OK — one closure must own a session's token, broker lifecycle, and cancellation state.
export type SessionState = {
  readonly token: string;
  readonly tokenFile: string;
};

type PluginOptions = {
  readonly runtimeDir?: string;
  readonly socketPath?: string;
  readonly pid?: number;
};

type ShellInput = { readonly sessionID?: string };
type ShellOutput = { env: Record<string, string> };

const decoder = new TextDecoder();
const CONTROL_TIMEOUT_MS = 2_000;
const SESSION_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;

export const REQUEST_TIMEOUT_MS = 100_000;

export const DAEMON_ERROR_CODES = [
  "BAD_REQUEST",
  "UNKNOWN_OP",
  "VERSION_MISMATCH",
  "UNKNOWN_TOKEN",
  "NO_SCOPE",
  "AGENT_TTY",
  "NOT_HUMAN_KEY",
  "DENIED",
  "TIMEOUT",
  "YUBIKEY_UNREACHABLE",
  "TOO_MANY_PENDING",
  "INTERNAL",
] as const;

export type DaemonErrorCode = (typeof DAEMON_ERROR_CODES)[number];

const DAEMON_ERROR_GUIDANCE = {
  BAD_REQUEST: "error: secretsd rejected this request as malformed; verify the key name and report the request if it persists.",
  UNKNOWN_OP: "error: secretsd does not support the requested operation; update OpenCode and secretsd to matching versions.",
  VERSION_MISMATCH: "error: secretsd protocol version mismatch; restart or update secretsd and OpenCode before requesting a secret.",
  UNKNOWN_TOKEN: "error: secretsd lost this session's registration after automatic re-registration; start a new OpenCode session and retry.",
  NO_SCOPE: "error: secretsd cannot attribute this request to a session because no session token or tty was provided; start it from a registered OpenCode session.",
  AGENT_TTY: "error: secretsd rejected a tokenless request from a tty already assigned to an agent session; use the registered session token.",
  NOT_HUMAN_KEY: "not human-tier: no approval is needed for this key; read it directly with `secrets get <KEY>`. If that read fails, the key is not configured.",
  DENIED: "denied: human approval was refused; do not retry unless the human asks you to.",
  TIMEOUT: "timed out: no one approved the request in time; make a new request only if approval is still needed.",
  YUBIKEY_UNREACHABLE: "error: the YubiKey or its tunnel is unreachable; restore the hardware or tunnel connection and retry.",
  TOO_MANY_PENDING: "error: this session already has too many approvals pending; wait for an existing request to be resolved before requesting again.",
  INTERNAL: "error: secretsd failed while decrypting; inspect `journalctl --user -u secretsd` for the daemon's sops stderr.",
} as const satisfies Record<DaemonErrorCode, string>;

type RequestOutcome =
  | { readonly kind: "broker-unreachable" }
  | { readonly kind: "broker-unresponsive" }
  | { readonly kind: "daemon-error"; readonly code: DaemonErrorCode }
  | { readonly kind: "granted" }
  | { readonly kind: "request-cancelled" }
  | { readonly kind: "runtime-unavailable" }
  | { readonly kind: "unexpected-broker-response" }
  | { readonly kind: "unexpected-error" };
type SecretRequest = {
  readonly state: SessionState;
  readonly sessionID: string;
  readonly pid: number;
  readonly key: string;
  readonly signal: AbortSignal;
  readonly reregister: () => Promise<void>;
};

class InvalidSessionIDError extends Error {
  readonly name = "InvalidSessionIDError";

  constructor() {
    super("invalid session ID");
  }
}

class BrokerError extends Error {
  readonly name: string = "BrokerError";
}

class BrokerUnavailableError extends BrokerError {
  readonly name = "BrokerUnavailableError";
}

class BrokerUnresponsiveError extends BrokerError {
  readonly name = "BrokerUnresponsiveError";
}

class BrokerProtocolError extends BrokerError {
  readonly name = "BrokerProtocolError";
}

class BrokerRequestCancelledError extends BrokerError {
  readonly name = "BrokerRequestCancelledError";
}

class ProtocolVersionMismatch extends Error {
  readonly name = "ProtocolVersionMismatch";

  constructor() {
    super("secretsd protocol version mismatch");
  }
}

function validateSessionID(sessionID: string): void {
  if (!SESSION_ID_PATTERN.test(sessionID)) {
    throw new InvalidSessionIDError();
  }
}

function tokenDirectory(runtimeDir: string): string {
  return join(runtimeDir, "secretsd");
}

function tokenFile(runtimeDir: string, sessionID: string): string {
  validateSessionID(sessionID);
  return join(tokenDirectory(runtimeDir), `${sessionID}.token`);
}

export function issueTokenFile(runtimeDir: string, sessionID: string): SessionState {
  const directory = tokenDirectory(runtimeDir);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  chmodSync(directory, 0o700);

  const tokenPath = tokenFile(runtimeDir, sessionID);
  const token = randomBytes(32).toString("hex");
  // Stage then rename: a concurrent reader sees either no file or the whole
  // token, never a truncated one. `wx` refuses to write through a pre-planted
  // path, and the mode is fixed before the token is reachable at its real name.
  const stagingPath = `${tokenPath}.${randomBytes(6).toString("hex")}.tmp`;
  writeFileSync(stagingPath, token, { encoding: "utf8", mode: 0o600, flag: "wx" });
  chmodSync(stagingPath, 0o600);
  renameSync(stagingPath, tokenPath);
  return { token, tokenFile: tokenPath };
}

export function removeTokenFile(state: SessionState): void {
  rmSync(state.tokenFile, { force: true });
}

class BrokerClient {
  constructor(private readonly socketPath: string) {}

  private async line(command: string, timeoutMs: number, signal?: AbortSignal): Promise<string> {
    return new Promise((resolve, reject) => {
      let response = "";
      let settled = false;
      let closeSocket: (() => void) | undefined;
      let timer: ReturnType<typeof setTimeout> | undefined;
      const abort = () => {
        finish(new BrokerRequestCancelledError("broker request aborted"));
        closeSocket?.();
      };
      const finish = (result: string | Error) => {
        if (settled) {
          return;
        }
        settled = true;
        if (timer) {
          clearTimeout(timer);
        }
        signal?.removeEventListener("abort", abort);
        if (result instanceof Error) {
          reject(result);
        } else {
          resolve(result);
        }
      };

      if (signal?.aborted) {
        abort();
        return;
      }
      signal?.addEventListener("abort", abort, { once: true });
      timer = setTimeout(() => {
        finish(new BrokerUnresponsiveError("broker timeout"));
        closeSocket?.();
      }, timeoutMs);
      Bun.connect({
        unix: this.socketPath,
        socket: {
          open(socket) {
            if (settled) {
              socket.end();
              return;
            }
            closeSocket = () => socket.end();
            socket.write(`${command}\n`);
          },
          data(socket, data) {
            response += decoder.decode(data);
            const newline = response.indexOf("\n");
            if (newline >= 0) {
              finish(response.slice(0, newline));
              socket.end();
            }
          },
          error() {
            finish(new BrokerUnavailableError("broker connection failed"));
          },
          close() {
            if (!settled) {
              finish(new BrokerProtocolError("broker closed without a response"));
            }
          },
        },
      }).catch(() => finish(new BrokerUnavailableError("broker connection failed")));
    });
  }

  private async command(message: string, timeoutMs = CONTROL_TIMEOUT_MS, signal?: AbortSignal): Promise<string> {
    const hello = await this.line("HELLO\tversion=1", CONTROL_TIMEOUT_MS, signal);
    if (hello === "ERR\tVERSION_MISMATCH" || hello.startsWith("ERR\tVERSION_MISMATCH\t")) {
      throw new ProtocolVersionMismatch();
    }
    if (hello !== "OK\tversion=1") {
      throw new BrokerProtocolError("broker rejected HELLO");
    }
    const response = await this.line(message, timeoutMs, signal);
    if (response === "ERR\tVERSION_MISMATCH" || response.startsWith("ERR\tVERSION_MISMATCH\t")) {
      throw new ProtocolVersionMismatch();
    }
    return response;
  }

  async register(state: SessionState, sessionID: string, pid: number): Promise<void> {
    const response = await this.command(`REGISTER\ttoken=${state.token}\tsession=${sessionID}\tpid=${pid}`);
    if (response !== "OK") {
      throw new BrokerProtocolError("broker registration rejected");
    }
  }

  async unregister(sessionID: string): Promise<void> {
    const response = await this.command(`UNREGISTER\tsession=${sessionID}`);
    if (response !== "OK") {
      throw new BrokerProtocolError("broker unregistration rejected");
    }
  }

  async request(key: string, state: SessionState, signal: AbortSignal): Promise<string> {
    return this.command(`REQUEST\tkey=${key}\ttoken=${state.token}`, REQUEST_TIMEOUT_MS, signal);
  }
}

function guidance(outcome: RequestOutcome): string {
  switch (outcome.kind) {
    case "broker-unreachable":
      return "unavailable: could not reach the secretsd broker; check that secretsd is running and its socket is available.";
    case "broker-unresponsive":
      return "error: the secretsd broker did not respond before the request deadline; retry after confirming it is healthy.";
    case "daemon-error":
      return DAEMON_ERROR_GUIDANCE[outcome.code];
    case "granted":
      return "granted: read the value with `secrets get <KEY>`.";
    case "request-cancelled":
      return "error: the secretsd request was cancelled because the OpenCode session ended.";
    case "runtime-unavailable":
      return "error: the secretsd runtime directory is unavailable, so this session cannot be registered.";
    case "unexpected-broker-response":
      return "error: secretsd returned an unrecognized protocol response; restart or update secretsd and OpenCode.";
    case "unexpected-error":
      return "error: secretsd encountered an unexpected plugin failure; inspect the OpenCode and secretsd logs.";
    default:
      return assertNever(outcome);
  }
}

function assertNever(value: never): never {
  throw new Error(`unexpected request outcome: ${JSON.stringify(value)}`);
}

function responseCode(response: string): DaemonErrorCode | undefined {
  if (!response.startsWith("ERR\t")) {
    return undefined;
  }
  switch (response.split("\t", 3)[1]) {
    case "BAD_REQUEST":
      return "BAD_REQUEST";
    case "UNKNOWN_OP":
      return "UNKNOWN_OP";
    case "VERSION_MISMATCH":
      return "VERSION_MISMATCH";
    case "UNKNOWN_TOKEN":
      return "UNKNOWN_TOKEN";
    case "NO_SCOPE":
      return "NO_SCOPE";
    case "AGENT_TTY":
      return "AGENT_TTY";
    case "NOT_HUMAN_KEY":
      return "NOT_HUMAN_KEY";
    case "DENIED":
      return "DENIED";
    case "TIMEOUT":
      return "TIMEOUT";
    case "YUBIKEY_UNREACHABLE":
      return "YUBIKEY_UNREACHABLE";
    case "TOO_MANY_PENDING":
      return "TOO_MANY_PENDING";
    case "INTERNAL":
      return "INTERNAL";
    default:
      return undefined;
  }
}

function responseOutcome(response: string): RequestOutcome {
  if (response === "OK\tstatus=granted") {
    return { kind: "granted" };
  }
  const code = responseCode(response);
  if (code) {
    return { kind: "daemon-error", code };
  }
  return { kind: "unexpected-broker-response" };
}

function failureOutcome(error: unknown): RequestOutcome {
  if (error instanceof ProtocolVersionMismatch) {
    return { kind: "daemon-error", code: "VERSION_MISMATCH" };
  }
  if (error instanceof BrokerUnavailableError) {
    return { kind: "broker-unreachable" };
  }
  if (error instanceof BrokerUnresponsiveError) {
    return { kind: "broker-unresponsive" };
  }
  if (error instanceof BrokerRequestCancelledError) {
    return { kind: "request-cancelled" };
  }
  if (error instanceof BrokerProtocolError) {
    return { kind: "unexpected-broker-response" };
  }
  return { kind: "unexpected-error" };
}

async function requestSecret(broker: BrokerClient, request: SecretRequest): Promise<RequestOutcome> {
  try {
    let response = await broker.request(request.key, request.state, request.signal);
    if (responseCode(response) === "UNKNOWN_TOKEN") {
      await request.reregister();
      response = await broker.request(request.key, request.state, request.signal);
    }
    return responseOutcome(response);
  } catch (error) {
    return failureOutcome(error);
  }
}

/// The SDK declares session.deleted with `properties.info` and, in its envelope
/// form, `properties.sessionID`. Accept either so revocation is not silently
/// skipped by whichever shape the runtime delivers.
type SessionEventInput = {
  readonly event: {
    readonly type: string;
    readonly properties?: {
      readonly sessionID?: string;
      readonly info?: { readonly id?: string };
    };
  };
};

export function createSecretsdPlugin(options: PluginOptions = {}) {
  const runtimeDir = options.runtimeDir ?? process.env.XDG_RUNTIME_DIR;
  const broker = new BrokerClient(options.socketPath ?? (runtimeDir ? join(runtimeDir, "secretsd.sock") : ""));
  const pid = options.pid ?? process.pid;
  const states = new Map<string, SessionState>();
  const registered = new Set<string>();
  const registrations = new Map<string, Promise<SessionState | undefined>>();
  const requestAbort = new AbortController();

  function ensureState(sessionID: string): SessionState | undefined {
    if (!runtimeDir) {
      return undefined;
    }
    const existing = states.get(sessionID);
    if (existing) {
      return existing;
    }
    const state = issueTokenFile(runtimeDir, sessionID);
    states.set(sessionID, state);
    return state;
  }

  async function ensureRegistered(sessionID: string): Promise<SessionState | undefined> {
    const state = ensureState(sessionID);
    if (!state) {
      return undefined;
    }
    if (registered.has(sessionID)) {
      return state;
    }
    const inFlight = registrations.get(sessionID);
    if (inFlight) {
      return inFlight;
    }
    const registration = broker
      .register(state, sessionID, pid)
      .then(() => {
        registered.add(sessionID);
        return state;
      })
      .finally(() => {
        registrations.delete(sessionID);
      });
    registrations.set(sessionID, registration);
    return registration;
  }

  function removeState(sessionID: string, state: SessionState): void {
    try {
      removeTokenFile(state);
    } finally {
      states.delete(sessionID);
      registered.delete(sessionID);
      registrations.delete(sessionID);
    }
  }

  const hooks = {
    "shell.env": async (input: ShellInput, output: ShellOutput): Promise<void> => {
      // no-excuse-ok: catch — plugin hooks must not prevent a shell from starting.
      try {
        if (input.sessionID) {
          const state = await ensureRegistered(input.sessionID);
          if (state) {
            output.env.SECRETSD_SESSION_TOKEN_FILE = state.tokenFile;
          }
        }
      } catch {
        return;
      }
    },
    event: async ({ event }: SessionEventInput): Promise<void> => {
      // Revoke at session end. `dispose` only runs when the whole serve process
      // exits, and the daemon's backstop is hours out, so without this a finished
      // session's token file and grant stay usable by any same-uid process.
      if (event.type !== "session.deleted") {
        return;
      }
      const sessionID = event.properties?.sessionID ?? event.properties?.info?.id;
      if (!sessionID) {
        return;
      }
      const state = states.get(sessionID);
      if (!state) {
        return;
      }
      // no-excuse-ok: catch — an unreachable broker must not strand the token file.
      try {
        await broker.unregister(sessionID);
      } finally {
        removeState(sessionID, state);
      }
    },
    tool: {
      secrets_request: tool({
        description: "Request human approval for a secretsd human-tier key; never returns secret values.",
        args: { key: tool.schema.string().regex(/^[A-Z][A-Z0-9_]*$/) },
        async execute({ key }, context) {
          try {
            const state = await ensureRegistered(context.sessionID);
            if (!state) {
              return guidance({ kind: "runtime-unavailable" });
            }
            return guidance(
              await requestSecret(broker, {
                state,
                sessionID: context.sessionID,
                pid,
                key,
                signal: requestAbort.signal,
                reregister: async () => {
                  registered.delete(context.sessionID);
                  await ensureRegistered(context.sessionID);
                },
              }),
            );
          } catch (error) {
            // no-excuse-ok: catch — tool results must not surface broker failures.
            return guidance(failureOutcome(error));
          }
        },
      }),
    },
    dispose: async (): Promise<void> => {
      requestAbort.abort();
      await Promise.allSettled(
        [...states.entries()].map(async ([sessionID, state]) => {
          try {
            await broker.unregister(sessionID);
          } catch {
            return;
          } finally {
            removeState(sessionID, state);
          }
        }),
      );
    },
  };

  return { hooks, states };
}

export default {
  id: "secretsd",
  server: async () => createSecretsdPlugin().hooks,
};
