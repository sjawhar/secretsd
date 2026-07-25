import { randomBytes } from "crypto";
import { chmodSync, mkdirSync, rmSync, writeFileSync } from "fs";
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

type RequestStatus = "granted" | "denied" | "unavailable";
type RequestOutcome = { readonly status: RequestStatus; readonly versionMismatch: boolean };
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
  readonly name = "BrokerError";
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
  writeFileSync(tokenPath, token, { encoding: "utf8", mode: 0o600 });
  chmodSync(tokenPath, 0o600);
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
        finish(new BrokerError("broker request aborted"));
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
        finish(new BrokerError("broker timeout"));
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
            finish(new BrokerError("broker connection failed"));
          },
          close() {
            if (!settled) {
              finish(new BrokerError("broker closed without a response"));
            }
          },
        },
      }).catch(() => finish(new BrokerError("broker connection failed")));
    });
  }

  private async command(message: string, timeoutMs = CONTROL_TIMEOUT_MS, signal?: AbortSignal): Promise<string> {
    const hello = await this.line("HELLO\tversion=1", CONTROL_TIMEOUT_MS, signal);
    if (hello === "ERR\tVERSION_MISMATCH" || hello.startsWith("ERR\tVERSION_MISMATCH\t")) {
      throw new ProtocolVersionMismatch();
    }
    if (hello !== "OK\tversion=1") {
      throw new BrokerError("broker rejected HELLO");
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
      throw new BrokerError("broker registration rejected");
    }
  }

  async unregister(sessionID: string): Promise<void> {
    const response = await this.command(`UNREGISTER\tsession=${sessionID}`);
    if (response !== "OK") {
      throw new BrokerError("broker unregistration rejected");
    }
  }

  async request(key: string, state: SessionState, signal: AbortSignal): Promise<string> {
    return this.command(`REQUEST\tkey=${key}\ttoken=${state.token}`, REQUEST_TIMEOUT_MS, signal);
  }
}

function guidance(outcome: RequestOutcome): string {
  if (outcome.versionMismatch) {
    return "unavailable: secretsd protocol version mismatch; restart or update secretsd and OpenCode before requesting a secret.";
  }
  if (outcome.status === "granted") {
    return "granted: use the secrets shim for the requested key.";
  }
  if (outcome.status === "denied") {
    return "denied: the request was denied or timed out; make a new request only if appropriate.";
  }
  return "unavailable: secretsd could not complete this human-tier request; check that the broker and YubiKey are available.";
}

function responseCode(response: string): string | undefined {
  if (!response.startsWith("ERR\t")) {
    return undefined;
  }
  return response.split("\t", 3)[1];
}

async function requestSecret(broker: BrokerClient, request: SecretRequest): Promise<RequestOutcome> {
  try {
    let response = await broker.request(request.key, request.state, request.signal);
    if (responseCode(response) === "UNKNOWN_TOKEN") {
      await request.reregister();
      response = await broker.request(request.key, request.state, request.signal);
    }
    if (response === "OK\tstatus=granted") {
      return { status: "granted", versionMismatch: false };
    }
    const code = responseCode(response);
    if (code === "DENIED" || code === "TIMEOUT") {
      return { status: "denied", versionMismatch: false };
    }
    return { status: "unavailable", versionMismatch: false };
  } catch (error) {
    return { status: "unavailable", versionMismatch: error instanceof ProtocolVersionMismatch };
  }
}

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
    tool: {
      secrets_request: tool({
        description: "Request human approval for a secretsd human-tier key; never returns secret values.",
        args: { key: tool.schema.string().regex(/^[A-Z][A-Z0-9_]*$/) },
        async execute({ key }, context) {
          try {
            const state = await ensureRegistered(context.sessionID);
            if (!state) {
              return guidance({ status: "unavailable", versionMismatch: false });
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
            return guidance({ status: "unavailable", versionMismatch: error instanceof ProtocolVersionMismatch });
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
