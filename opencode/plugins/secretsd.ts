import { randomBytes } from "crypto";
import { chmodSync, existsSync, lstatSync, mkdirSync, renameSync, rmSync, statSync, writeFileSync } from "fs";
import { tool } from "@opencode-ai/plugin";
import { dirname, join } from "path";
import { fileURLToPath } from "url";

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

/// Skills shipped beside this plugin. Registering the directory through the
/// config hook is how a plugin contributes skills; it needs no symlink and no
/// edit to the user's config.
const SKILLS_DIRECTORY = join(dirname(fileURLToPath(import.meta.url)), "..", "skills");

type ConfigInput = {
  skills?: { paths?: string[] };
};

type ShellInput = { readonly sessionID?: string };
type ShellOutput = { env: Record<string, string> };

const decoder = new TextDecoder();
const CONTROL_TIMEOUT_MS = 2_000;
export const PROTOCOL_VERSION = 3;
const HELLO = `HELLO\tversion=${PROTOCOL_VERSION}`;
const SESSION_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;

export const REQUEST_TIMEOUT_MS = 100_000;

export const DAEMON_ERROR_CODES = [
  "BAD_REQUEST",
  "UNKNOWN_OP",
  "VERSION_MISMATCH",
  "UNKNOWN_TOKEN",
  "NO_SCOPE",
  "AGENT_TTY",
  "FOREIGN_CALLER",
  "NOT_HUMAN_KEY",
  "AMBIGUOUS_KEY",
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
  UNKNOWN_TOKEN: "error: secretsd still does not know this session, even after an automatic re-registration; ask the human to check `systemctl --user status secretsd`, because a daemon that keeps restarting cannot hold a grant.",
  NO_SCOPE: "error: secretsd cannot attribute this request to a session because no session token or tty was provided; start it from a registered OpenCode session.",
  AGENT_TTY: "error: secretsd rejected a tokenless request from a tty already assigned to an agent session; use the registered session token.",
  FOREIGN_CALLER: "error: secretsd refused this request because the session token was presented from outside that session's process tree; run the request from the session that owns the token.",
  NOT_HUMAN_KEY: "not human-tier: no approval is needed for this key. Run the command that needs it with `secrets <KEY> -- <command>`, or read the bytes with `secrets get <KEY> --value`; plain `secrets get <KEY>` prints status, not the value. If that fails, the key is not configured. If config.toml just gained a new source root, restart secretsd (systemctl --user restart secretsd.service).",
  AMBIGUOUS_KEY: "error: the key exists in more than one human-tier location; ask the human to remove one of the duplicate files.",
  DENIED: "denied: human approval was refused; do not retry unless the human asks you to.",
  TIMEOUT: "timed out: no one approved the request in time; make a new request only if approval is still needed.",
  YUBIKEY_UNREACHABLE: "error: the YubiKey or its tunnel is unreachable; restore the hardware or tunnel connection and retry.",
  TOO_MANY_PENDING: "error: this session already has too many approvals pending; wait for an existing request to be resolved before requesting again.",
  INTERNAL: "error: secretsd failed while decrypting; inspect `journalctl --user -u secretsd` for the daemon's sops stderr.",
} as const satisfies Record<DaemonErrorCode, string>;

export type RequestOutcome =
  | { readonly kind: "broker-unreachable" }
  | { readonly kind: "broker-unresponsive" }
  | { readonly kind: "daemon-error"; readonly code: DaemonErrorCode }
  | { readonly kind: "granted" }
  | { readonly kind: "request-cancelled" }
  | { readonly kind: "runtime-unavailable"; readonly reason: string }
  | { readonly kind: "unexpected-broker-response" }
  | { readonly kind: "unexpected-error" };
export type SecretRequest = {
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

/// A refusal to use the runtime directory, carrying operator-facing detail.
///
/// The reason names directories and errno codes only -- never token bytes, which
/// must never reach a tool result.
class RuntimeUnavailableError extends Error {
  readonly name = "RuntimeUnavailableError";
  readonly reason: string;

  constructor(reason: string) {
    super(`secretsd runtime directory unusable: ${reason}`);
    this.reason = reason;
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

function errnoCode(error: unknown): string {
  return typeof error === "object" && error !== null && "code" in error && typeof error.code === "string"
    ? error.code
    : "unknown error";
}

/// Resolve the directory holding the broker socket and this session's token.
///
/// Mirrors `SocketPath::resolve` in `src/client.rs`: an explicit path wins, then
/// `XDG_RUNTIME_DIR`, then the per-user directory systemd would have named. The
/// fallback is what keeps the two halves of a release agreeing -- without it a
/// serve process that inherited no `XDG_RUNTIME_DIR`, from a tmux server started
/// without one or from non-interactive ssh, could never issue a token while the
/// `secrets` CLI beside it resolved the same socket fine.
export function resolveRuntimeDir(
  override: string | undefined,
  environmentValue: string | undefined,
  uid: number | undefined,
): string | undefined {
  // An empty value is absent, matching how the daemon reads its own environment.
  if (override) {
    return override;
  }
  if (environmentValue) {
    return environmentValue;
  }
  return uid === undefined ? undefined : `/run/user/${uid}`;
}

/// Resolve the broker socket the plugin registers with.
///
/// Mirrors `BrokerClient::from_environment` in `src/client.rs`: an explicit path
/// wins, then `SECRETSD_SOCK`, then the resolved runtime directory. The plugin
/// mints the token and the CLI presents it, so the two must reach the same
/// daemon; a plugin that ignored `SECRETSD_SOCK` while the CLI honoured it would
/// register the token with one daemon and present it to another, and the request
/// would fail `UNKNOWN_TOKEN` for no visible reason.
export function resolveSocketPath(
  override: string | undefined,
  environmentValue: string | undefined,
  runtimeDir: string | undefined,
): string {
  if (override) {
    return override;
  }
  if (environmentValue) {
    return environmentValue;
  }
  return runtimeDir ? join(runtimeDir, "secretsd.sock") : "";
}

/// Stat the runtime root, turning a missing or unreadable directory into a
/// refusal that names it.
function runtimeRootStats(runtimeDir: string) {
  try {
    return statSync(runtimeDir);
  } catch (error) {
    const code = errnoCode(error);
    throw new RuntimeUnavailableError(
      code === "ENOENT" ? `${runtimeDir} does not exist` : `${runtimeDir} is unusable (${code})`,
    );
  }
}

/// Refuse a runtime root that is absent, foreign, or open to other users.
///
/// The directory is never created. A missing `/run/user/<uid>` means there is no
/// systemd user session, and fabricating it would put session tokens somewhere
/// the daemon never looks while reporting success.
function assertRuntimeRoot(runtimeDir: string, uid: number | undefined): void {
  const stats = runtimeRootStats(runtimeDir);
  if (!stats.isDirectory()) {
    throw new RuntimeUnavailableError(`${runtimeDir} is not a directory`);
  }
  if (uid !== undefined && stats.uid !== uid) {
    throw new RuntimeUnavailableError(`${runtimeDir} is not owned by this user`);
  }
  if ((stats.mode & 0o022) !== 0) {
    throw new RuntimeUnavailableError(`${runtimeDir} is writable by other users`);
  }
}

/// Create or adopt the `0700` token directory, accepting only a real directory
/// this user owns.
///
/// `chmodSync` and `writeFileSync` both follow symlinks, so a pre-planted link
/// would otherwise steer token files -- and the `0700` chmod -- at a directory
/// this plugin never chose.
function prepareTokenDirectory(runtimeDir: string): string {
  const uid = process.getuid?.();
  assertRuntimeRoot(runtimeDir, uid);
  const directory = tokenDirectory(runtimeDir);
  try {
    // Deliberately not recursive: the runtime root must already exist.
    mkdirSync(directory, { mode: 0o700 });
  } catch (error) {
    const code = errnoCode(error);
    if (code !== "EEXIST") {
      throw new RuntimeUnavailableError(`${directory} could not be created (${code})`);
    }
    const stats = lstatSync(directory);
    if (!stats.isDirectory()) {
      throw new RuntimeUnavailableError(`${directory} is not a directory`);
    }
    if (uid !== undefined && stats.uid !== uid) {
      throw new RuntimeUnavailableError(`${directory} is not owned by this user`);
    }
  }
  // Set the mode explicitly: a restrictive umask can strip owner bits from the
  // create above, and an adopted directory may carry any mode at all.
  chmodSync(directory, 0o700);
  return directory;
}

/// Write `token` to this session's token path, atomically and privately.
function writeTokenFile(runtimeDir: string, sessionID: string, token: string): string {
  const directory = prepareTokenDirectory(runtimeDir);

  const tokenPath = tokenFile(runtimeDir, sessionID);
  // Stage then rename: a concurrent reader sees either no file or the whole
  // token, never a truncated one. `wx` refuses to write through a pre-planted
  // path, and the mode is fixed before the token is reachable at its real name.
  const stagingPath = `${tokenPath}.${randomBytes(6).toString("hex")}.tmp`;
  try {
    writeFileSync(stagingPath, token, { encoding: "utf8", mode: 0o600, flag: "wx" });
    chmodSync(stagingPath, 0o600);
    renameSync(stagingPath, tokenPath);
  } catch (error) {
    // Name the directory, never the staging path: its random suffix reads like
    // token material.
    throw new RuntimeUnavailableError(`${directory} rejected a token file (${errnoCode(error)})`);
  }
  return tokenPath;
}

export function issueTokenFile(runtimeDir: string, sessionID: string): SessionState {
  const token = randomBytes(32).toString("hex");
  return { token, tokenFile: writeTokenFile(runtimeDir, sessionID, token) };
}

/// Put a known session's token back on disk after its file disappeared.
///
/// Reuses the same token rather than minting one: it is still the token the
/// daemon has registered, so the session keeps its grants. Registering a fresh
/// token for a session displaces the old one and revokes its grants
/// (`Registry::register`, `src/grants.rs:139`), which would charge the human
/// another touch for a file this plugin failed to keep.
export function restoreTokenFile(runtimeDir: string, sessionID: string, state: SessionState): void {
  writeTokenFile(runtimeDir, sessionID, state.token);
}

export function removeTokenFile(state: SessionState): void {
  rmSync(state.tokenFile, { force: true });
}

/// Validate a handshake reply and return the answering daemon's instance id.
///
/// Fields are space-separated because the daemon's formatter collapses tabs.
/// A missing instance id is a protocol error, not something to work around: it
/// means the daemon predates restart reporting, so restarts would go unnoticed.
function parseHandshake(reply: string): string {
  if (reply === "ERR\tVERSION_MISMATCH" || reply.startsWith("ERR\tVERSION_MISMATCH\t")) {
    throw new ProtocolVersionMismatch();
  }
  if (!reply.startsWith("OK\t")) {
    throw new BrokerProtocolError("broker rejected HELLO");
  }
  let version: string | undefined;
  let instance: string | undefined;
  for (const field of reply.slice("OK\t".length).split(" ")) {
    if (field.startsWith("version=")) {
      version = field.slice("version=".length);
    }
    if (field.startsWith("instance=")) {
      instance = field.slice("instance=".length);
    }
  }
  if (version !== String(PROTOCOL_VERSION)) {
    throw new ProtocolVersionMismatch();
  }
  if (!instance) {
    throw new BrokerProtocolError("broker handshake omitted its instance id");
  }
  return instance;
}

export class BrokerClient {
  constructor(
    private readonly socketPath: string,
    private readonly onInstance: (instance: string) => void = () => {},
  ) {}

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

  /// Complete the version handshake and report which daemon process answered.
  private async handshake(signal?: AbortSignal): Promise<string> {
    const instance = parseHandshake(await this.line(HELLO, CONTROL_TIMEOUT_MS, signal));
    this.onInstance(instance);
    return instance;
  }

  /// Learn whether the daemon is still the one this plugin registered with.
  ///
  /// Registrations are memory-only, so a restart silently invalidates every one
  /// of them and nothing notifies the plugin. Asking is the only way to find out.
  async probe(signal?: AbortSignal): Promise<void> {
    await this.handshake(signal);
  }

  private async command(message: string, timeoutMs = CONTROL_TIMEOUT_MS, signal?: AbortSignal): Promise<string> {
    await this.handshake(signal);
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

export function guidance(outcome: RequestOutcome): string {
  switch (outcome.kind) {
    case "broker-unreachable":
      return "unavailable: could not reach the secretsd broker; check that secretsd is running and its socket is available.";
    case "broker-unresponsive":
      return "error: the secretsd broker did not respond before the request deadline; retry after confirming it is healthy.";
    case "daemon-error":
      return DAEMON_ERROR_GUIDANCE[outcome.code];
    case "granted":
      return "granted: run the command that needs it with `secrets <KEY> -- <command>`, or read the bytes with `secrets get <KEY> --value`; plain `secrets get <KEY>` prints status, not the value.";
    case "request-cancelled":
      return "error: the secretsd request was cancelled because the OpenCode session ended.";
    case "runtime-unavailable":
      return `error: secretsd cannot use its runtime directory, so this session has no token and no secret can be granted: ${outcome.reason}. OpenCode takes that directory from XDG_RUNTIME_DIR and otherwise derives /run/user/<uid>; ask the human to restart OpenCode with XDG_RUNTIME_DIR=/run/user/$(id -u), or to repair that directory.`;
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
    case "FOREIGN_CALLER":
      return "FOREIGN_CALLER";
    case "NOT_HUMAN_KEY":
      return "NOT_HUMAN_KEY";
    case "AMBIGUOUS_KEY":
      return "AMBIGUOUS_KEY";
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

export function failureOutcome(error: unknown): RequestOutcome {
  if (error instanceof RuntimeUnavailableError) {
    return { kind: "runtime-unavailable", reason: error.reason };
  }
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

export async function requestSecret(broker: BrokerClient, request: SecretRequest): Promise<RequestOutcome> {
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
  const runtimeDir = resolveRuntimeDir(options.runtimeDir, process.env.XDG_RUNTIME_DIR, process.getuid?.());
  const pid = options.pid ?? process.pid;
  const states = new Map<string, SessionState>();
  const registered = new Set<string>();
  const registrations = new Map<string, Promise<SessionState>>();
  const requestAbort = new AbortController();
  let brokerInstance: string | undefined;
  const broker = new BrokerClient(
    resolveSocketPath(options.socketPath, process.env.SECRETSD_SOCK, runtimeDir),
    (instance) => {
      if (brokerInstance !== undefined && brokerInstance !== instance) {
        // A different daemon process answered, so it holds no registrations at
        // all: every session must register again before its requests can be
        // scoped to it. design.md requires this before requests are allowed.
        registered.clear();
      }
      brokerInstance = instance;
    },
  );

  /// Record, once per distinct cause, that this process can issue no token.
  ///
  /// The agent gets the actionable text in its tool result, but the human who has
  /// to repair the directory only ever sees the serve log, and `shell.env`
  /// otherwise swallows this to keep shells starting. Deduplicated by reason
  /// because `shell.env` runs before every single command. Reasons name
  /// directories and errno codes only, never token bytes.
  const reportedRuntimeFailures = new Set<string>();
  function noteRuntimeUnavailable(error: unknown): void {
    if (!(error instanceof RuntimeUnavailableError) || reportedRuntimeFailures.has(error.reason)) {
      return;
    }
    reportedRuntimeFailures.add(error.reason);
    console.error(`secretsd: no session token can be issued: ${error.reason}`);
  }

  function ensureState(sessionID: string): SessionState {
    if (!runtimeDir) {
      throw new RuntimeUnavailableError("neither XDG_RUNTIME_DIR nor a uid was available to locate it");
    }
    const existing = states.get(sessionID);
    if (existing) {
      // logind removes `/run/user/<uid>` when the user's last session ends unless
      // lingering is enabled, so a long-lived serve process -- one inside a tmux
      // server that outlives every login -- can outlive its own token file. The
      // cached state alone would keep exporting a path to a file that is gone,
      // and the `secrets` CLI reads the file, not this memory.
      if (!existsSync(existing.tokenFile)) {
        restoreTokenFile(runtimeDir, sessionID, existing);
      }
      return existing;
    }
    const state = issueTokenFile(runtimeDir, sessionID);
    states.set(sessionID, state);
    return state;
  }

  async function ensureRegistered(sessionID: string): Promise<SessionState> {
    const state = ensureState(sessionID);
    if (registered.has(sessionID)) {
      // `registered` is only a belief about a daemon that may since have
      // restarted, dropping every registration without telling the plugin. Ask
      // who is answering now: the raw `secrets` CLI cannot register itself, so
      // this is the only thing that can heal that path before the next command.
      // no-excuse-ok: catch — an unreachable broker must not stop the token path
      // from being exported; the request itself reports the real failure.
      try {
        await broker.probe();
      } catch {
        // Detection failed. Keep the existing registration rather than churn.
      }
      // A restart clears `registered`, so re-check before trusting it.
      if (registered.has(sessionID)) {
        return state;
      }
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
    config: async (config: ConfigInput): Promise<void> => {
      // The CLI's contract is easy to misread -- `secrets get KEY` prints status,
      // not the secret -- so the skill explaining it ships with the plugin rather
      // than living in whichever dotfiles checkout happens to be present.
      config.skills ??= {};
      config.skills.paths ??= [];
      if (!config.skills.paths.includes(SKILLS_DIRECTORY)) {
        config.skills.paths.push(SKILLS_DIRECTORY);
      }
    },
    "shell.env": async (input: ShellInput, output: ShellOutput): Promise<void> => {
      // no-excuse-ok: catch — plugin hooks must not prevent a shell from starting.
      try {
        if (input.sessionID) {
          const state = await ensureRegistered(input.sessionID);
          output.env.SECRETSD_SESSION_TOKEN_FILE = state.tokenFile;
        }
      } catch (error) {
        noteRuntimeUnavailable(error);
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
            noteRuntimeUnavailable(error);
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
