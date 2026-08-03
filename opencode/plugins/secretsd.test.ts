import { afterEach, describe, expect, test } from "bun:test";
import type { ToolContext, ToolResult } from "@opencode-ai/plugin";
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  symlinkSync,
} from "fs";
import { join } from "path";
import secretsdPlugin, {
  DAEMON_ERROR_CODES,
  PROTOCOL_VERSION,
  REQUEST_TIMEOUT_MS,
  createSecretsdPlugin,
  issueTokenFile,
  resolveRuntimeDir,
  resolveSocketPath,
} from "./secretsd";

// allow: SIZE_OK — the plan requires all fake-broker protocol scenarios in this single test file.
const roots: string[] = [];
const HELLO = `HELLO\tversion=${PROTOCOL_VERSION}`;
const HANDSHAKE = `OK\tversion=${PROTOCOL_VERSION} instance=test-instance\n`;

function root(): string {
  const value = mkdtempSync("/tmp/secretsd-plugin-");
  roots.push(value);
  return value;
}

function toolContext(sessionID: string): ToolContext {
  return {
    sessionID,
    messageID: "test-message",
    agent: "test-agent",
    directory: "/tmp",
    worktree: "/tmp",
    abort: new AbortController().signal,
    metadata: () => {},
    ask: async () => {},
  };
}

function toolOutput(result: ToolResult): string {
  return typeof result === "string" ? result : result.output;
}

afterEach(() => {
  for (const value of roots.splice(0)) {
    rmSync(value, { force: true, recursive: true });
  }
});

test("exports a V1 server plugin despite its testable named helpers", () => {
  expect(secretsdPlugin).toHaveProperty("id", "secretsd");
  expect(secretsdPlugin).toHaveProperty("server");
});

test("keeps the Rust and plugin protocol versions in lockstep", () => {
  const proto = readFileSync(join(import.meta.dir, "../../src/proto.rs"), "utf8");
  const rustVersion = /pub const PROTOCOL_VERSION: u32 = (\d+)/.exec(proto)?.[1];

  if (rustVersion === undefined) {
    throw new Error("src/proto.rs does not define PROTOCOL_VERSION");
  }

  expect(rustVersion).toBe(PROTOCOL_VERSION.toString());
});

describe("secretsd token issuance", () => {
  test("writes a 256-bit token to a 0600 file in a 0700 directory", async () => {
    const runtimeDir = root();
    const plugin = createSecretsdPlugin({
      runtimeDir,
      socketPath: join(runtimeDir, "broker.sock"),
      pid: 42,
    });

    await plugin.hooks["shell.env"]({ sessionID: "session-a" }, { env: {} });

    const file = join(runtimeDir, "secretsd", "session-a.token");
    expect(existsSync(file)).toBe(true);
    expect(/^[0-9a-f]{64}$/.test(readFileSync(file, "utf8"))).toBe(true);
    expect(statSync(join(runtimeDir, "secretsd")).mode & 0o777).toBe(0o700);
    expect(statSync(file).mode & 0o777).toBe(0o600);
  });

  test("adds only the token-file path to the session shell environment", async () => {
    const runtimeDir = root();
    const plugin = createSecretsdPlugin({
      runtimeDir,
      socketPath: join(runtimeDir, "broker.sock"),
      pid: 42,
    });
    const broker = fakeBroker(join(runtimeDir, "broker.sock"));
    const output: { env: Record<string, string> } = { env: {} };

    await plugin.hooks["shell.env"]({ sessionID: "session-b" }, output);

    expect(output.env.SECRETSD_SESSION_TOKEN_FILE).toBe(join(runtimeDir, "secretsd", "session-b.token"));
    const token = readFileSync(output.env.SECRETSD_SESSION_TOKEN_FILE, "utf8");
    expect(Object.values(output.env).some((value) => value === token)).toBe(false);
    broker.stop();
  });

test("registers its bundled skills directory through the config hook", async () => {
    // A plugin contributes skills by adding its directory to config.skills.paths;
    // this is what ships the `secrets` CLI guidance with the tool that needs it.
    const plugin = createSecretsdPlugin({ runtimeDir: root() });
    const config: { skills?: { paths?: string[] } } = {};

    await plugin.hooks.config(config);

    const paths = config.skills?.paths ?? [];
    expect(paths.some((entry) => entry.endsWith("/skills"))).toBe(true);
    expect(existsSync(join(paths[0]!, "using-secrets", "SKILL.md"))).toBe(true);

    // Re-running a hook must not duplicate the entry.
    await plugin.hooks.config(config);
    expect(config.skills?.paths?.length).toBe(1);
  });

  test("session end unregisters the session and removes its token file", async () => {
    // Without this, a finished session's token file and broker grant survive
    // until the whole serve process exits or the daemon's backstop expires.
    const runtimeDir = root();
    const socketPath = join(runtimeDir, "broker.sock");
    const plugin = createSecretsdPlugin({ runtimeDir, socketPath, pid: 4242 });
    const broker = fakeBroker(socketPath);
    const output: { env: Record<string, string> } = { env: {} };
    await plugin.hooks["shell.env"]({ sessionID: "session-ended" }, output);
    const tokenPath = output.env.SECRETSD_SESSION_TOKEN_FILE;
    expect(existsSync(tokenPath)).toBe(true);

    await plugin.hooks.event({
      event: { type: "session.deleted", properties: { sessionID: "session-ended" } },
    });

    expect(existsSync(tokenPath)).toBe(false);
    expect(broker.received.some((line) => line.startsWith("UNREGISTER\t"))).toBe(true);
    broker.stop();
  });

  test("session end accepts the info-shaped payload and ignores other events", async () => {
    // The SDK declares both payload shapes; a mismatch would silently skip revocation.
    const runtimeDir = root();
    const socketPath = join(runtimeDir, "broker.sock");
    const plugin = createSecretsdPlugin({ runtimeDir, socketPath, pid: 4343 });
    const broker = fakeBroker(socketPath);
    const output: { env: Record<string, string> } = { env: {} };
    await plugin.hooks["shell.env"]({ sessionID: "session-info" }, output);
    const tokenPath = output.env.SECRETSD_SESSION_TOKEN_FILE;

    await plugin.hooks.event({
      event: { type: "session.idle", properties: { sessionID: "session-info" } },
    });
    expect(existsSync(tokenPath)).toBe(true);

    await plugin.hooks.event({
      event: { type: "session.deleted", properties: { info: { id: "session-info" } } },
    });
    expect(existsSync(tokenPath)).toBe(false);
    broker.stop();
  });

  test("issues the token by rename so no partial token is ever readable", () => {
    // A reader must see either no file or a complete 64-hex token, and no
    // staging file may be left behind at the real path's directory.
    const runtimeDir = root();

    const state = issueTokenFile(runtimeDir, "session-atomic");

    expect(/^[0-9a-f]{64}$/.test(readFileSync(state.tokenFile, "utf8"))).toBe(true);
    expect(statSync(state.tokenFile).mode & 0o777).toBe(0o600);
    const leftovers = readdirSync(join(runtimeDir, "secretsd")).filter((name) => name.endsWith(".tmp"));
    expect(leftovers).toEqual([]);
  });

  test("rejects an unsafe session ID before deriving a token filename", () => {
    const runtimeDir = root();

    expect(() => issueTokenFile(runtimeDir, "../other-session")).toThrow("invalid session ID");
    expect(existsSync(join(runtimeDir, "secretsd", "other-session.token"))).toBe(false);
  });
});

function fakeBroker(socketPath: string) {
  const received: string[] = [];
  let buffered = "";
  const server = Bun.listen({
    unix: socketPath,
    socket: {
      data(socket, data) {
        buffered += new TextDecoder().decode(data);
        for (;;) {
          const newline = buffered.indexOf("\n");
          if (newline < 0) {
            return;
          }
          const line = buffered.slice(0, newline);
          buffered = buffered.slice(newline + 1);
          received.push(line);
          socket.write(line === HELLO ? HANDSHAKE : "OK\n");
        }
      },
    },
  });
  return { received, stop: () => server.stop(true) };
}

function redactFrames(frames: readonly string[]): string[] {
  return frames.map((frame) => frame.replace(/token=[0-9a-f]{64}/g, "token=<TOKEN>"));
}

async function eventually(predicate: () => boolean): Promise<boolean> {
  const deadline = Date.now() + 1_000;
  while (Date.now() < deadline) {
    if (predicate()) {
      return true;
    }
    await Bun.sleep(10);
  }
  return predicate();
}

test("shell.env registers a new session once before injecting its token-file path", async () => {
  const runtimeDir = root();
  const socketPath = join(runtimeDir, "broker.sock");
  const plugin = createSecretsdPlugin({ runtimeDir, socketPath, pid: 77 });
  const broker = fakeBroker(socketPath);
  const firstOutput: { env: Record<string, string> } = { env: {} };
  const secondOutput: { env: Record<string, string> } = { env: {} };

  await plugin.hooks["shell.env"]({ sessionID: "session-restart" }, firstOutput);
  await plugin.hooks["shell.env"]({ sessionID: "session-restart" }, secondOutput);

  // The trailing HELLO is the restart probe: the second call already believed
  // this session was registered, so it asks which daemon is answering before
  // trusting that belief. It still registers only once.
  expect(redactFrames(broker.received)).toEqual([
    HELLO,
    "REGISTER\ttoken=<TOKEN>\tsession=session-restart\tpid=77",
    HELLO,
  ]);
  expect(firstOutput.env.SECRETSD_SESSION_TOKEN_FILE).toBe(join(runtimeDir, "secretsd", "session-restart.token"));
  expect(secondOutput.env.SECRETSD_SESSION_TOKEN_FILE).toBe(join(runtimeDir, "secretsd", "session-restart.token"));
  broker.stop();
});

test("dispose unregisters every live session and removes its token file", async () => {
  const runtimeDir = root();
  const socketPath = join(runtimeDir, "broker.sock");
  const broker = fakeBroker(socketPath);
  const plugin = createSecretsdPlugin({ runtimeDir, socketPath, pid: 88 });
  await plugin.hooks["shell.env"]({ sessionID: "session-dispose" }, { env: {} });

  await plugin.hooks.dispose();

  expect(redactFrames(broker.received)).toEqual([
    HELLO,
    "REGISTER\ttoken=<TOKEN>\tsession=session-dispose\tpid=88",
    HELLO,
    "UNREGISTER\tsession=session-dispose",
  ]);
  expect(existsSync(join(runtimeDir, "secretsd", "session-dispose.token"))).toBe(false);
  broker.stop();
});

test("re-registers once after UNKNOWN_TOKEN and returns value-free granted guidance", async () => {
  const runtimeDir = root();
  const socketPath = join(runtimeDir, "broker.sock");
  let requestCount = 0;
  let registrations = 0;
  const received: string[] = [];
  let buffered = "";
  const server = Bun.listen({
    unix: socketPath,
    socket: {
      data(socket, data) {
        buffered += new TextDecoder().decode(data);
        for (;;) {
          const newline = buffered.indexOf("\n");
          if (newline < 0) {
            return;
          }
          const line = buffered.slice(0, newline);
          buffered = buffered.slice(newline + 1);
          received.push(line);
          if (line === HELLO) {
            socket.write(HANDSHAKE);
          } else if (line.startsWith("REGISTER\t")) {
            registrations += 1;
            socket.write("OK\n");
          } else if (line.startsWith("REQUEST\t")) {
            requestCount += 1;
            socket.write(requestCount === 1 ? "ERR\tUNKNOWN_TOKEN\tbroker restarted\n" : "OK\tstatus=granted\n");
          } else {
            socket.write("OK\n");
          }
        }
      },
    },
  });
  const plugin = createSecretsdPlugin({ runtimeDir, socketPath, pid: 99 });

  const result = toolOutput(
    await plugin.hooks.tool.secrets_request.execute({ key: "FLEET_LICENSE_KEY" }, toolContext("session-d")),
  );

  expect(registrations).toBe(2);
  expect(requestCount).toBe(2);
  expect(result.startsWith("granted:")).toBe(true);
  expect(/[0-9a-f]{64}/.test(result)).toBe(false);
  expect(result.includes("synthetic-secret-value")).toBe(false);
  expect(redactFrames(received)).toEqual([
    HELLO,
    "REGISTER\ttoken=<TOKEN>\tsession=session-d\tpid=99",
    HELLO,
    "REQUEST\tkey=FLEET_LICENSE_KEY\ttoken=<TOKEN>",
    HELLO,
    "REGISTER\ttoken=<TOKEN>\tsession=session-d\tpid=99",
    HELLO,
    "REQUEST\tkey=FLEET_LICENSE_KEY\ttoken=<TOKEN>",
  ]);
  await plugin.hooks.dispose();
  server.stop(true);
});

async function requestGuidanceFor(responseFrame: string): Promise<string> {
  const runtimeDir = root();
  const socketPath = join(runtimeDir, "broker.sock");
  let registrations = 0;
  let buffered = "";
  const server = Bun.listen({
    unix: socketPath,
    socket: {
      data(socket, data) {
        buffered += new TextDecoder().decode(data);
        for (;;) {
          const newline = buffered.indexOf("\n");
          if (newline < 0) {
            return;
          }
          const line = buffered.slice(0, newline);
          buffered = buffered.slice(newline + 1);
          if (line === HELLO) {
            socket.write(HANDSHAKE);
          } else if (line.startsWith("REGISTER\t")) {
            registrations += 1;
            socket.write("OK\n");
          } else if (line.startsWith("REQUEST\t")) {
            socket.write(`${responseFrame}\n`);
          } else {
            socket.write("OK\n");
          }
        }
      },
    },
  });
  const plugin = createSecretsdPlugin({ runtimeDir, socketPath, pid: 101 });
  const result = toolOutput(
    await plugin.hooks.tool.secrets_request.execute(
      { key: "FLEET_LICENSE_KEY" },
      toolContext("session-errors"),
    ),
  );
  await plugin.hooks.dispose();
  server.stop(true);
  return result;
}

test("maps every daemon ErrCode to distinct actionable guidance", async () => {
  const cases = [
    [
      "ERR\tBAD_REQUEST\tbad request",
      "error: secretsd rejected this request as malformed; verify the key name and report the request if it persists.",
    ],
    [
      "ERR\tUNKNOWN_OP\tunknown operation",
      "error: secretsd does not support the requested operation; update OpenCode and secretsd to matching versions.",
    ],
    [
      "ERR\tVERSION_MISMATCH\tupgrade required",
      "error: secretsd protocol version mismatch; restart or update secretsd and OpenCode before requesting a secret.",
    ],
    [
      "ERR\tUNKNOWN_TOKEN\tbroker restarted",
      "error: secretsd still does not know this session, even after an automatic re-registration; ask the human to check `systemctl --user status secretsd`, because a daemon that keeps restarting cannot hold a grant.",
    ],
    [
      "ERR\tNO_SCOPE\tno scope",
      "error: secretsd cannot attribute this request to a session because no session token or tty was provided; start it from a registered OpenCode session.",
    ],
    [
      "ERR\tAGENT_TTY\tagent tty",
      "error: secretsd rejected a tokenless request from a tty already assigned to an agent session; use the registered session token.",
    ],
    [
      "ERR\tFOREIGN_CALLER\tforeign caller",
      "error: secretsd refused this request because the session token was presented from outside that session's process tree; run the request from the session that owns the token.",
    ],
    [
      "ERR\tNOT_HUMAN_KEY\tnot human",
      "not human-tier: no approval is needed for this key. Run the command that needs it with `secrets <KEY> -- <command>`, or read the bytes with `secrets get <KEY> --value`; plain `secrets get <KEY>` prints status, not the value. If that fails, the key is not configured. If config.toml just gained a new source root, restart secretsd (systemctl --user restart secretsd.service).",
    ],
    [
      "ERR\tAMBIGUOUS_KEY\tambiguous key",
      "error: the key exists in more than one human-tier location; ask the human to remove one of the duplicate files.",
    ],
    ["ERR\tDENIED\tdenied", "denied: human approval was refused; do not retry unless the human asks you to."],
    [
      "ERR\tTIMEOUT\ttimed out",
      "timed out: no one approved the request in time; make a new request only if approval is still needed.",
    ],
    [
      "ERR\tYUBIKEY_UNREACHABLE\tunreachable",
      "error: the YubiKey or its tunnel is unreachable; restore the hardware or tunnel connection and retry.",
    ],
    [
      "ERR\tTOO_MANY_PENDING\tqueue full",
      "error: this session already has too many approvals pending; wait for an existing request to be resolved before requesting again.",
    ],
    [
      "ERR\tINTERNAL\tinternal",
      "error: secretsd failed while decrypting; inspect `journalctl --user -u secretsd` for the daemon's sops stderr.",
    ],
  ] as const;

  const results = await Promise.all(cases.map(async ([frame]) => requestGuidanceFor(frame)));

  expect(cases.map(([frame]) => frame.split("\t")[1])).toEqual(DAEMON_ERROR_CODES);
  expect(results).toEqual(cases.map(([, expected]) => expected));
  expect(new Set(results).size).toBe(cases.length);
  const notHumanKey = results[cases.findIndex(([frame]) => frame.includes("NOT_HUMAN_KEY"))];
  expect(notHumanKey).not.toContain("YubiKey");
  expect(notHumanKey).not.toContain("unavailable");
});

test("keeps an OpenCode session usable when the broker socket is absent", async () => {
  const runtimeDir = root();
  const plugin = createSecretsdPlugin({
    runtimeDir,
    socketPath: join(runtimeDir, "absent.sock"),
    pid: 7,
  });
  const output: { env: Record<string, string> } = { env: {} };

  await plugin.hooks["shell.env"]({ sessionID: "session-e" }, output);
  const result = toolOutput(
    await plugin.hooks.tool.secrets_request.execute({ key: "DEEL_API_KEY" }, toolContext("session-e")),
  );

  expect(output.env.SECRETSD_SESSION_TOKEN_FILE).toBeUndefined();
  expect(result.startsWith("unavailable:")).toBe(true);
  await plugin.hooks.dispose();
});

test("reports a broker version mismatch loudly without a tokenless fallback", async () => {
  const runtimeDir = root();
  const socketPath = join(runtimeDir, "broker.sock");
  const server = Bun.listen({
    unix: socketPath,
    socket: { data(socket) { socket.write("ERR\tVERSION_MISMATCH\tupgrade required\n"); } },
  });
  const plugin = createSecretsdPlugin({ runtimeDir, socketPath, pid: 8 });
  const result = toolOutput(
    await plugin.hooks.tool.secrets_request.execute(
      { key: "PULUMI_CONFIG_PASSPHRASE" },
      toolContext("session-f"),
    ),
  );

  expect(result.includes("protocol version mismatch")).toBe(true);
  expect(result.includes("tokenless")).toBe(false);
  await plugin.hooks.dispose();
  server.stop(true);
});

test("dispose aborts a live REQUEST instead of waiting for its 100-second deadline", async () => {
  const runtimeDir = root();
  const socketPath = join(runtimeDir, "broker.sock");
  let registrations = 0;
  let requests = 0;
  let buffered = "";
  const server = Bun.listen({
    unix: socketPath,
    socket: {
      data(socket, data) {
        buffered += new TextDecoder().decode(data);
        for (;;) {
          const newline = buffered.indexOf("\n");
          if (newline < 0) {
            return;
          }
          const line = buffered.slice(0, newline);
          buffered = buffered.slice(newline + 1);
          if (line === HELLO) {
            socket.write(HANDSHAKE);
          } else if (line.startsWith("REGISTER\t")) {
            registrations += 1;
            socket.write("OK\n");
          } else if (line.startsWith("REQUEST\t")) {
            requests += 1;
          } else {
            socket.write("OK\n");
          }
        }
      },
    },
  });
  const plugin = createSecretsdPlugin({ runtimeDir, socketPath, pid: 9 });
  const request = plugin.hooks.tool.secrets_request
    .execute({ key: "PULUMI_CONFIG_PASSPHRASE" }, toolContext("session-abort"))
    .then(toolOutput);
  expect(await eventually(() => requests === 1)).toBe(true);
  await plugin.hooks.dispose();
  const result = await Promise.race([request, Bun.sleep(250).then(() => "still-waiting")]);

  expect(REQUEST_TIMEOUT_MS).toBe(100_000);
  expect(result).toBe("error: the secretsd request was cancelled because the OpenCode session ended.");
  expect(existsSync(join(runtimeDir, "secretsd", "session-abort.token"))).toBe(false);
  server.stop(true);
});


test("re-registers a live session when the daemon reports a new instance", async () => {
  const runtimeDir = root();
  const socketPath = join(runtimeDir, "broker.sock");
  const received: string[] = [];
  let instance = "instance-one";
  let buffered = "";
  const server = Bun.listen({
    unix: socketPath,
    socket: {
      data(socket, data) {
        buffered += new TextDecoder().decode(data);
        for (;;) {
          const newline = buffered.indexOf("\n");
          if (newline < 0) {
            return;
          }
          const line = buffered.slice(0, newline);
          buffered = buffered.slice(newline + 1);
          received.push(line);
          socket.write(line === HELLO ? `OK\tversion=${PROTOCOL_VERSION} instance=${instance}\n` : "OK\n");
        }
      },
    },
  });
  const plugin = createSecretsdPlugin({ runtimeDir, socketPath, pid: 55 });
  const registrations = () => received.filter((frame) => frame.startsWith("REGISTER")).length;

  // Given: a session registered with whichever daemon answered first.
  await plugin.hooks["shell.env"]({ sessionID: "session-restarted" }, { env: {} });
  const beforeRestart = registrations();

  // When: a different daemon process answers, as a restart leaves things. It
  // holds no registrations, and nothing notifies the plugin.
  instance = "instance-two";
  await plugin.hooks["shell.env"]({ sessionID: "session-restarted" }, { env: {} });

  // Then: the session registers again up front, rather than waiting for a
  // request to fail with UNKNOWN_TOKEN -- which the raw `secrets` CLI could
  // never recover from, since only this plugin can register.
  expect(beforeRestart).toBe(1);
  expect(registrations()).toBe(2);

  // And: while the same daemon keeps answering, nothing re-registers.
  await plugin.hooks["shell.env"]({ sessionID: "session-restarted" }, { env: {} });
  expect(registrations()).toBe(2);
  server.stop(true);
});

describe("runtime directory resolution", () => {
  // Mirrors `socket_path_is_lazy_and_has_the_documented_fallback` in
  // tests/client.rs so both halves of the release resolve the same directory.
  // Without the per-user fallback a serve process that inherited no
  // XDG_RUNTIME_DIR -- from a tmux server started without it, or from
  // non-interactive ssh -- could never issue a token, while the `secrets` CLI
  // beside it resolved the socket fine.
  test("prefers an explicit directory, then the environment, then the per-user default", () => {
    expect(resolveRuntimeDir("/tmp/override", "/tmp/environment", 42)).toBe("/tmp/override");
    expect(resolveRuntimeDir(undefined, "/tmp/environment", 42)).toBe("/tmp/environment");
    expect(resolveRuntimeDir(undefined, undefined, 42)).toBe("/run/user/42");
  });

  test("treats an empty environment value as absent, as the daemon does", () => {
    expect(resolveRuntimeDir(undefined, "", 42)).toBe("/run/user/42");
  });

  test("reports no directory when there is no uid to derive one from", () => {
    // Refusing beats guessing, and it must not throw during plugin construction.
    expect(resolveRuntimeDir(undefined, undefined, undefined)).toBeUndefined();
  });
});

/// Run `work` with `console.error` captured, so the plugin's one-line report for
/// the human does not masquerade as a failure in the test output.
async function capturingStderr<T>(work: () => Promise<T>): Promise<{ result: T; lines: string[] }> {
  const lines: string[] = [];
  const original = console.error;
  console.error = (...args: unknown[]) => {
    lines.push(args.map(String).join(" "));
  };
  try {
    return { result: await work(), lines };
  } finally {
    console.error = original;
  }
}

test("refuses a missing runtime directory instead of creating one", async () => {
  // A missing /run/user/<uid> means there is no systemd user session. Creating
  // it would put session tokens somewhere the daemon never looks while
  // reporting success, so this must fail closed -- and say how to fix it,
  // because the agent that hits this cannot read the plugin's source.
  const runtimeDir = join(root(), "absent-runtime");
  const plugin = createSecretsdPlugin({
    runtimeDir,
    socketPath: join(runtimeDir, "broker.sock"),
    pid: 11,
  });

  const { result: raw, lines } = await capturingStderr(async () =>
    plugin.hooks.tool.secrets_request.execute({ key: "DEEL_API_KEY" }, toolContext("session-no-runtime")),
  );
  const result = toolOutput(raw);

  expect(result).toContain("XDG_RUNTIME_DIR");
  expect(result).toContain(runtimeDir);
  expect(existsSync(runtimeDir)).toBe(false);
  expect(/[0-9a-f]{64}/.test(result)).toBe(false);
  expect(lines).toEqual([`secretsd: no session token can be issued: ${runtimeDir} does not exist`]);
  await plugin.hooks.dispose();
});

test("refuses a token directory that is a symlink rather than a real directory", async () => {
  // chmodSync and writeFileSync both follow symlinks, so a pre-planted link
  // would steer token files -- and the 0700 chmod -- at a directory this plugin
  // never chose.
  const runtimeDir = root();
  const elsewhere = root();
  symlinkSync(elsewhere, join(runtimeDir, "secretsd"));
  const plugin = createSecretsdPlugin({
    runtimeDir,
    socketPath: join(runtimeDir, "broker.sock"),
    pid: 12,
  });

  const { result: raw } = await capturingStderr(async () =>
    plugin.hooks.tool.secrets_request.execute({ key: "DEEL_API_KEY" }, toolContext("session-symlinked")),
  );
  const result = toolOutput(raw);

  expect(result).toContain("XDG_RUNTIME_DIR");
  expect(readdirSync(elsewhere)).toEqual([]);
  expect(/[0-9a-f]{64}/.test(result)).toBe(false);
  await plugin.hooks.dispose();
});

test("refuses a runtime directory other users can write to", async () => {
  // This is the reachable half of the runtime-root check: a directory other
  // users can write to lets them replace this session's token file, so the
  // per-user fallback must verify what it derived rather than assume it.
  const runtimeDir = root();
  chmodSync(runtimeDir, 0o777);
  const plugin = createSecretsdPlugin({
    runtimeDir,
    socketPath: join(runtimeDir, "broker.sock"),
    pid: 13,
  });

  const { result: raw } = await capturingStderr(async () =>
    plugin.hooks.tool.secrets_request.execute({ key: "DEEL_API_KEY" }, toolContext("session-open-runtime")),
  );
  const result = toolOutput(raw);

  expect(result).toContain("writable by other users");
  expect(existsSync(join(runtimeDir, "secretsd"))).toBe(false);
  await plugin.hooks.dispose();
});

describe("socket path resolution", () => {
  // The plugin registers the token and the CLI presents it, so both must reach
  // the same daemon. `BrokerClient::from_environment` in src/client.rs honours
  // SECRETSD_SOCK; if the plugin ignored it, a redirected CLI would present its
  // token to a daemon that never registered it and get UNKNOWN_TOKEN.
  test("prefers an explicit path, then SECRETSD_SOCK, then the runtime directory", () => {
    expect(resolveSocketPath("/tmp/explicit.sock", "/tmp/env.sock", "/tmp/runtime")).toBe("/tmp/explicit.sock");
    expect(resolveSocketPath(undefined, "/tmp/env.sock", "/tmp/runtime")).toBe("/tmp/env.sock");
    expect(resolveSocketPath(undefined, undefined, "/tmp/runtime")).toBe("/tmp/runtime/secretsd.sock");
  });

  test("treats an empty SECRETSD_SOCK as absent", () => {
    expect(resolveSocketPath(undefined, "", "/tmp/runtime")).toBe("/tmp/runtime/secretsd.sock");
  });

  test("has no socket to offer when there is no runtime directory either", () => {
    expect(resolveSocketPath(undefined, undefined, undefined)).toBe("");
  });
});

test("rewrites a token file that vanished under a long-running process", async () => {
  // logind removes /run/user/<uid> when the user's last session ends unless
  // lingering is enabled, so a tmux server -- and the opencode serve process
  // inside it -- outlives its own token file. The plugin cached the state and
  // kept exporting a path to a file that was no longer there, leaving the
  // session unable to get a secret until opencode restarted.
  const runtimeDir = root();
  const socketPath = join(runtimeDir, "broker.sock");
  const plugin = createSecretsdPlugin({ runtimeDir, socketPath, pid: 14 });
  const broker = fakeBroker(socketPath);

  const first: { env: Record<string, string> } = { env: {} };
  await plugin.hooks["shell.env"]({ sessionID: "ses_longLived" }, first);
  const tokenPath = first.env.SECRETSD_SESSION_TOKEN_FILE!;
  const originalToken = readFileSync(tokenPath, "utf8");

  rmSync(join(runtimeDir, "secretsd"), { recursive: true, force: true });
  expect(existsSync(tokenPath)).toBe(false);

  const second: { env: Record<string, string> } = { env: {} };
  await plugin.hooks["shell.env"]({ sessionID: "ses_longLived" }, second);

  expect(second.env.SECRETSD_SESSION_TOKEN_FILE).toBe(tokenPath);
  expect(existsSync(tokenPath)).toBe(true);
  // The same token, not a fresh one: registering a new token for a session
  // displaces the old one and revokes its grants (src/grants.rs:153), which
  // would cost the human another touch for a file this plugin lost.
  expect(readFileSync(tokenPath, "utf8")).toBe(originalToken);
  expect(statSync(tokenPath).mode & 0o777).toBe(0o600);
  expect(statSync(join(runtimeDir, "secretsd")).mode & 0o777).toBe(0o700);
  expect(broker.received.filter((line) => line.startsWith("REGISTER")).length).toBe(1);
  broker.stop();
  await plugin.hooks.dispose();
});

test("tells the human once why no token can be issued, without per-command noise", async () => {
  // The agent sees the refusal in its tool result, but the human who has to
  // repair the directory only reads the serve log -- and `shell.env` swallows the
  // failure so shells keep starting. `shell.env` runs before every command, so
  // this must be deduplicated rather than repeated.
  const runtimeDir = join(root(), "absent-runtime");
  const plugin = createSecretsdPlugin({
    runtimeDir,
    socketPath: join(runtimeDir, "broker.sock"),
    pid: 15,
  });
  const { lines } = await capturingStderr(async () => {
    await plugin.hooks["shell.env"]({ sessionID: "ses_logOnce" }, { env: {} });
    await plugin.hooks["shell.env"]({ sessionID: "ses_logOnce" }, { env: {} });
    await plugin.hooks.tool.secrets_request.execute({ key: "DEEL_API_KEY" }, toolContext("ses_logOnce"));
  });

  expect(lines.length).toBe(1);
  expect(lines[0]).toContain(runtimeDir);
  expect(/[0-9a-f]{64}/.test(lines[0]!)).toBe(false);
  await plugin.hooks.dispose();
});
