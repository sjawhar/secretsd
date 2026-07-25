import { afterEach, describe, expect, test } from "bun:test";
import type { ToolContext, ToolResult } from "@opencode-ai/plugin";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from "fs";
import { join } from "path";
import { REQUEST_TIMEOUT_MS, createSecretsdPlugin, issueTokenFile } from "./secretsd";

// allow: SIZE_OK — the plan requires all fake-broker protocol scenarios in this single test file.
const roots: string[] = [];

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

describe("secretsd token issuance", () => {
  test("writes a 256-bit token to a 0600 file in a 0700 directory", async () => {
    const runtimeDir = root();
    const plugin = createSecretsdPlugin({
      runtimeDir,
      socketPath: join(runtimeDir, "missing.sock"),
      pid: 42,
    });

    await plugin.hooks.event({
      event: { type: "session.created", properties: { info: { id: "session-a" } } },
    });

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
      socketPath: join(runtimeDir, "missing.sock"),
      pid: 42,
    });
    await plugin.hooks.event({
      event: { type: "session.created", properties: { info: { id: "session-b" } } },
    });
    const output: { env: Record<string, string> } = { env: {} };

    await plugin.hooks["shell.env"]({ sessionID: "session-b" }, output);

    expect(output.env.SECRETSD_SESSION_TOKEN_FILE).toBe(join(runtimeDir, "secretsd", "session-b.token"));
    const token = readFileSync(output.env.SECRETSD_SESSION_TOKEN_FILE, "utf8");
    expect(Object.values(output.env).some((value) => value === token)).toBe(false);
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
          socket.write(line === "HELLO\tversion=1" ? "OK\tversion=1\n" : "OK\n");
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

test("registers at creation and unregisters plus removes the file at deletion", async () => {
  const runtimeDir = root();
  const socketPath = join(runtimeDir, "broker.sock");
  const broker = fakeBroker(socketPath);
  const plugin = createSecretsdPlugin({ runtimeDir, socketPath, pid: 4242 });

  await plugin.hooks.event({
    event: { type: "session.created", properties: { info: { id: "session-c" } } },
  });
  expect(await eventually(() => broker.received.length === 2)).toBe(true);
  await plugin.hooks.event({
    event: { type: "session.deleted", properties: { info: { id: "session-c" } } },
  });

  expect(redactFrames(broker.received)).toEqual([
    "HELLO\tversion=1",
    "REGISTER\ttoken=<TOKEN>\tsession=session-c\tpid=4242",
    "HELLO\tversion=1",
    "UNREGISTER\tsession=session-c",
  ]);
  expect(existsSync(join(runtimeDir, "secretsd", "session-c.token"))).toBe(false);
  broker.stop();
});

test("shell.env re-registers a persisted session before shell access", async () => {
  const runtimeDir = root();
  const socketPath = join(runtimeDir, "broker.sock");
  const plugin = createSecretsdPlugin({ runtimeDir, socketPath, pid: 77 });
  await plugin.hooks.event({
    event: { type: "session.created", properties: { info: { id: "session-restart" } } },
  });
  const broker = fakeBroker(socketPath);
  const output: { env: Record<string, string> } = { env: {} };

  await plugin.hooks["shell.env"]({ sessionID: "session-restart" }, output);

  expect(redactFrames(broker.received)).toEqual([
    "HELLO\tversion=1",
    "REGISTER\ttoken=<TOKEN>\tsession=session-restart\tpid=77",
  ]);
  expect(output.env.SECRETSD_SESSION_TOKEN_FILE).toBe(join(runtimeDir, "secretsd", "session-restart.token"));
  broker.stop();
});

test("session.created never waits on a stale broker socket", async () => {
  const runtimeDir = root();
  const socketPath = join(runtimeDir, "broker.sock");
  const server = Bun.listen({ unix: socketPath, socket: { data() {} } });
  const plugin = createSecretsdPlugin({ runtimeDir, socketPath, pid: 78 });
  const eventReturned = await Promise.race([
    plugin.hooks
      .event({ event: { type: "session.created", properties: { info: { id: "session-stale" } } } })
      .then(() => true),
    Bun.sleep(100).then(() => false),
  ]);

  expect(eventReturned).toBe(true);
  server.stop(true);
  await plugin.hooks.dispose();
});

test("dispose unregisters every live session and removes its token file", async () => {
  const runtimeDir = root();
  const socketPath = join(runtimeDir, "broker.sock");
  const broker = fakeBroker(socketPath);
  const plugin = createSecretsdPlugin({ runtimeDir, socketPath, pid: 88 });
  await plugin.hooks.event({
    event: { type: "session.created", properties: { info: { id: "session-dispose" } } },
  });
  expect(await eventually(() => broker.received.length === 2)).toBe(true);

  await plugin.hooks.dispose();

  expect(redactFrames(broker.received)).toEqual([
    "HELLO\tversion=1",
    "REGISTER\ttoken=<TOKEN>\tsession=session-dispose\tpid=88",
    "HELLO\tversion=1",
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
          if (line === "HELLO\tversion=1") {
            socket.write("OK\tversion=1\n");
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
  await plugin.hooks.event({
    event: { type: "session.created", properties: { info: { id: "session-d" } } },
  });
  expect(await eventually(() => registrations === 1)).toBe(true);

  const result = toolOutput(
    await plugin.hooks.tool.secrets_request.execute({ key: "FLEET_LICENSE_KEY" }, toolContext("session-d")),
  );

  expect(registrations).toBe(2);
  expect(requestCount).toBe(2);
  expect(result.startsWith("granted:")).toBe(true);
  expect(/[0-9a-f]{64}/.test(result)).toBe(false);
  expect(result.includes("synthetic-secret-value")).toBe(false);
  expect(redactFrames(received)).toEqual([
    "HELLO\tversion=1",
    "REGISTER\ttoken=<TOKEN>\tsession=session-d\tpid=99",
    "HELLO\tversion=1",
    "REQUEST\tkey=FLEET_LICENSE_KEY\ttoken=<TOKEN>",
    "HELLO\tversion=1",
    "REGISTER\ttoken=<TOKEN>\tsession=session-d\tpid=99",
    "HELLO\tversion=1",
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
          if (line === "HELLO\tversion=1") {
            socket.write("OK\tversion=1\n");
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
  await plugin.hooks.event({
    event: { type: "session.created", properties: { info: { id: "session-errors" } } },
  });
  expect(await eventually(() => registrations === 1)).toBe(true);
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

test("maps every non-version, non-token REQUEST error from the daemon", async () => {
  const cases = [
    ["ERR\tBAD_REQUEST\tbad request", "unavailable"],
    ["ERR\tUNKNOWN_OP\tunknown operation", "unavailable"],
    ["ERR\tNO_SCOPE\tno scope", "unavailable"],
    ["ERR\tAGENT_TTY\tagent tty", "unavailable"],
    ["ERR\tNOT_HUMAN_KEY\tnot human", "unavailable"],
    ["ERR\tDENIED\tdenied", "denied"],
    ["ERR\tTIMEOUT\ttimed out", "denied"],
    ["ERR\tYUBIKEY_UNREACHABLE\tunreachable", "unavailable"],
    ["ERR\tTOO_MANY_PENDING\tqueue full", "unavailable"],
    ["ERR\tINTERNAL\tinternal", "unavailable"],
  ] as const;

  for (const [frame, expectedStatus] of cases) {
    const result = await requestGuidanceFor(frame);
    expect(result.startsWith(`${expectedStatus}:`)).toBe(true);
  }
});

test("keeps an OpenCode session usable when the broker socket is absent", async () => {
  const runtimeDir = root();
  const plugin = createSecretsdPlugin({
    runtimeDir,
    socketPath: join(runtimeDir, "absent.sock"),
    pid: 7,
  });
  await plugin.hooks.event({
    event: { type: "session.created", properties: { info: { id: "session-e" } } },
  });
  const output: { env: Record<string, string> } = { env: {} };

  await plugin.hooks["shell.env"]({ sessionID: "session-e" }, output);
  const result = toolOutput(
    await plugin.hooks.tool.secrets_request.execute({ key: "DEEL_API_KEY" }, toolContext("session-e")),
  );

  expect(output.env.SECRETSD_SESSION_TOKEN_FILE).toBe(join(runtimeDir, "secretsd", "session-e.token"));
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
  await plugin.hooks.event({
    event: { type: "session.created", properties: { info: { id: "session-f" } } },
  });

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
          if (line === "HELLO\tversion=1") {
            socket.write("OK\tversion=1\n");
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
  await plugin.hooks.event({
    event: { type: "session.created", properties: { info: { id: "session-abort" } } },
  });
  expect(await eventually(() => registrations === 1)).toBe(true);

  const request = plugin.hooks.tool.secrets_request
    .execute({ key: "PULUMI_CONFIG_PASSPHRASE" }, toolContext("session-abort"))
    .then(toolOutput);
  expect(await eventually(() => requests === 1)).toBe(true);
  await plugin.hooks.dispose();
  const result = await Promise.race([request, Bun.sleep(250).then(() => "still-waiting")]);

  expect(REQUEST_TIMEOUT_MS).toBe(100_000);
  expect(result !== "still-waiting" && result.startsWith("unavailable:")).toBe(true);
  expect(existsSync(join(runtimeDir, "secretsd", "session-abort.token"))).toBe(false);
  server.stop(true);
});
