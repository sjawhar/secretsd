import { afterEach, expect, test } from "bun:test";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { z } from "zod";
import { PROTOCOL_VERSION } from "../../opencode/plugins/secretsd.ts";
import secretsdOmpExtension, { getAnchor, injectSessionToken, setAnchor } from "./secretsd.ts";

// allow: SIZE_OK -- every process-shared-anchor scenario belongs in one file,
// mirroring opencode/plugins/secretsd.test.ts.
const HELLO = `HELLO\tversion=${PROTOCOL_VERSION}`;
const HANDSHAKE = `OK\tversion=${PROTOCOL_VERSION} instance=test-instance\n`;

const roots: string[] = [];
// Every fake broker created by `fakeBroker` (or the specialized brokers built
// for individual tests) registers itself here so `afterEach` can stop it even
// when an assertion throws mid-test -- a thrown expectation must never leak a
// listening unix socket into the next test.
const brokers: Array<{ stop: () => void }> = [];
let originalRuntimeDir: string | undefined;
let originalSocket: string | undefined;
let envOverridden = false;

function root(): string {
	const value = mkdtempSync("/tmp/secretsd-omp-");
	roots.push(value);
	return value;
}

/// Every instance in this file reads its runtime/socket only from the real
/// environment (the omp extension takes no injectable options), so tests
/// point that environment at a scratch runtime dir and fake broker socket.
function setup(): { runtimeDir: string; socketPath: string } {
	const runtimeDir = root();
	originalRuntimeDir = process.env.XDG_RUNTIME_DIR;
	originalSocket = process.env.SECRETSD_SOCK;
	envOverridden = true;
	process.env.XDG_RUNTIME_DIR = runtimeDir;
	const socketPath = join(runtimeDir, "broker.sock");
	process.env.SECRETSD_SOCK = socketPath;
	return { runtimeDir, socketPath };
}

afterEach(() => {
	for (const broker of brokers.splice(0)) {
		broker.stop();
	}
	// The shared anchor lives on `globalThis`; every test must start from a
	// clean process, exactly like a fresh omp launch.
	setAnchor(undefined);
	if (envOverridden) {
		if (originalRuntimeDir === undefined) delete process.env.XDG_RUNTIME_DIR;
		else process.env.XDG_RUNTIME_DIR = originalRuntimeDir;
		if (originalSocket === undefined) delete process.env.SECRETSD_SOCK;
		else process.env.SECRETSD_SOCK = originalSocket;
		envOverridden = false;
	}
	for (const value of roots.splice(0)) {
		rmSync(value, { force: true, recursive: true });
	}
});

/// Polls until `predicate` is true or one second passes, for asserting on a
/// frame that arrives asynchronously over the fake broker's socket.
async function eventually(predicate: () => boolean): Promise<boolean> {
	const deadline = Date.now() + 1_000;
	while (Date.now() < deadline) {
		if (predicate()) return true;
		await Bun.sleep(10);
	}
	return predicate();
}

function defaultRespond(line: string): string {
	if (line === HELLO) return HANDSHAKE;
	if (line.startsWith("REQUEST\t")) return "OK\tstatus=granted\n";
	return "OK\n";
}

function fakeBroker(socketPath: string, respond: (line: string) => string = defaultRespond) {
	const received: string[] = [];
	let buffered = "";
	const server = Bun.listen({
		unix: socketPath,
		socket: {
			data(socket, data) {
				buffered += new TextDecoder().decode(data);
				for (;;) {
					const newline = buffered.indexOf("\n");
					if (newline < 0) return;
					const line = buffered.slice(0, newline);
					buffered = buffered.slice(newline + 1);
					received.push(line);
					socket.write(respond(line));
				}
			},
		},
	});
	const broker = { received, stop: () => server.stop(true) };
	brokers.push(broker);
	return broker;
}

/// A broker that answers HELLO/REGISTER/UNREGISTER normally but never
/// answers REQUEST -- it just records the frame and leaves the connection
/// open, simulating a broker mid-decision so a test can assert what happens
/// to a `secrets_request` still in flight when its owning session tears down.
function pendingRequestBroker(socketPath: string) {
	const received: string[] = [];
	let buffered = "";
	const server = Bun.listen({
		unix: socketPath,
		socket: {
			data(socket, data) {
				buffered += new TextDecoder().decode(data);
				for (;;) {
					const newline = buffered.indexOf("\n");
					if (newline < 0) return;
					const line = buffered.slice(0, newline);
					buffered = buffered.slice(newline + 1);
					received.push(line);
					if (line === HELLO) socket.write(HANDSHAKE);
					else if (line.startsWith("REQUEST\t")) continue; // hold: never respond
					else socket.write("OK\n");
				}
			},
		},
	});
	const broker = { received, stop: () => server.stop(true) };
	brokers.push(broker);
	return broker;
}

/// A broker that answers HELLO immediately but holds every REGISTER frame's
/// socket open without responding, until `release()` writes "OK\n" to each
/// one -- for asserting what happens when a REGISTER is still in flight when
/// the anchor that sent it gets retired out from under it.
function delayedRegisterBroker(socketPath: string) {
	const received: string[] = [];
	const held: Array<{ write: (data: string) => void }> = [];
	let buffered = "";
	const server = Bun.listen({
		unix: socketPath,
		socket: {
			data(socket, data) {
				buffered += new TextDecoder().decode(data);
				for (;;) {
					const newline = buffered.indexOf("\n");
					if (newline < 0) return;
					const line = buffered.slice(0, newline);
					buffered = buffered.slice(newline + 1);
					received.push(line);
					if (line === HELLO) socket.write(HANDSHAKE);
					else if (line.startsWith("REGISTER\t")) held.push(socket);
					else socket.write("OK\n");
				}
			},
		},
	});
	const broker = {
		received,
		release: () => {
			for (const socket of held.splice(0)) socket.write("OK\n");
		},
		stop: () => server.stop(true),
	};
	brokers.push(broker);
	return broker;
}

function redactFrames(frames: readonly string[]): string[] {
	return frames.map((frame) => frame.replace(/token=[0-9a-f]{64}/g, "token=<TOKEN>"));
}

type FakeToolResult = { isError: boolean; content: unknown; details?: unknown };
type FakeTool = {
	name: string;
	execute: (toolCallId: string, params: unknown, signal: AbortSignal | undefined) => Promise<FakeToolResult>;
};
type FakeHandler = (event: unknown, ctx: unknown) => unknown;

/// A minimal `ExtensionAPI` double: `secretsdOmpExtension` only calls `zod`,
/// `on`, and `registerTool`, so nothing else needs a fake. Cast at the library
/// boundary: this object intentionally implements a strict subset of
/// `ExtensionAPI`.
function fakePi(): { pi: ExtensionAPI; handlers: Record<string, FakeHandler>; tools: Record<string, FakeTool> } {
	const handlers: Record<string, FakeHandler> = {};
	const tools: Record<string, FakeTool> = {};
	const double = {
		zod: z,
		on(event: string, handler: FakeHandler) {
			handlers[event] = handler;
		},
		registerTool(tool: FakeTool) {
			tools[tool.name] = tool;
		},
	};
	return { pi: double as unknown as ExtensionAPI, handlers, tools };
}

/// Mount one `secretsdOmpExtension` instance and drive its `session_start`,
/// exactly like omp re-invoking `loadExtensions` for the root session or one
/// in-process subagent session.
async function mountSession(sessionID: string): Promise<{
	handlers: Record<string, FakeHandler>;
	tools: Record<string, FakeTool>;
	notifications: string[];
}> {
	const { pi, handlers, tools } = fakePi();
	secretsdOmpExtension(pi);
	const notifications: string[] = [];
	const ctx = {
		sessionManager: { getSessionId: () => sessionID },
		ui: { notify: (message: string) => notifications.push(message) },
	};
	await handlers.session_start(undefined, ctx);
	return { handlers, tools, notifications };
}

test("two in-process instances share one registration and one token file", async () => {
	const { runtimeDir } = setup();
	const broker = fakeBroker(process.env.SECRETSD_SOCK as string);

	await mountSession("root-session");
	await mountSession("subagent-session");

	// Exactly one REGISTER reached the broker, even though two sessions
	// (root + subagent) each ran their own session_start. The trailing HELLO
	// is the subagent's own ensureRegistered call finding the anchor already
	// believed registered and probing the daemon before trusting that belief.
	expect(redactFrames(broker.received)).toEqual([
		HELLO,
		`REGISTER\ttoken=<TOKEN>\tsession=root-session\tpid=${process.pid}`,
		HELLO,
	]);

	// The anchor still names the root session; the subagent never displaced it
	// and never minted its own token file.
	const anchor = getAnchor();
	expect(anchor?.ownerSessionId).toBe("root-session");
	expect(existsSync(join(runtimeDir, "secretsd", "root-session.token"))).toBe(true);
	expect(existsSync(join(runtimeDir, "secretsd", "subagent-session.token"))).toBe(false);

	// injectSessionToken is the literal spawnHook both instances' bash tools
	// were built with; it must inject the anchor's (root's) token file, not a
	// per-instance one, regardless of which instance's shell invoked it.
	const spawnResult = injectSessionToken({ env: { PATH: "/usr/bin" } });
	expect(spawnResult.env?.SECRETSD_SESSION_TOKEN_FILE).toBe(anchor?.state.tokenFile);
	expect(spawnResult.env?.PATH).toBe("/usr/bin");
});

test("only the owner's session_shutdown unregisters and removes the token file", async () => {
	const { runtimeDir } = setup();
	const broker = fakeBroker(process.env.SECRETSD_SOCK as string);

	const owner = await mountSession("root-session");
	const subagent = await mountSession("subagent-session");
	const tokenPath = join(runtimeDir, "secretsd", "root-session.token");

	await subagent.handlers.session_shutdown(undefined, undefined);

	// A subagent's shutdown must never touch the broker or the token file --
	// doing so would revoke every grant for the whole tree. The trailing HELLO
	// before it is the subagent's own ensureRegistered probe.
	expect(redactFrames(broker.received)).toEqual([
		HELLO,
		`REGISTER\ttoken=<TOKEN>\tsession=root-session\tpid=${process.pid}`,
		HELLO,
	]);
	expect(existsSync(tokenPath)).toBe(true);
	expect(getAnchor()).toBeDefined();

	await owner.handlers.session_shutdown(undefined, undefined);

	expect(redactFrames(broker.received)).toEqual([
		HELLO,
		`REGISTER\ttoken=<TOKEN>\tsession=root-session\tpid=${process.pid}`,
		HELLO,
		HELLO,
		"UNREGISTER\tsession=root-session",
	]);
	expect(existsSync(tokenPath)).toBe(false);
	expect(getAnchor()).toBeUndefined();
});

test("secrets_request from a non-owner instance sends the anchor session's token", async () => {
	setup();
	const broker = fakeBroker(process.env.SECRETSD_SOCK as string);

	await mountSession("root-session");
	const subagent = await mountSession("subagent-session");
	const anchorToken = getAnchor()?.state.token;
	expect(anchorToken).toBeTruthy();

	const result = await subagent.tools.secrets_request.execute(
		"tool-call-1",
		{ key: "DEEL_API_KEY" },
		new AbortController().signal,
	);

	expect(result.isError).toBe(false);
	const requestFrames = redactFrames(broker.received.filter((line) => line.startsWith("REQUEST\t")));
	expect(requestFrames).toEqual(["REQUEST\tkey=DEEL_API_KEY\ttoken=<TOKEN>"]);
});

test("owner session_info_changed re-registers with a fresh token; a non-owner's is a no-op", async () => {
	const { runtimeDir } = setup();
	const broker = fakeBroker(process.env.SECRETSD_SOCK as string);

	const owner = await mountSession("root-session");
	const subagent = await mountSession("subagent-session");
	const originalToken = getAnchor()?.state.token;

	// Non-owner: its own session id changing must never re-key the shared
	// anchor -- only the owner may retire and replace the tree's identity.
	await subagent.handlers.session_info_changed(undefined, {
		sessionManager: { getSessionId: () => "subagent-session-renamed" },
	});
	expect(getAnchor()?.ownerSessionId).toBe("root-session");
	expect(getAnchor()?.state.token).toBe(originalToken);

	// Owner: a /new-style id change is a new presence-proof scope -- mint a
	// fresh token, retire the old registration, and register the new one. The
	// handler awaits both, so this resolves only once they are done.
	await owner.handlers.session_info_changed(undefined, {
		sessionManager: { getSessionId: () => "root-session-2" },
	});

	const anchor = getAnchor();
	expect(anchor?.ownerSessionId).toBe("root-session-2");
	expect(anchor?.registered).toBe(true);
	expect(anchor?.state.token).not.toBe(originalToken);
	expect(existsSync(join(runtimeDir, "secretsd", "root-session.token"))).toBe(false);
	expect(existsSync(join(runtimeDir, "secretsd", "root-session-2.token"))).toBe(true);

	const registerFrames = redactFrames(broker.received.filter((line) => line.startsWith("REGISTER\t")));
	expect(registerFrames).toEqual([
		`REGISTER\ttoken=<TOKEN>\tsession=root-session\tpid=${process.pid}`,
		`REGISTER\ttoken=<TOKEN>\tsession=root-session-2\tpid=${process.pid}`,
	]);
	expect(broker.received).toContain("UNREGISTER\tsession=root-session");
});

test("a restarted daemon re-registers the same token on the next request", async () => {
	setup();
	// A mutable instance id in the handshake response stands in for a daemon
	// restart -- see opencode/plugins/secretsd.test.ts's
	// "re-registers a live session when the daemon reports a new instance",
	// which uses the same technique instead of actually rebinding the socket.
	let instance = "instance-one";
	const broker = fakeBroker(process.env.SECRETSD_SOCK as string, (line) => {
		if (line === HELLO) return `OK\tversion=${PROTOCOL_VERSION} instance=${instance}\n`;
		if (line.startsWith("REQUEST\t")) return "OK\tstatus=granted\n";
		return "OK\n";
	});

	const owner = await mountSession("root-session");
	const token = getAnchor()?.state.token;
	expect(token).toBeTruthy();

	instance = "instance-two";
	const result = await owner.tools.secrets_request.execute(
		"tool-call-1",
		{ key: "DEEL_API_KEY" },
		new AbortController().signal,
	);

	expect(result.isError).toBe(false);
	// ensureRegistered's probe (inside secrets_request) sees the new instance
	// id, forgets the belief that it is registered, and re-registers before
	// the REQUEST goes out -- with the SAME token, not a freshly minted one:
	// the skill's "run the command once more" promise depends on this.
	const registerFrames = broker.received.filter((line) => line.startsWith("REGISTER\t"));
	expect(registerFrames).toEqual([
		`REGISTER\ttoken=${token}\tsession=root-session\tpid=${process.pid}`,
		`REGISTER\ttoken=${token}\tsession=root-session\tpid=${process.pid}`,
	]);
});

test("owner session_shutdown fences an in-flight secrets_request instead of letting it resurrect the anchor", async () => {
	setup();
	const broker = pendingRequestBroker(process.env.SECRETSD_SOCK as string);

	const owner = await mountSession("root-session");
	const requestPromise = owner.tools.secrets_request.execute(
		"tool-call-1",
		{ key: "DEEL_API_KEY" },
		new AbortController().signal,
	);

	// Let the REQUEST actually reach the (never-answering) broker before
	// tearing the session down, so the abort races a genuinely in-flight call.
	await eventually(() => broker.received.some((line) => line.startsWith("REQUEST\t")));
	await owner.handlers.session_shutdown(undefined, undefined);

	// The abort fired by session_shutdown (BEFORE unregister/removeTokenFile)
	// must fail the pending request loudly rather than let its `reregister`
	// resurrect the anchor after teardown.
	const result = await requestPromise;
	expect(result.isError).toBe(true);
	expect(broker.received.filter((line) => line.startsWith("REGISTER\t"))).toHaveLength(1);
});

test("secrets_request lazily reclaims a missing anchor under the invoking instance's own session id", async () => {
	setup();
	const broker = fakeBroker(process.env.SECRETSD_SOCK as string);

	const owner = await mountSession("root-session");
	// A missing anchor here stands in for a prior claim that failed or was
	// torn down -- `owner`'s closure still believes it is the owner, but the
	// process-shared anchor itself is gone.
	setAnchor(undefined);

	const result = await owner.tools.secrets_request.execute(
		"tool-call-1",
		{ key: "DEEL_API_KEY" },
		new AbortController().signal,
	);

	expect(result.isError).toBe(false);
	expect(getAnchor()?.ownerSessionId).toBe("root-session");
	const registerFrames = redactFrames(broker.received.filter((line) => line.startsWith("REGISTER\t")));
	expect(registerFrames).toEqual([
		`REGISTER\ttoken=<TOKEN>\tsession=root-session\tpid=${process.pid}`,
		`REGISTER\ttoken=<TOKEN>\tsession=root-session\tpid=${process.pid}`,
	]);
});

test("a REGISTER that resolves after owner teardown gets a compensating UNREGISTER and never marks the anchor registered", async () => {
	setup();
	const broker = delayedRegisterBroker(process.env.SECRETSD_SOCK as string);

	const { pi, handlers } = fakePi();
	secretsdOmpExtension(pi);
	const ctx = {
		sessionManager: { getSessionId: () => "root-session" },
		ui: { notify: () => {} },
	};
	// Not awaited yet: `session_start`'s `ensureRegistered` blocks on the
	// broker's (held) REGISTER response, so this promise settles only after
	// `broker.release()` below.
	const startPromise = handlers.session_start(undefined, ctx);

	// Let the REGISTER frame actually reach the (held) broker before tearing
	// the session down mid-registration.
	await eventually(() => broker.received.some((line) => line.startsWith("REGISTER\t")));
	const anchorDuringRegistration = getAnchor();
	await handlers.session_shutdown(undefined, undefined);
	expect(getAnchor()).toBeUndefined();

	// Now let the delayed REGISTER response arrive, after retirement.
	broker.release();
	await startPromise;

	// The daemon believes it registered this token; nobody here does. The
	// compensating UNREGISTER tells it so, and `registered` is never flipped
	// true for an anchor that no longer exists.
	expect(anchorDuringRegistration?.registered).toBe(false);
	expect(broker.received.filter((line) => line.startsWith("REGISTER\t"))).toHaveLength(1);
	expect(broker.received.filter((line) => line.startsWith("UNREGISTER\t"))).toHaveLength(1);
});

test("resources_discover advertises the package's real skills directory", async () => {
	const { pi, handlers } = fakePi();
	secretsdOmpExtension(pi);
	const result = (await handlers.resources_discover(undefined, undefined)) as { skillPaths: string[] };
	// v2.5.1 shipped "../../../skills" -- the package's PARENT -- so the plugin
	// advertised a directory that does not exist, and shipped skills silently
	// vanished on any host without omp's own plugin sub-discovery channel.
	expect(result.skillPaths).toHaveLength(1);
	expect(existsSync(result.skillPaths[0] as string)).toBe(true);
	expect(existsSync(join(result.skillPaths[0] as string, "using-secrets", "SKILL.md"))).toBe(true);
});
