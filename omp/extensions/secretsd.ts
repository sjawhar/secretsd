/**
 * secretsd extension for oh-my-pi (omp).
 *
 * Mirrors the OpenCode plugin (../../opencode/plugins/secretsd.ts) using omp's
 * ExtensionAPI, and imports the protocol client from it so the broker protocol
 * stays single-sourced:
 *
 * - registers the session with the secretsd broker and writes its token file
 * - overrides the bash tool so SECRETSD_SESSION_TOKEN_FILE is present, letting
 *   `secrets` CLI calls inside agent shells act with this session's identity
 *   (human-tier keys included, after approval)
 * - registers the secrets_request tool for YubiKey-gated approval requests
 * - exposes the bundled using-secrets skill
 * - unregisters and removes the token file on shutdown
 *
 * Session IDs: omp mints UUIDv7s, which satisfy the plugin's SESSION_ID_PATTERN.
 *
 * Process-shared identity: omp re-invokes `loadExtensions` for every
 * in-process subagent session, so each Extension binds to THAT session's own
 * `ExtensionAPI` (cwd, eventBus, runtime) -- `secretsdOmpExtension` therefore
 * runs once per session, root and every subagent alike, each getting a fresh
 * closure with no module state shared between them. Neither `SessionStartEvent`
 * nor `ExtensionContext` carries a root/subagent indicator (checked against
 * `@earendil-works/pi-coding-agent`'s published extension types: no such field
 * exists), so identity is anchored on `globalThis` instead of per-instance
 * state: the first instance to observe `session_start` in this OS process
 * mints the token and registers with the broker (the OWNER); every later
 * instance -- always a subagent, since subagents are created only after the
 * root session has already started -- adopts that anchor and never mints a
 * token or registers a scope of its own. Because subagents run in the SAME
 * process as the root (in-process `loadExtensions`, not a spawned child), the
 * daemon's `SO_PEERPIDFD` ancestry pin taken at REGISTER names that one shared
 * process regardless of which instance happened to call `register`. This is
 * what makes spawnHook and secrets_request in a subagent act as the root
 * session -- extending docs/design.md's "the token-file path is inherited by
 * everything the session spawns" from a single session's process tree to the
 * whole in-process session tree.
 */
import { createBashTool, type ExtensionAPI, type ExtensionContext } from "@earendil-works/pi-coding-agent";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
	BrokerClient,
	failureOutcome,
	guidance,
	issueTokenFile,
	removeTokenFile,
	requestSecret,
	resolveRuntimeDir,
	resolveSocketPath,
	restoreTokenFile,
	type RequestOutcome,
	type SessionState,
} from "../../opencode/plugins/secretsd.ts";

const extensionDir = dirname(fileURLToPath(import.meta.url));
// One level up from omp/extensions/ is omp/; two is the package root, whose
// skills/ directory ships the using-secrets skill. v2.5.1 shipped an
// off-by-one ("../../../skills" = the package's PARENT), silently advertising
// a directory that does not exist; omp's own plugin sub-discovery masked it.
const SKILLS_DIRECTORY = resolve(extensionDir, "../../skills");

/// The process-wide identity every `secretsdOmpExtension` instance shares: one
/// token, one broker registration, one BrokerClient, regardless of how many
/// in-process sessions (root + subagents) load this extension.
export type SharedAnchor = {
	ownerSessionId: string;
	state: SessionState;
	runtimeDir: string;
	broker: BrokerClient;
	brokerInstance: string;
	registered: boolean;
	registration: Promise<void> | null;
	/// Aborts every in-flight `secrets_request` pinned to this anchor. Fired
	/// by the owner's `session_shutdown` and by the re-key path in
	/// `session_info_changed` -- both BEFORE the token file disappears or the
	/// broker registration is torn down -- so a request racing teardown fails
	/// loudly instead of resurrecting a dead anchor's registration.
	abort: AbortController;
};

/// `Symbol.for` (not a module-level `let`) because omp's per-session
/// `loadExtensions` call may or may not share this module's instance across
/// sessions; `globalThis` is correct either way.
export const SHARED_ANCHOR_KEY = Symbol.for("secretsd.omp.session");

/// The process-shared anchor accessor: the read/write seam every instance
/// (and every test) uses instead of touching `globalThis` directly.
export function getAnchor(): SharedAnchor | undefined {
	return (globalThis as Record<PropertyKey, unknown>)[SHARED_ANCHOR_KEY] as SharedAnchor | undefined;
}

export function setAnchor(anchor: SharedAnchor | undefined): void {
	(globalThis as Record<PropertyKey, unknown>)[SHARED_ANCHOR_KEY] = anchor;
}

function createAnchor(sessionID: string): SharedAnchor {
	const runtimeDir = resolveRuntimeDir(undefined, process.env.XDG_RUNTIME_DIR, process.getuid?.());
	if (!runtimeDir) throw new Error("secretsd runtime directory unavailable");
	const state = issueTokenFile(runtimeDir, sessionID);
	const broker = new BrokerClient(resolveSocketPath(undefined, process.env.SECRETSD_SOCK, runtimeDir), (instance) => {
		// A new instance id means the daemon restarted and dropped every
		// registration; forget ours so the next use re-registers. Read the
		// anchor fresh: by the time a handshake resolves, session_info_changed
		// may have re-keyed it to a new SharedAnchor object.
		const anchor = getAnchor();
		if (!anchor) return;
		if (anchor.brokerInstance && instance !== anchor.brokerInstance) {
			anchor.registered = false;
		}
		anchor.brokerInstance = instance;
	});
	return {
		ownerSessionId: sessionID,
		state,
		runtimeDir,
		broker,
		brokerInstance: "",
		registered: false,
		registration: null,
		abort: new AbortController(),
	};
}

/// First `session_start` in the process wins ownership of the shared anchor;
/// every later instance (always a subagent) adopts it. The read-then-write is
/// synchronous end to end -- no `await` in between -- so two in-process
/// `session_start` handlers can never race this check.
function claimOrAdoptAnchor(sessionID: string): { anchor: SharedAnchor; owner: boolean } {
	const existing = getAnchor();
	if (existing) return { anchor: existing, owner: false };
	const anchor = createAnchor(sessionID);
	setAnchor(anchor);
	return { anchor, owner: true };
}

function ensureTokenFile(anchor: SharedAnchor): void {
	if (!existsSync(anchor.state.tokenFile)) {
		restoreTokenFile(anchor.runtimeDir, anchor.ownerSessionId, anchor.state);
	}
}

/// Throws if `anchor` is no longer the process-shared anchor, or its session
/// already tore down, by the time this fence runs. Every path that can
/// register or re-register on `anchor`'s behalf calls this first -- and, for
/// `ensureRegistered`, again right before actually sending REGISTER -- so a
/// call that started against a live anchor (a probe fired from
/// `injectSessionToken`, a queued `secrets_request`) can never resume after
/// `session_shutdown` or a `session_info_changed` re-key has retired it.
function assertAnchorLive(anchor: SharedAnchor): void {
	if (getAnchor() !== anchor || anchor.abort.signal.aborted) {
		throw new Error("secretsd session ended during the request");
	}
}

async function ensureRegistered(anchor: SharedAnchor): Promise<SessionState> {
	assertAnchorLive(anchor);
	if (anchor.registered) {
		try {
			await anchor.broker.probe();
		} catch {
			// Unreachable broker: keep the belief; the request itself reports.
		}
		if (anchor.registered) return anchor.state;
	}
	if (anchor.registration) {
		await anchor.registration;
		return anchor.state;
	}
	// Re-check right before committing to a REGISTER: the probe above awaited
	// a round trip, during which teardown or a re-key may have retired this
	// anchor.
	assertAnchorLive(anchor);
	const registration = anchor.broker
		.register(anchor.state, anchor.ownerSessionId, process.pid)
		.then(async () => {
			if (getAnchor() !== anchor || anchor.abort.signal.aborted) {
				// Retired while REGISTER was on the wire: the daemon now
				// believes this token is registered, but nobody here does.
				// Compensate so it doesn't keep a live scope for an anchor
				// this process has abandoned, and never flip `registered`.
				try {
					await anchor.broker.unregister(anchor.ownerSessionId);
				} catch {
					// Best-effort: daemon reaps dead pids on its own.
				}
				throw new Error("secretsd session ended during the request");
			}
			anchor.registered = true;
		})
		.finally(() => {
			anchor.registration = null;
		});
	anchor.registration = registration;
	await registration;
	return anchor.state;
}

/// The bash tool's spawnHook in every instance -- owner and every subagent
/// alike -- so every agent shell in the process tree carries the anchor's
/// token file and therefore the root session's broker identity. Synchronous:
/// `ensureTokenFile` re-materializes a deleted token file on the fly.
export function injectSessionToken(spawnCtx: { env?: Record<string, string> }): { env?: Record<string, string> } {
	const anchor = getAnchor();
	if (!anchor) return spawnCtx;
	// The spawn hook is synchronous and cannot await a broker round trip, so
	// this probe's result always arrives after THIS command has already
	// spawned with whatever token file is on disk. What it buys: if the
	// daemon restarted, the probe's handshake carries a new instance id,
	// which flips `anchor.registered` false and re-registers the SAME token
	// in the background -- so the *next* `secrets <KEY> -- cmd` (the skill's
	// "run the command once more") finds a live registration instead of
	// repeating the same TIMEOUT. Mirrors opencode's per-command
	// shell.env re-registration, just fired here instead of awaited there.
	void ensureRegistered(anchor).catch(() => {});
	try {
		ensureTokenFile(anchor);
		// Drop env names the spawn validator rejects (e.g. exported bash
		// functions encoded as `BASH_FUNC_name%%`). The default tool never
		// round-trips these; a spawnHook-supplied env does.
		const env: Record<string, string> = {};
		for (const [k, v] of Object.entries(spawnCtx.env ?? {})) {
			if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(k)) env[k] = v;
		}
		env.SECRETSD_SESSION_TOKEN_FILE = anchor.state.tokenFile;
		return { ...spawnCtx, env };
	} catch {
		return spawnCtx;
	}
}

export default function secretsdOmpExtension(pi: ExtensionAPI) {
	const z = pi.zod;
	let isOwner = false;
	let claimed = false;
	// Captured at `session_start` so `secrets_request`'s lazy-reclaim path
	// (getAnchor() undefined -- a failed/torn-down claim) has this instance's
	// own session id to claim under, without re-deriving it from `ctx`.
	let ownSessionId: string | undefined;
	const requestAbort = new AbortController();

	function toolResult(key: string, outcome: RequestOutcome) {
		const text = guidance(outcome);
		const isError = !(
			outcome.kind === "granted" ||
			(outcome.kind === "daemon-error" && (outcome.code === "NOT_HUMAN_KEY" || outcome.code === "DENIED"))
		);
		return {
			content: [{ type: "text", text: `${key}: ${text}` }],
			isError,
			details: { key, outcome: outcome.kind },
		};
	}

	pi.on("resources_discover", async () => ({ skillPaths: [SKILLS_DIRECTORY] }));

	pi.on("session_start", async (_event, ctx: ExtensionContext) => {
		const sessionID = ctx.sessionManager.getSessionId();
		ownSessionId = sessionID;
		try {
			// Decide ownership at most once per instance -- a "reload"
			// session_start firing again on an already-adopting (non-owner)
			// instance must never re-run the first-wins race UNLESS the anchor
			// itself is gone: a torn-down or never-claimed anchor stranding the
			// whole tree is worse than a subagent claiming it, so ANY instance --
			// owner or subagent -- that observes a missing anchor here may claim
			// it (still the synchronous, race-free read-then-write below).
			if (!claimed || !getAnchor()) {
				const claim = claimOrAdoptAnchor(sessionID);
				isOwner = claim.owner;
				claimed = true;
			}
			const anchor = getAnchor();
			if (!anchor) throw new Error("secretsd anchor unavailable");
			await ensureRegistered(anchor);
		} catch (err) {
			// Broker down (or runtime dir unavailable) must not block the
			// session; tools report the details.
			ctx.ui.notify(`secretsd: registration deferred (${String(err)})`, "warning");
		}

		// Override bash so every agent shell carries the anchor's token file.
		pi.registerTool(createBashTool(process.cwd(), { spawnHook: injectSessionToken }));
	});

	pi.on("session_info_changed", async (_event, ctx: ExtensionContext) => {
		// A subagent's own session id never changes, and it must never mint the
		// whole tree a second identity -- only the owner re-keys the anchor.
		if (!isOwner) return;
		const id = ctx.sessionManager.getSessionId();
		const previous = getAnchor();
		if (!id || !previous || id === previous.ownerSessionId) return;

		// Session id can change on new/switch/fork; a new logical session is a
		// new presence-proof scope (docs/design.md "Grant lifecycle"), so mint a
		// fresh token and re-register rather than reusing the retiring one.
		let next: SharedAnchor;
		try {
			next = {
				...previous,
				ownerSessionId: id,
				state: issueTokenFile(previous.runtimeDir, id),
				registered: false,
				registration: null,
				// A fresh controller: `next` is a new presence-proof scope, so it
				// must not inherit `previous.abort`, which is about to fire.
				abort: new AbortController(),
			};
		} catch {
			return; // Could not mint a fresh token; keep the retiring anchor intact.
		}
		setAnchor(next);
		// Fence BEFORE unregistering/removing the token file: any
		// `secrets_request` still in flight against `previous` must fail loudly
		// rather than resurrect it via `reregister`.
		previous.abort.abort();
		removeTokenFile(previous.state);
		if (previous.registered) {
			try {
				await previous.broker.unregister(previous.ownerSessionId);
			} catch {
				// Best-effort: daemon reaps dead pids on its own.
			}
		}
		try {
			await ensureRegistered(next);
		} catch {
			// Broker down must not block the session switch; the next request
			// (secrets_request or a bash spawn) reports why.
		}
	});

	pi.on("session_shutdown", async () => {
		requestAbort.abort();
		// A subagent's shutdown must never unregister the anchor: that would
		// revoke every grant for the whole tree out from under the root and any
		// sibling subagent still running. Only the owner tears it down.
		if (!isOwner) return;
		const anchor = getAnchor();
		if (!anchor) return;
		// Fence BEFORE unregistering/removing the token file: any
		// `secrets_request` still in flight must fail loudly rather than
		// resurrect the anchor via `reregister` after teardown starts.
		anchor.abort.abort();
		try {
			if (anchor.registered) await anchor.broker.unregister(anchor.ownerSessionId);
		} catch {
			// Best-effort: daemon reaps dead pids on its own.
		} finally {
			removeTokenFile(anchor.state);
			setAnchor(undefined);
		}
	});

	pi.registerTool({
		name: "secrets_request",
		label: "Secrets Request",
		description:
			"Request human approval for a secretsd human-tier key; never returns secret values. After a grant, run commands with `secrets <KEY> -- <command>`.",
		parameters: z.object({
			key: z
				.string()
				.regex(/^[A-Z][A-Z0-9_]*$/, "key must be an UPPER_SNAKE_CASE secret name")
				.describe("Secret key name, e.g. DEEL_API_KEY"),
		}),
		execute: async (_id, params, signal) => {
			try {
				let anchor = getAnchor();
				if (!anchor) {
					// A missing anchor means a prior claim failed, was never made, or
					// was torn down (session_shutdown, `secrets lock`, a lost race);
					// claiming lazily here -- keyed off THIS instance's own session
					// id -- lets the very request that discovered the gap self-heal
					// it instead of erroring for the rest of the process's life.
					// Except when THIS instance's own session already shut down
					// (`requestAbort` fired): a stale call surviving past that point
					// must not mint and register a brand new anchor on its behalf.
					if (requestAbort.signal.aborted || !ownSessionId) {
						throw new Error("secretsd session not initialized");
					}
					const claim = claimOrAdoptAnchor(ownSessionId);
					anchor = claim.anchor;
					isOwner = claim.owner;
				}
				await ensureRegistered(anchor);
				const outcome = await requestSecret(anchor.broker, {
					state: anchor.state,
					sessionID: anchor.ownerSessionId,
					pid: process.pid,
					key: params.key,
					signal: AbortSignal.any(
						signal
							? [signal, requestAbort.signal, anchor.abort.signal]
							: [requestAbort.signal, anchor.abort.signal],
					),
					reregister: async () => {
						// The anchor this request started against may have been torn
						// down (teardown fence above) or re-keyed (session_info_changed)
						// while the request was in flight; re-registering it now would
						// resurrect a dead registration instead of failing loudly.
						assertAnchorLive(anchor);
						anchor.registered = false;
						await ensureRegistered(anchor);
					},
				});
				return toolResult(params.key, outcome);
			} catch (error) {
				return toolResult(params.key, failureOutcome(error));
			}
		},
	});
}
