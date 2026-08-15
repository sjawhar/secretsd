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
 */
// `createBashTool` is declared in dist/types/extensibility/legacy-pi-coding-agent-shim.d.ts:125;
// the package's dist/types/index.d.ts barrel omits that legacy export.
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
const SKILLS_DIRECTORY = resolve(extensionDir, "../../opencode/skills");

export default function secretsdOmpExtension(pi: ExtensionAPI) {
	const z = pi.zod;
	let runtimeDir: string | null = null;
	let broker: BrokerClient | null = null;
	let brokerInstance = "";
	const states = new Map<string, SessionState>();
	const registered = new Set<string>();
	const registrations = new Map<string, Promise<SessionState>>();
	const requestAbort = new AbortController();
	let currentSessionId = "";

	function initBroker(): BrokerClient {
		if (broker) return broker;
		runtimeDir = resolveRuntimeDir(undefined, process.env.XDG_RUNTIME_DIR, process.getuid?.());
		broker = new BrokerClient(resolveSocketPath(undefined, process.env.SECRETSD_SOCK, runtimeDir), (instance) => {
			// A new instance id means the daemon restarted and dropped every
			// registration; forget ours so the next use re-registers.
			if (brokerInstance && instance !== brokerInstance) {
				registered.clear();
			}
			brokerInstance = instance;
		});
		return broker;
	}

	function ensureState(sessionID: string): SessionState {
		let state = states.get(sessionID);
		if (!state) {
			initBroker();
			if (!runtimeDir) throw new Error("secretsd runtime directory unavailable");
			state = issueTokenFile(runtimeDir, sessionID);
			states.set(sessionID, state);
		} else if (runtimeDir && !existsSync(state.tokenFile)) {
			restoreTokenFile(runtimeDir, sessionID, state);
		}
		return state;
	}

	async function ensureRegistered(sessionID: string): Promise<SessionState> {
		const state = ensureState(sessionID);
		const client = initBroker();
		if (registered.has(sessionID)) {
			try {
				await client.probe();
			} catch {
				// Unreachable broker: keep the belief; the request itself reports.
			}
			if (registered.has(sessionID)) return state;
		}
		const inFlight = registrations.get(sessionID);
		if (inFlight) return inFlight;
		const registration = client
			.register(state, sessionID, process.pid)
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
		currentSessionId = ctx.sessionManager.getSessionId();
		try {
			await ensureRegistered(currentSessionId);
		} catch (err) {
			// Broker down must not block the session; tools report the details.
			ctx.ui.notify(`secretsd: registration deferred (${String(err)})`, "warning");
		}

		// Override bash so every agent shell carries this session's token file.
		// spawnHook is synchronous: state was prepared above, and ensureState
		// re-materializes a deleted token file on the fly.
		pi.registerTool(
			createBashTool(process.cwd(), {
				spawnHook: (spawnCtx: { env?: Record<string, string> }) => {
					try {
						const state = ensureState(currentSessionId);
						// Drop env names the spawn validator rejects (e.g. exported bash
						// functions encoded as `BASH_FUNC_name%%`). The default tool never
						// round-trips these; a spawnHook-supplied env does.
						const env: Record<string, string> = {};
						for (const [k, v] of Object.entries(spawnCtx.env ?? {})) {
							if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(k)) env[k] = v;
						}
						env.SECRETSD_SESSION_TOKEN_FILE = state.tokenFile;
						return { ...spawnCtx, env };
					} catch {
						return spawnCtx;
					}
				},
			}),
		);
	});

	pi.on("session_info_changed", async (_event, ctx: ExtensionContext) => {
		// Session id can change on new/switch/fork; keep registrations keyed right.
		const id = ctx.sessionManager.getSessionId();
		if (id && id !== currentSessionId) {
			currentSessionId = id;
			ensureRegistered(id).catch(() => {});
		}
	});

	pi.on("session_shutdown", async () => {
		requestAbort.abort();
		await Promise.allSettled(
			[...states.entries()].map(async ([sessionID, state]) => {
				try {
					if (registered.has(sessionID)) {
						await broker?.unregister(sessionID);
					}
				} catch {
					// Best-effort: daemon reaps dead pids on its own.
				} finally {
					removeTokenFile(state);
					states.delete(sessionID);
					registered.delete(sessionID);
					registrations.delete(sessionID);
				}
			}),
		);
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
				const client = initBroker();
				const state = await ensureRegistered(currentSessionId);
				const outcome = await requestSecret(client, {
					state,
					sessionID: currentSessionId,
					pid: process.pid,
					key: params.key,
					signal: signal ? AbortSignal.any([signal, requestAbort.signal]) : requestAbort.signal,
					reregister: async () => {
						registered.delete(currentSessionId);
						await ensureRegistered(currentSessionId);
					},
				});
				return toolResult(params.key, outcome);
			} catch (error) {
				return toolResult(params.key, failureOutcome(error));
			}
		},
	});
}
