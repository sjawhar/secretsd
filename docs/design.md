# Secrets Session Broker (`secretsd`) — Design

**Status**: current architecture

## Goal

Human-gated secrets (currently DEEL_API_KEY and PULUMI_CONFIG_PASSPHRASE)
**at grant time only** (one YubiKey touch), and remain available to that
session — and only that session — for the session's lifetime. Agent-tier
secrets keep working unattended with zero interaction, exactly as today.

### Threat model (what this defends against)

1. **Use while the user is away**: no new grant can be created without a
   physical YubiKey touch. An idle machine cannot mint access.
2. **Cross-session grant theft by string-claiming**: a session cannot obtain
   another session's grant by claiming its session ID. Authorization requires
   an unguessable per-session token issued by trusted harness code.
3. **Attribution**: every human-tier access is recorded in structured
   journald fields with its scope and caller details. The YubiKey blink is the
   physical prompt and its touch is the authorization.

### Accepted residual risks (stated plainly)

- **Same-UID reality**: all agents run as the same Unix user as the human. A
  *malicious* process can ptrace the broker, read `/proc/<pid>/environ` of a
  granted session, or read secrets out of a child process env. Kernel
  isolation between same-user processes does not exist. Per-session grants
  are therefore **workflow scoping and blast-radius control against sloppy or
  prompt-injected agents**, plus audit — not a hard security boundary. The
  hard boundary remains: no touch → no new plaintext.
- **Touch-cache window**: the YubiKey PIV touch cache is firmware-fixed at
  15s. Within 15s of a legitimate touch, one additional pending decrypt could
  complete without a distinct touch. Mitigated by single-flight sequencing
  (below); the residual window is accepted for touch-only ergonomics. The
  future explicit-approve mode eliminates it.
- **Grant lifetime and silent harness death**: once granted, a secret stays
  available to its session until the session-end event, `secrets lock`, or the
  12h backstop — including while the user is away. This is deliberate:
  presence is proven at grant time, not continuously. A silently crashed
  harness cannot send its session-end event, and the broker has no death-watch
  fallback, so its grants survive until the 12h backstop.
- **Open registration**: the broker socket is same-UID-open, so any process
  can register a token and pose as "a session". A forged registration cannot
  mint a grant — the touch requirement stands — but it can supply misleading
  metadata. A same-UID "private plugin channel" would be security theater
  (any such credential is readable by the same UID); structured journald
  records retain kernel-derived peer attribution for after-the-fact review.
- **Tokenless path abuse**: an agent that strips its own env can reach the
  interactive `(tty, boot-id)` flow. It still cannot get a grant without a
  touch, and the request's scope is recorded in journald. Best-effort
  hardening: the plugin registers PTYs it allocates and the broker rejects
  tokenless requests from them; ttys the plugin cannot see (for example,
  agent-created tmux panes) remain an accepted same-UID residual.

## Non-goals

- Per-use approval (schema leaves room; explicitly not wanted now).
- Per-key TTL policies (additive later; grant records carry created-at).
- Claude Code support for human-tier grants (dropped to simplify the design
  to a single authorization mechanism; CC keeps agent-tier access unchanged
  and gets a clear error for human-tier keys). Re-adding CC later means
  re-introducing a process-ancestry anchor path — a known, bounded extension.
- Hard isolation between same-UID processes.

## Architecture

```
agent (OpenCode session)
  │
  ├── MCP tool: secrets_request(KEY)      ── opencode plugin → broker socket
  │     (triggers grant flow; never returns secret values)
  │
└── bash: secrets get KEY [--value|--no-request] / secrets KEY -- cmd
        │
        ▼
   shims/secrets (bash, unchanged interface)
        │  agent-tier keys: sops decrypt directly, as today. No broker.
        │  human-tier keys: request over unix socket, sending the
        ▼  session token (read from a file referenced in env)
   secretsd  — Rust daemon, systemd user service, socket-activated,
        │     one per machine ($XDG_RUNTIME_DIR/secretsd.sock, 0600)
        │     plaintext cached only in daemon memory (mlockall, zeroize);
        │     clients and `-- cmd` children necessarily receive the
        │     plaintext of keys granted to them
        ▼
   YubiKey (blink = physical prompt; touch = grant approval)
```

### Components

1. **`secrets`** (Rust, single binary): `secrets serve` holds grants and
   decrypted human-tier values in memory; runs the approval state machine;
   performs sops decrypts; and logs everything to journald.
   - Deps: std + `nix` (SO_PEERCRED for logging/UID check) + `zeroize`.
     No serde/dotenv crates on the plaintext path.
   - Hardening: `mlockall(MCL_CURRENT|MCL_FUTURE)` (fail closed if it
     fails), `PR_SET_DUMPABLE=0`, no core dumps, plaintext never in
     logs/errors, zeroized buffers, `Restart=on-failure`.
   - Input validation: key names must match `[A-Z][A-Z0-9_]*`; human-tier
     files opened via `openat` against the `secrets.human.d` directory with
     `O_NOFOLLOW`, regular files only.
   - `SECRETSD_HUMAN_DIR` is required daemon configuration and must be set to
     an explicit deployment-owned directory by the user service. The daemon
     refuses to start when it is absent.
   - Restart semantics: grants are memory-only and lost on restart. This is
     the correct security default. The shim reports "broker restarted;
     re-approval required" clearly.

2. **OpenCode plugin** (`opencode/plugins/secretsd.ts`): the identity
   authority, shipped and tested with the `secretsd` release.
   - Package installation places the exact tested plugin at
     `~/.local/share/secretsd/opencode/plugins/secretsd.ts`. Dotfiles loads it
     through the stable release-owned entry
     `file://{env:HOME}/.local/share/secretsd/opencode/plugins/secretsd.ts`,
     not a symlink into a dotfiles checkout.
   - On session create: generates a random 256-bit token, registers
    `(token, session_id, serve_pid)` with the broker, writes the token to
    `$XDG_RUNTIME_DIR/secretsd/<session>.token` (inside a `0700` directory,
    with mode `0600`), and injects only
    `SECRETSD_SESSION_TOKEN_FILE=<path>` into the session's bash environment.
    The token value never enters the environment, so `env` dumps, transcripts,
    and child-environment logs never contain the bearer credential itself.
   - Token lifecycle: the token is persisted in the plugin's session state
     and **re-registered on broker or serve restart** before requests are
     allowed. An unknown token is a hard identity error — it never falls
     back to the tokenless path.
   - Registers PTYs it allocates for sessions, letting the broker reject
     tokenless requests from known agent ttys (best effort; see residuals).
   - On session delete: notifies the broker → grants revoked,
     values zeroized when the last grant for a key dies. Event-driven; no
     `/proc` sweeps needed for the primary path.
   - Registers an MCP tool `secrets_request(key)` (OpenCode presents this to agents as `SecretsRequest`; instruct them by that name) → returns `granted`,
     `denied`, or `unavailable` guidance. Never returns secret values (they
     must not enter the transcript).

3. **`secrets` client mode** (every invocation other than `secrets serve`):
   preserves the CLI. The human-key set is derived from
   `secrets.human.d/*.env` filenames: those keys **always** route through the
   broker — a duplicate of a human key appearing in an agent-tier file is a
   fail-closed error, never a silent broker bypass. All other keys use local
   agent-tier sops decryption without contacting the daemon. Human-tier
   operations connect to the socket, send the session token when present, and
   block for the touch flow. No client-controlled daemon file-path overrides
   exist.
   `serve` is a reserved first argument, so a key literally named `serve` is not
   usable in the `secrets KEY -- cmd` shorthand. The match is exact, so
   conventional SCREAMING_SNAKE names (including `SERVE`) are unaffected.

### Storage: recipients are the policy

The "tier" concept reduces to: **a key's sops recipient set is its access
class.** No policy file exists, so there is nothing for an agent to tamper
with — enforcement is cryptographic.

- **Auto (agent tier)**: `secrets.env` (committed), `secrets.local.env`
  (devbox, gitignored) — unchanged files, unchanged recipients (agent keys +
  YubiKey + recovery), unchanged zero-interaction consumers (voxtype, legion,
  skill MCPs, `dojo/.env` infrastructure).
- **Grant-required (human tier)**: `secrets.human.d/<KEY>.env` — one sops
  dotenv file per key, recipients: YubiKey + recovery **only**. Per-key files
  mean a grant decrypts only that key; broker memory never holds ungranted
  values. Key names remain listable without decryption (sops encrypts
  values, not names) — this also structurally fixes the known stray-blink
  bug in `secrets list`.
- Moving a key between classes = a deliberate re-encryption ceremony
  performed by the human (requires decrypting, which requires touch).
- An agent can corrupt or swap ciphertext files (same-UID write access) but
  cannot weaken access: after decrypt, the broker requires the file to
  contain **exactly one assignment whose name equals the requested key**,
  and rejects symlinks. Corruption is DoS only, visible in jj diffs.
- `.sops.yaml` **must gain a creation rule for `secrets\.human\.d/[^/]+\.env$`
  (YubiKey + recovery only) ordered before the default rule** — today the
  default rule carries agent recipients, so without this rule a new per-key
  file would silently be agent-decryptable, bypassing the broker entirely.
  The ceremony includes verifying that the agent key **fails** to decrypt
  every `secrets.human.d/*.env`.
- Key *names* are visible in the public repo (filenames). This is not new —
  sops never encrypted dotenv names in `secrets.human.env` either. Accepted.

## Authorization model

A grant is `(session_token, key)`, held in broker memory.

- Requests carry the session token, read by the shim from the file named in
  `SECRETSD_SESSION_TOKEN_FILE`. Authorization is a constant-time token
  comparison. No trust in claimed session IDs, process names, or ancestry.
- The token-file path is inherited by everything the session spawns (env),
  so session-owned background jobs (`setsid` etc.) keep working — scope
  follows the token, not the process tree.
- A sibling session in the same `opencode serve` process has a different
  token and cannot match another session's grant. Stealing a token requires
  actively reading another session's 0600 token file or memory — the
  accepted same-UID residual, a materially higher bar than claiming an ID
  string, and one that leaves no accidental trail in `env` dumps or
  transcripts.
- **Tokenless requests** (the human at an interactive shell): keyed on
  `(tty, boot-id)` as the grant scope; same touch flow; revoked when the tty
  vanishes. They are rejected outright from PTYs registered as agent-session
  ttys, and their scope is retained in the journald audit event.
- Requests from other-UID peers: rejected (socket is 0600; SO_PEERCRED
  double-checks).

### Grant lifecycle

```
request → pending → decrypting → granted ──(session end | lock | 12h)→ revoked+zeroized
                        │
                        ├─ denied  (secrets deny / timeout 90s)
                        └─ failed  (YubiKey unreachable, decrypt error)
```

- State transitions are atomic with generation IDs. Deny/timeout kills the
  decrypt child process group and discards late output. Concurrent waiters
  are coalesced **only** for the same `(token, key)`; one session's approval
  never creates another session's grant.
- Revocation triggers: plugin session-end event (primary), `secrets lock`
  (wipe all + revoke all), and a 12h backstop per grant.
- Grants are never persisted. Reopening the same on-disk session re-registers
  the persisted token but starts with zero grants — the first human-tier
  request goes through a fresh blink-and-touch. One touch to resume is
  deliberate: a new process is a new presence proof.
- Plaintext lifetime = union of active grants for that key; zeroized when
  the last grant dies.

## Approval UX

1. Agent or interactive shell requests a human-tier key.
2. The broker creates the pending request and starts the decrypt. The YubiKey
   blink is the unspoofable physical prompt; no software channel or client
   acknowledgement gates this step. The operator initiates the request, and
   the structured journald event is the sole after-the-fact attribution when
   asking why the key blinked.
3. **One touch completes the grant**. `secrets deny <id>` or the 90s timeout
   rejects it.
4. **Single-flight**: at most one YubiKey operation is in flight; the broker
   waits out the 15s hardware touch cache before starting the next pending
   decrypt, so one touch can never approve two requests.
   Per-scope pending-request limits with backoff after deny/timeout prevent
   one hostile or broken session from flooding the single-flight queue and
   locking out legitimate grants; `secrets deny` and `secrets lock` are
   always serviced immediately, ahead of the queue.
5. Devbox: approval requires the YubiKey tunnel. If unreachable, fail fast
   with "YubiKey unreachable — connect the pcscd bridge", not a hang.
6. Repeat access within a granted session: instant, silent, no hardware
   interaction.

Future (config-flip, no architecture change): explicit `secrets approve
<id>` mode — approval runs in the human's TTY, which is what pinentry
needs, so PIN+touch (`pin-policy` change) becomes possible per-key.

## CLI / tool surface

```
secrets get KEY                        pre-authorizes: asks the broker for a grant
                                       (touch if none is live) and prints status only
secrets get KEY --value                prints the secret; the only form that does
secrets get KEY --no-request           status without asking, so it never triggers a touch
secrets KEY -- cmd                     injects into a child environment, never prints
secrets list                            names only; never decrypts
secrets grants                          active grants + pending requests
secrets deny [id]                       reject a pending request
secrets lock                            wipe all plaintext, revoke all grants
secrets approve [id]                    reserved for explicit-approve mode
MCP: secrets_request(key)               grant flow trigger; no values returned
```

## Migration

1. Add the `secrets.human.d/` creation rule to `.sops.yaml` (YubiKey +
   recovery only, ordered before the default rule) and a
   recipient-verification check (agent key must fail to decrypt any file
   under `secrets.human.d/`). **This precedes any file creation.**
2. Build + install `secrets` and the plugin on both machines (installer +
   systemd user units; binary fits the `bin/` convention; `cargo-deny` in CI
   posture per mise setup).
3. One-time ceremony **on the laptop**: split `secrets.human.env` into
   `secrets.human.d/<KEY>.env` (YubiKey decrypts; re-encrypt to YubiKey +
   recovery only; recovery key stays in 1Password and never transits the
   devbox). Run the recipient-verification check. Confirm no human key
   also exists in an agent-tier file. `dojo/.env` is agent-tier and
   untouched — no key ceremony.
4. Install the Rust `secrets` client and route human-key requests by filename
   through the broker; agent-tier reads remain local and daemon-independent.
5. Verify (section below), then remove `secrets.human.env`.
6. sops files never merge textually (existing rule; per-key files also
   shrink conflict surface).

## Verification

- Agent tier unattended (must not regress):
`ssh devbox '~/.dotfiles/shims/secrets get ANTHROPIC_API_KEY'` — reports status
  interaction, no broker involvement.
- Grant flow: from an OpenCode session, `secrets get DEEL_API_KEY --value` → YubiKey
  blink and touch prompt.
- Cross-session isolation: session B requesting a key granted to session A
  gets its own pending request, never A's value.
- Revocation: end the session → `secrets grants` empty → next request
  requires touch again. `secrets lock` same.
- `secrets list` produces zero YubiKey interaction (strace-verifiable).
- Recipient check: agent age key fails to decrypt every
  `secrets.human.d/*.env`.
- Duplicate-key bypass: a human key planted in `secrets.env` → shim fails
  closed, never serves the agent-tier copy.
- Token-strip: unset `SECRETSD_SESSION_TOKEN_FILE` inside an agent session
  → request uses the tokenless scope (or is rejected if the PTY is registered),
  never inherits the session's grant.
- Broker restart mid-session → clear re-approval message, no hang.
- Recovery path unchanged: `SOPS_AGE_KEY=$(op ...) sops -d
  secrets.human.d/<KEY>.env` on the laptop only.

## Future extensions (explicitly deferred)

- Per-use approval mode and per-key TTLs (grant records already carry
  created-at; additive).
- Explicit-approve + PIN mode (see Approval UX).
- Claude Code human-tier support via process-ancestry anchoring.
- Migrating agent-tier storage to per-key files / per-key recipient sets
  (e.g., laptop-only keys) — the "recipients are the policy" model already
  covers it; pure churn today.
