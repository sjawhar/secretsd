# secretsd

A session-scoped secrets broker. Holds hardware-gated secrets in memory and
scopes them to the workflow of an agent session a human explicitly approved,
for that session's lifetime.

## What problem this solves

AI coding agents need API keys. Most keys should be available unattended
(that's the "agent tier", handled entirely by sops + a disk-resident age key —
`secretsd` is not involved). A small set of sensitive keys should require a
human to be present *when access is first granted*. `secretsd` is the piece
that makes "present at grant time" workable without interrupting a 90-minute
work session: one YubiKey touch grants one key to one session, and it stays
granted until that session ends.

Design rationale, threat model, and accepted residual risks:
[`docs/design.md`](docs/design.md). **Read it before changing behavior** — most
of the non-obvious choices are load-bearing responses to a specific threat
model, and several "obvious improvements" were already tried and rejected.

## Architecture

```
client (secrets shim / opencode plugin)
   │  line protocol over <runtime>/secretsd.sock (0600)
   ▼
secretsd ── grants: (scope, key) → SecretBytes, memory only
   │        scope = token-verified session | (tty, boot-id)
   └──► sops + age + YubiKey       (blink = physical prompt; touch = authorization)
```

`<runtime>` is `$XDG_RUNTIME_DIR`, or `/run/user/<uid>` when that is unset or
empty. Both halves of the release resolve it by the same rule — `SocketPath::resolve`
(`src/client.rs:35`) and `resolveRuntimeDir` (`opencode/plugins/secretsd.ts`) —
because a client that resolves a different directory than the plugin that minted
its token is refused, not degraded.

Both halves resolve the socket path by the same rule (`SocketPath::resolve`,
`src/client.rs:35`) but honour **different override variables**: the client and
plugin connect through `SECRETSD_SOCK` (`BrokerClient::from_environment`,
`src/client.rs:91`; `resolveSocketPath`, `opencode/plugins/secretsd.ts`), while a
standalone `secrets serve` listens on `SECRETSD_SOCKET` (`Config::from_env`,
`src/lib.rs:105`). The split is deliberate — a test harness redirects the daemon's
listener without silently redirecting every client on the machine — so
redirecting one half never leaves the token registered with a daemon the other
half is not talking to. Under socket activation systemd owns the listener and
neither variable applies.

One binary. `secrets serve` is the daemon; every other argv is the client
(`src/bin/secrets.rs`). Both halves live in this crate, so a protocol change
touches both sides in one commit.

Agent-tier keys never reach the daemon at all: the client decrypts each
configured root's `secrets.local.env` or `secrets.env` locally. Only the
filenames in configured `secrets.human.d/` directories are brokered.

| Module | Owns |
|---|---|
| `src/proto.rs` | Wire protocol parse/format. Hand-rolled; no serde. |
| `src/config.rs` | Source-root configuration, config-path resolution, and root validation. |
| `src/hardening.rs` | `mlockall`, `PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`. Fail-closed. |
| `src/secret.rs` | `SecretBytes` (zeroize on drop), key-name validation, single-assignment dotenv parse. |
| `src/decrypt.rs` | Spawning sops, timeout, killing the process group on cancel. |
| `src/grants.rs` | Scopes, session registrations, grant table, revocation. |
| `src/requests.rs` | Request state machine, single-flight YubiKey queue, cooldown, pending limits. |
| `src/audit.rs` | Sanitizes values shared by audit-log surfaces. |
| `src/server.rs` | Socket activation, three connection lanes, per-connection `handle`, audit line. |
| `src/server/dispatch.rs` | Protocol-op routing and request/response decisions. |
| `src/server/approval.rs` | Access resolution and the approval wait lifecycle. |
| `src/server/worker.rs` | The single approval worker: dequeue → decrypt → insert grant. |
| `src/peer.rs` | `SO_PEERPIDFD` peer pinning and `/proc` ancestry walk. |
| `src/store.rs` | Human-tier ciphertext discovery, descriptor opens, and `FileIdentity` snapshots used to invalidate stale grants. |
| `src/client/` | The client half of the binary. See `src/client/AGENTS.md`. |

## Where to look

| Task | Go to |
|---|---|
| Change how a request is authorized | `Registry::resolve`, `src/grants.rs:188`; `src/server/approval.rs:29` |
| Change ancestry / peer identity | `src/peer.rs:46` (`from_stream`), `:97` (`descends_from`) |
| Add or change a protocol op | `src/proto.rs:97` (requests), `src/proto/response.rs` |
| Change source-root configuration | `Sources::config_path`, `src/config.rs:54`; `Sources::load`, `src/config.rs:70` |
| Change what the audit line records | `src/server.rs:294`, context built at `:167`; sanitization in `src/audit.rs:19` |
| Change how sops is invoked | `src/decrypt.rs:251`; failure classes at `:27` |
| Change how the runtime directory is resolved | `resolveRuntimeDir`, `opencode/plugins/secretsd.ts`; `SocketPath::resolve` and `runtime_dir`, `src/client.rs:35` |
| Change which socket either half connects to | `resolveSocketPath`, `opencode/plugins/secretsd.ts`; `BrokerClient::from_environment`, `src/client.rs:91` |
| Change the session token file's lifetime | `restoreTokenFile`, `opencode/plugins/secretsd.ts`; `ensureState` beside it |
| Change the approval lifecycle | `src/server/approval.rs:49`; `src/server/worker.rs:27` |
| Change the CLI surface | `src/client/cli.rs:17` |
| Change human-secret creation | `src/client/edit/new.rs`: `human`, `write_piped_human`, `read_piped_assignment`, `encrypt`, and `encrypt_bytes` |
| Change stale-grant invalidation | `resolve_access`, `src/server/approval.rs:30`; `HumanStore::identity`, `src/store.rs:145` |
| Change grant lifetime or revocation | `GrantTable::revoke`, `src/grants.rs:293` |

## Non-negotiables

These are security properties, not style preferences. A change that breaks one
of them is a bug even if tests pass:

1. **No plaintext at rest.** Secret values live only in `SecretBytes` in this
   process. Never write them to disk, logs, or error messages. The one
   deliberate exception is creating a *new* secret (`src/client/edit/new.rs`):
   the operator's editor needs a plaintext file, so one is written `0600` in
   the runtime directory, scrubbed and unlinked on every exit path, and never
   at the target. That buys a creation flow needing no `YubiKey` touch, since
   encryption is public-key only. Nothing else may write plaintext to disk.
2. **No serde on the plaintext path.** See the note in `Cargo.toml`.
3. **The physical touch authorizes.** A human-tier decrypt proceeds directly
   to the YubiKey: its blink is the unspoofable physical prompt and a touch is
   the authorization. Never add a software notification or acknowledgement
   gate. The human initiates requests; journald is the sole after-the-fact
   attribution record for a question such as "why did my key blink?".
4. **Single-flight YubiKey.** At most one decrypt in flight, plus a cooldown
   longer than the hardware's touch cache, so one touch can never approve two
   requests. `SECRETSD_TOUCH_POLICY=always` declares hardware with no cache
   (touch-policy Always keys), which is the only thing that makes a sub-15s
   cooldown safe; the default assumes the cached policy and keeps the floor.
5. **Fail closed.** Unknown token, unparseable request, missing scope, failed
   `mlockall`, ambiguous file: refuse. Never fall back to a weaker path.
6. **Grants are never persisted.** Process restart loses grants by design, and
   it loses session registrations with them. Nothing notifies a harness of that,
   and the `secrets` CLI cannot register itself, so the handshake reports a
   per-process `instance` id: a harness that sees it change must re-register
   before its requests are allowed. Re-registering a session with the token it
   already holds is idempotent and must never revoke that session's grants.
7. **Token *and* ancestry.** A session token says *which* session; it does not
   prove the caller belongs to it, because any process sharing the uid can read
   the token file. A request carrying a token is refused with `FOREIGN_CALLER`
   unless the caller descends from the pid that registered that session, taken
   from the kernel via `SO_PEERPIDFD` at `REGISTER` — never from the wire. A
   failed ancestry check must never degrade to a tty scope; a caller can
   allocate a pty. This contains callers outside the session tree; anything the
   agent itself runs is inside it, and that residual is accepted.

## Development

```bash
cargo +nightly fmt --all -- --check   # nightly: imports_granularity, group_imports
cargo clippy --all-targets --all-features -- -D warnings
cargo nextest run --all-targets --all-features --workspace
cargo +nightly miri nextest run --all-features -E 'test(/^(secret|grants|requests|proto|client|config)::tests::/)'
cargo machete && cargo deny check all
bun install --frozen-lockfile && bun run test:secretsd-plugin
(cd omp && bun install --frozen-lockfile && bun run test:secretsd-omp-extension)
```

Miri covers the pure `secret`, `grants`, `requests`, `proto`, `client`, and `config`
modules. It cannot cover the `unsafe` fd-3 adoption in `server.rs`: that code
requires a real socket. Guard it through review, the `LISTEN_PID`/`LISTEN_FDS`
validation, and the integration tests in `tests/broker.rs`.

Releases are automatic: every push to `main` derives the next semver from the
conventional-commit subjects since the last tag, then tags, builds, attests, and
publishes. `feat:` bumps the minor, `fix:` the patch, `feat!:`/`BREAKING CHANGE`
the major, anything else does not release. Never tag by hand. The version lands
in `Cargo.toml` and `package.json` in the same commit so plugin and daemon match.

Tests must not require a real YubiKey. Inject a fake decryptor with
`SECRETSD_SOPS_BIN`, set `SECRETSD_CONFIG` to a scratch source-root
configuration, and use a scratch socket with `SECRETSD_SOCKET`. All are read from the **daemon's own
environment**, never from a client request, since clients are untrusted.

## Consumers

The Rust client and OpenCode plugin that speak this protocol are owned and
tested in this repository, and both ship in the release archive. Consumers load
the plugin from a tag matching the installed binary:

```
secretsd@git+https://github.com/sjawhar/secretsd.git#v<VERSION>
```

The tag must match the installed daemon, because the wire protocol is versioned
and the two are released together. Pinning a moving ref such as `#main` is wrong
twice over: it decouples plugin from daemon, and the package manager caches the
ref so updates never arrive. The dotfiles installer derives the tag from the
installed release rather than hard-coding one.

The plugin issues a random token per OpenCode session at
`<runtime>/secretsd/<sessionID>.token`, ensures the directory is `0700` and the
file is `0600`, and exports only `SECRETSD_SESSION_TOKEN_FILE=<path>` to that
session. The token value must never enter the environment. Per-session tokens
provide workflow scoping and audit, not hard isolation between processes that
share a Unix UID. The plugin verifies `<runtime>` rather than trusting it: it
must exist, be a directory this uid owns, and be closed to other writers, and
the token directory must be a real directory rather than a symlink. It never
creates `<runtime>` itself — a missing `/run/user/<uid>` means there is no
systemd user session, so writing tokens there would report a success the daemon
cannot see.

The omp extension (`omp/extensions/secretsd.ts`) anchors ONE token per omp OS
process, not per session: the first session to start (the root) registers it,
and every in-process subagent session this extension loads into adopts that
same anchor instead of minting its own — so grants deliberately span the whole
session tree, per `docs/design.md`'s "the token-file path is inherited by
everything the session spawns." The owning (root) session's shutdown
unregisters and removes the token file for the whole tree.

The wire protocol is the contract between client and daemon: it carries a
version in the handshake, and a mismatch must fail loudly rather than degrade.
Changing the shape of a request or a reply — including adding a field — bumps
`PROTOCOL_VERSION`. A strict peer rejects the new shape, so the version is what
turns that into a clear "update both" instead of a puzzling parse failure. That
the two halves ship in one release is not a reason to skip the bump: the plugin
is loaded when `opencode serve` starts, so it lags a daemon that has already
restarted, and mixed peers therefore occur during a normal upgrade.
