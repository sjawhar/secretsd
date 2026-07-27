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
   │  line protocol over $XDG_RUNTIME_DIR/secretsd.sock (0600)
   ▼
secretsd ── grants: (scope, key) → SecretBytes, memory only
   │        scope = token-verified session | (tty, boot-id)
   └──► sops + age + YubiKey       (blink = physical prompt; touch = authorization)
```

One binary. `secrets serve` is the daemon; every other argv is the client
(`src/bin/secrets.rs`). Both halves live in this crate, so a protocol change
touches both sides in one commit.

Agent-tier keys never reach the daemon at all: the client decrypts
`secrets.env` locally. Only the filenames in `secrets.human.d/` are brokered.

| Module | Owns |
|---|---|
| `src/proto.rs` | Wire protocol parse/format. Hand-rolled; no serde. |
| `src/hardening.rs` | `mlockall`, `PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`. Fail-closed. |
| `src/secret.rs` | `SecretBytes` (zeroize on drop), key-name validation, single-assignment dotenv parse. |
| `src/decrypt.rs` | Spawning sops, timeout, killing the process group on cancel. |
| `src/grants.rs` | Scopes, session registrations, grant table, revocation. |
| `src/requests.rs` | Request state machine, single-flight YubiKey queue, cooldown, pending limits. |
| `src/server.rs` | Socket activation, three connection lanes, per-connection `handle`, audit line. |
| `src/server/dispatch.rs` | Op routing, `resolve_access`, `await_approval`. |
| `src/server/worker.rs` | The single approval worker: dequeue → decrypt → insert grant. |
| `src/peer.rs` | `SO_PEERPIDFD` peer pinning and `/proc` ancestry walk. |
| `src/store.rs` | Human-tier ciphertext files; opens by inode, not path. |
| `src/client/` | The client half of the binary. See `src/client/AGENTS.md`. |

## Where to look

| Task | Go to |
|---|---|
| Change how a request is authorized | `Registry::resolve`, `src/grants.rs:165` |
| Change ancestry / peer identity | `src/peer.rs:46` (`from_stream`), `:97` (`descends_from`) |
| Add or change a protocol op | `src/proto.rs:93` (requests), `src/proto/response.rs` |
| Change what the audit line records | `src/server.rs:336`, context built at `:200` |
| Change how sops is invoked | `src/decrypt.rs:202`; failure classes at `:28` |
| Change the approval lifecycle | `src/server/worker.rs:26` |
| Change the CLI surface | `src/client/cli.rs:17` |
| Change grant lifetime or revocation | `GrantTable`, `src/grants.rs:218` |

## Non-negotiables

These are security properties, not style preferences. A change that breaks one
of them is a bug even if tests pass:

1. **No plaintext at rest.** Secret values live only in `SecretBytes` in this
   process. Never write them to disk, logs, or error messages.
2. **No serde on the plaintext path.** See the note in `Cargo.toml`.
3. **The physical touch authorizes.** A human-tier decrypt proceeds directly
   to the YubiKey: its blink is the unspoofable physical prompt and a touch is
   the authorization. Never add a software notification or acknowledgement
   gate. The human initiates requests; journald is the sole after-the-fact
   attribution record for a question such as "why did my key blink?".
4. **Single-flight YubiKey.** At most one decrypt in flight, plus a cooldown
   longer than the PIV touch cache, so one touch can never approve two
   requests.
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
cargo +nightly miri nextest run --all-features -E 'test(/^(secret|grants|requests|proto|client)::tests::/)'
cargo machete && cargo deny check all
bun install --frozen-lockfile && bun run test:secretsd-plugin
```

Miri covers the pure `secret`, `grants`, `requests`, `proto`, and `client`
modules. It cannot cover the `unsafe` fd-3 adoption in `server.rs`: that code
requires a real socket. Guard it through review, the `LISTEN_PID`/`LISTEN_FDS`
validation, and the integration tests in `tests/broker.rs`.

Releases are automatic: every push to `main` derives the next semver from the
conventional-commit subjects since the last tag, then tags, builds, attests, and
publishes. `feat:` bumps the minor, `fix:` the patch, `feat!:`/`BREAKING CHANGE`
the major, anything else does not release. Never tag by hand. The version lands
in `Cargo.toml` and `package.json` in the same commit so plugin and daemon match.

Tests must not require a real YubiKey. Inject a fake decryptor with
`SECRETSD_SOPS_BIN`, set the required `SECRETSD_HUMAN_DIR`, and use a scratch
socket with `SECRETSD_SOCKET`. All are read from the **daemon's own
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
`${XDG_RUNTIME_DIR}/secretsd/<sessionID>.token`, ensures the directory is
`0700` and the file is `0600`, and exports only
`SECRETSD_SESSION_TOKEN_FILE=<path>` to that session. The token value must
never enter the environment. Per-session tokens provide workflow scoping and
audit, not hard isolation between processes that share a Unix UID.

The wire protocol is the contract between client and daemon: it carries a
version in the handshake, and a mismatch must fail loudly rather than degrade.
Changing the shape of a request or a reply — including adding a field — bumps
`PROTOCOL_VERSION`. A strict peer rejects the new shape, so the version is what
turns that into a clear "update both" instead of a puzzling parse failure. That
the two halves ship in one release is not a reason to skip the bump: the plugin
is loaded when `opencode serve` starts, so it lags a daemon that has already
restarted, and mixed peers therefore occur during a normal upgrade.
