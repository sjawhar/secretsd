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

| Module | Owns |
|---|---|
| `src/proto.rs` | Wire protocol parse/format. Hand-rolled; no serde. |
| `src/hardening.rs` | `mlockall`, `PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`. Fail-closed. |
| `src/secret.rs` | `SecretBytes` (zeroize on drop), key-name validation, single-assignment dotenv parse. |
| `src/decrypt.rs` | Spawning sops, timeout, killing the process group on cancel. |
| `src/grants.rs` | Scopes, session registrations, grant table, revocation. |
| `src/requests.rs` | Request state machine, single-flight YubiKey queue, cooldown, pending limits. |
| `src/server.rs` | Socket activation, poll loop, op dispatch. |

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
6. **Grants are never persisted.** Process restart loses grants by design.

## Development

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo nextest run
cargo +nightly miri nextest run --all-features -E 'test(/^(secret|grants|requests|proto|client)::tests::/)'
```

Miri covers the pure `secret`, `grants`, `requests`, `proto`, and `client`
modules. It cannot cover the `unsafe` fd-3 adoption in `server.rs`: that code
requires a real socket. Guard it through review, the `LISTEN_PID`/`LISTEN_FDS`
validation, and the integration tests in `tests/broker.rs`.

Tests must not require a real YubiKey. Inject a fake decryptor with
`SECRETSD_SOPS_BIN`, set the required `SECRETSD_HUMAN_DIR`, and use a scratch
socket with `SECRETSD_SOCKET`. All are read from the **daemon's own
from a client request, since clients are untrusted.

## Consumers

The Rust client and OpenCode plugin that speak this protocol are owned and
tested in this repository. Package installation places the exact tested plugin
at `~/.local/share/secretsd/opencode/plugins/secretsd.ts`; consuming dotfiles
must load
`file://{env:HOME}/.local/share/secretsd/opencode/plugins/secretsd.ts`.
An absolute release-owned path keeps the plugin version coupled to its daemon
release and cannot point at unrelated working-tree code after a partial
dotfiles checkout.

The plugin issues a random token per OpenCode session at
`${XDG_RUNTIME_DIR}/secretsd/<sessionID>.token`, ensures the directory is
`0700` and the file is `0600`, and exports only
`SECRETSD_SESSION_TOKEN_FILE=<path>` to that session. The token value must
never enter the environment. Per-session tokens provide workflow scoping and
audit, not hard isolation between processes that share a Unix UID.

The wire protocol is the contract between client and daemon: it carries a
version in the handshake, and a mismatch must fail loudly rather than degrade.
