# tests

Integration tests. Unit tests live beside their module as `src/<mod>/tests.rs`.

## Wiring

There is no `tests/lib.rs`. Each root test file pulls in its helpers explicitly:

```rust
#[path = "broker/grants.rs"] mod grants;   // a module
include!("broker/support.rs");             // inlined harness
```

`#[path]` for real modules, `include!` for shared harness code that needs the
parent's imports. A new helper follows whichever the sibling files use — adding
a `mod.rs` would change how every existing file resolves.

| File | Covers |
|---|---|
| `broker.rs` | socket activation, dispatch, audit output, protocol errors |
| `client.rs` | CLI surface end to end against a fake broker |
| `client/broker_transport.rs` | frame-level transport, scope frames, no-`GET` guarantees |
| `hardening.rs` | `mlockall` / dumpability / `RLIMIT_CORE`, spawning the real binary |
| `e2e_client.rs` | drives `e2e-client-harness.sh` with real sops; exit 0 or 77 |

## No real hardware

Nothing here may need a YubiKey. Point the daemon at a fixture instead:

- `SECRETSD_SOPS_BIN=tests/fixtures/fake-sops-ok` — succeeds, emits dotenv
- `…/fake-sops-fail` — non-zero, writes to stderr
- `…/fake-sops-hang` — sleeps, for timeout and process-group kill

Also set `SECRETSD_HUMAN_DIR` (required) and `SECRETSD_SOCKET` (scratch path).
All are read from the **daemon's own** environment; a client cannot supply them.

## Ancestry affects test shape

The daemon grants only to callers descended from the process that registered the
session. A test that registers from a short-lived helper and then requests from
a sibling gets `FOREIGN_CALLER` — correctly. `e2e-client-harness.sh` therefore
`exec`s its continuation from the registering process, mirroring how the plugin
registers from the long-lived OpenCode server.

## Miri

CI runs miri over `secret|grants|requests|proto|client` unit tests only. Any test
that touches a socket, `/proc`, or the filesystem must carry
`#[cfg_attr(miri, ignore)]` — miri cannot emulate `getsockopt`, and an unmarked
test breaks the miri job, not the test job.
