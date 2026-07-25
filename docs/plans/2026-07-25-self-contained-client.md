# Self-contained `secrets` Client and Deployment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `secretsd` own the Rust `secrets` CLI, its shared wire protocol, its OpenCode plugin, and portable systemd units without regressing unattended agent-tier access.

**Architecture:** Turn the package into a library with `proto` and `client` modules and one `secrets` binary. `secrets serve` runs the daemon; every other invocation is the drop-in client CLI. The client uses typed protocol frames and exact byte reads for human-tier requests while keeping agent-tier sops decryption local and daemon-independent. Human-tier requests proceed to the hardware prompt; the physical YubiKey touch is the authorization gesture, and the structured journald request event supplies after-the-fact attribution.

**Tech Stack:** Rust 1.92 / edition 2024, `nix`, `zeroize`, `subtle`, `tracing`, systemd user units, Bun/OpenCode plugin tests, sops dotenv subprocesses.

## Global Constraints

- Use **jj, never git**.  There is one commit per deliverable, never per task.  If recovery is required, every `jj restore` command must name only the intended path; an unscoped restore destroyed secrets today.
- The current 104 Rust tests must remain passing; retain all security coverage whose guarded property survives, and delete or rewrite an assertion only when this plan explicitly records why that property no longer applies.
- Run `cargo +nightly fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, and `cargo nextest run --workspace --all-targets --all-features` for the final Rust gate.  Run Miri only for pure `secret`, `grants`, `requests`, `proto`, and new pure `client` tests.
- Enforce clippy `pedantic`, `nursery`, and `cargo` with `-D warnings`.  Do not use `unwrap`, `expect`, `panic`, or indexing outside `#[cfg(test)]`.
- Secret plaintext and session-token bytes must never occur in logs, `Debug`, errors, test snapshots, or diagnostic output.  Redact test frames before asserting them.
- Do not use serde or dotenv parsers on plaintext paths.  Continue hand-parsing protocol and dotenv bytes and zeroize temporary plaintext buffers.
- Agent-tier reads from `secrets.env` and optional `secrets.local.env` must shell out directly to `sops`; they must not resolve or contact a daemon socket and must work with neither `XDG_RUNTIME_DIR` nor a token-file variable set.
- All sops invocations, including agent-tier invocations, must pass `-d --input-type dotenv --output-type dotenv`.  The fake-sops fixtures must reject either missing flag so an incorrect command cannot pass tests.
- Discover human-tier keys only from `secrets.human.d/*.env` filenames.  `secrets list` must never decrypt or contact the daemon, and a name in both tiers must fail closed for both `get` and `list`.
- Read only the path in `SECRETSD_SESSION_TOKEN_FILE`; do not treat the environment value as a token.  Preserve the token-file contract: `${XDG_RUNTIME_DIR}/secretsd/<sessionID>.token`, directory mode `0700`, file mode `0600`, and export only the path.
- Resolve the human-tier socket only when a human-tier operation requires it: `SECRETSD_SOCK`, then `${XDG_RUNTIME_DIR}/secretsd.sock`, then `/run/user/<uid>/secretsd.sock`.  Missing environment variables must never abort client startup.
- Framed `OK\tlen=<n>\n` responses are exact byte frames: reject malformed headers, early EOF, surplus bytes, and payloads containing NUL before values reach stdout or a child environment.
- Preserve the structured journald request log as the sole attribution mechanism.  No packaged unit may hardcode a companion-repository path or a personal command into this repository.
- `LimitMEMLOCK=infinity`, `LimitCORE=0`, `RemoveOnStop=yes`, `Accept=no`, and `SocketMode=0600` are load-bearing deployment invariants and must remain documented and tested where applicable.

## File Structure

| File | Responsibility |
|---|---|
| `src/lib.rs` | Shared crate root; exports daemon modules plus reusable `proto` and `client` modules. |
| `src/proto.rs` | One canonical protocol version and typed request/response headers. |
| `src/client.rs` | Unix-socket transport, HELLO negotiation, exact framed-byte read, typed error mapping, lazy socket resolution, and TTY/token-path helpers. |
| `src/bin/secrets.rs` | Dispatches `serve` to the library daemon entry point and otherwise runs the drop-in CLI: direct agent sops path, filename-only human discovery, duplicate detection, broker operations, edit commands, and env injection. |
| `src/main.rs` | Delete after Cargo is switched to the two explicit binaries. |
| `src/requests.rs` | Pending request lifecycle, timeout, denial, and single-flight state for hardware-backed decrypts. |
| `src/server/dispatch.rs` and `src/server/worker.rs` | Dispatch requests, retain structured request attribution, and start a decrypt without a software announcement gate. |
| `src/hardening.rs` and `tests/hardening.rs` | Preflight `RLIMIT_MEMLOCK`, fail before threads/allocations, and report the required systemd limit. |
| `tests/client.rs` and `tests/e2e_client.rs` | Client protocol/CLI tests plus a scratch-daemon REGISTER/GET harness using fake sops and no hardware. |
| `tests/fixtures/fake-sops-ok` | Strict dotenv-only fake sops used by both daemon and client tests. |
| `opencode/plugins/secretsd.ts` and `opencode/plugins/secretsd.test.ts` | Relocated plugin and its existing test logic, owned and tested with the daemon release. |
| `opencode/package.json` | Pinned plugin test dependency and Bun test command. |
| `.github/workflows/ci.yml` | Existing Rust gates plus Bun installation and the relocated plugin test. |
| `systemd/secretsd.service` and `systemd/secretsd.socket` | Generic packaged units with no personal paths or ancillary-service configuration. |
| `docs/design.md` and `AGENTS.md` | Current architecture and operator requirements, rewritten to describe the self-contained client, physical-touch authorization, and journald attribution. |
| `docs/dotfiles-cutover.md` | Companion-repository-only installation contract and safe cross-machine cutover order. |

---

### Task 1: Establish the shared binary layout and typed protocol client

**Parallel-safe:** No — every later CLI and daemon task imports these interfaces.

**Files:**
- Modify: `Cargo.toml`, `src/lib.rs`, `src/proto.rs`
- Create: `src/client.rs`, `src/bin/secrets.rs`, `tests/client.rs`
- Delete: `src/main.rs`

**Interfaces:**
- Produces `client::BrokerClient`, `BrokerResponse`, `ClientError`, `SocketPath`, `read_token_file`, and `caller_tty`.
- Does not add an acknowledgement request or announcement response; human requests use the ordinary typed request and response frames.
- `BrokerClient::call(&self, request: &str) -> Result<BrokerResponse, ClientError>` performs HELLO first, then parses the response without stringly protocol copies in either binary.

- [ ] **Step 1: Write failing typed-frame tests**

Create `tests/client.rs` with this complete test module (the `FakeBroker` accepts two connections, asserts HELLO, and emits the supplied byte response on the second):

```rust
use std::io::Write;
use std::os::unix::net::UnixListener;
use std::thread;

use secretsd::client::{BrokerClient, ClientError, SocketPath, parse_response};

#[test]
fn exact_payload_accepts_declared_non_nul_bytes() {
    assert_eq!(parse_response(b"OK\tlen=3\nabc"), Ok(secretsd::client::BrokerResponse::Bytes(b"abc".to_vec())));
}

#[test]
fn framed_payload_rejects_short_long_and_nul_bytes() {
    for bytes in [b"OK\tlen=4\nabc".as_slice(), b"OK\tlen=3\nabcx", b"OK\tlen=3\na\0b"] {
        assert!(matches!(parse_response(bytes), Err(ClientError::InvalidResponse)));
    }
}

#[test]
fn socket_path_is_lazy_and_has_the_documented_fallback() {
    assert_eq!(SocketPath::resolve(Some("/tmp/override"), Some("/tmp/runtime"), 42).as_path(), "/tmp/override");
    assert_eq!(SocketPath::resolve(None, Some("/tmp/runtime"), 42).as_path(), "/tmp/runtime/secretsd.sock");
    assert_eq!(SocketPath::resolve(None, None, 42).as_path(), "/run/user/42/secretsd.sock");
}

#[test]
fn client_rejects_wrong_hello_field_name() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("broker.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let worker = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.write_all(b"OK\tv=1\n").unwrap();
    });
    let result = BrokerClient::new(path).hello();
    worker.join().unwrap();
    assert!(matches!(result, Err(ClientError::VersionHandshake)));
}
```

- [ ] **Step 2: Prove the tests fail**

Run: `cargo nextest run --test client`

Expected: FAIL because `secretsd::client` does not exist.

- [ ] **Step 3: Add the exact shared module boundary**

Replace the module list at the top of `src/lib.rs`, add `serve_main()` there, and add the `secrets` binary entry point. Keep all existing daemon exports unchanged.

```rust
/// Shared Unix-socket protocol client used by the `secrets` CLI.
pub mod client;
pub mod proto;

// src/bin/secrets.rs
fn main() -> std::process::ExitCode {
    let arguments = std::env::args_os().collect::<Vec<_>>();
    match arguments.get(1).map(OsString::as_os_str) {
        Some(command) if command == OsStr::new("serve") && arguments.len() == 2 => {
            secretsd::serve_main()
        }
        Some(command) if command == OsStr::new("serve") => {
            eprintln!("secrets: serve does not accept arguments");
            std::process::ExitCode::FAILURE
        }
        _ => match secretsd::client::cli::run(arguments) {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(error) => { eprintln!("secrets: {error}"); std::process::ExitCode::FAILURE }
        },
    }
}
```

In `src/proto.rs`, keep the human-request protocol limited to its ordinary typed request and response frames; do not add acknowledgement or announcement variants.  Do not add another version constant or protocol parser to a binary.

Create `src/client.rs` with `SocketPath::resolve`, `ClientError` (whose `Display` maps every current `ErrCode` plus malformed/IO/handshake cases to an actionable message), `BrokerResponse`, and byte-oriented `parse_response`.  Its reader must call `read_until(b'\n', ...)`, parse only ASCII headers, allocate exactly the declared payload length with `try_reserve_exact`, read exactly that many bytes, then make one additional `read` and reject a nonzero result.  Reject a NUL byte before returning `BrokerResponse::Bytes`.  `hello()` accepts only `OK\tversion=1\n`; it must reject the historical typo `OK\tv=1\n`.

- [ ] **Step 4: Run focused Rust checks**

Run: `cargo +nightly fmt --all -- --check && cargo clippy --all-targets --all-features -- -D warnings && cargo nextest run --test client`

Expected: formatter and clippy are clean; all four tests pass.

---

### Task 2: Implement daemon-independent agent-tier and CLI compatibility

**Parallel-safe:** No — depends on Task 1; may proceed alongside Task 3 after its exported client interface is merged.

**Files:**
- Modify: `src/client.rs`, `src/bin/secrets.rs`, `tests/client.rs`, `tests/fixtures/fake-sops-ok`

**Interfaces:**
- Produces `cli::run(impl IntoIterator<Item = OsString>) -> Result<(), CliError>`.
- Produces `AgentStore::value(&SecretName) -> Result<SecretBytes, CliError>` and `HumanNames::load(&Path) -> Result<BTreeSet<SecretName>, CliError>`.
- Preserves `get`, `KEY... -- command`, `list`, `edit`, `edit-local`, `edit-human`, `grants`, `deny [id]`, and `lock` exactly.

- [ ] **Step 1: Write compatibility tests before implementation**

Append these tests to `tests/client.rs`; each command runs `env -i PATH="$PATH" HOME="$HOME" DOTFILES_DIR=<fixture>`, proving no runtime directory, token, or socket is required for agent-tier paths:

```rust
#[test]
fn agent_get_works_with_a_minimal_noninteractive_environment() {
    let fixture = Fixture::agent("AGENT_ONLY=agent-value\n");
    let output = fixture.run_minimal(["get", "AGENT_ONLY"]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"agent-value\n");
    assert!(fixture.sops_log().contains("-d --input-type dotenv --output-type dotenv"));
    assert!(!fixture.sops_log().contains("secretsd.sock"));
}

#[test]
fn list_uses_human_filenames_without_invoking_sops_for_them() {
    let fixture = Fixture::agent("AGENT_ONLY=agent-value\n");
    fixture.write_human_name("HUMAN");
    let output = fixture.run_minimal(["list"]);
    assert_eq!(output.stdout, b"AGENT_ONLY\nHUMAN  (human tier)\n");
    assert_eq!(fixture.sops_calls(), 1);
}

#[test]
fn duplicate_agent_and_human_name_fails_before_broker_or_output() {
    let fixture = Fixture::agent("DUP=agent-value\n");
    fixture.write_human_name("DUP");
    for args in [["get", "DUP"].as_slice(), ["list"].as_slice()] {
        let output = fixture.run_minimal(args);
        assert_ne!(output.status.code(), Some(0));
        assert!(String::from_utf8_lossy(&output.stderr).contains("exists in both agent and human tiers"));
    }
}

#[test]
fn inject_form_sets_values_only_in_the_child_environment() {
    let fixture = Fixture::agent("A=one\nB=two\n");
    let output = fixture.run_minimal(["A", "B", "--", "sh", "-c", "printf '%s:%s' \"$A\" \"$B\""]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"one:two");
}
```

- [ ] **Step 2: Verify the new tests fail**

Run: `cargo nextest run --test client agent_get_works_with_a_minimal_noninteractive_environment`

Expected: FAIL because no `secrets` binary CLI or `Fixture` helper exists.

- [ ] **Step 3: Implement the direct sops path and exact command surface**

Implement `AgentStore::decrypt_all` by spawning only:

```rust
Command::new(&self.sops_bin)
    .args(["-d", "--input-type", "dotenv", "--output-type", "dotenv"])
    .arg(path)
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::null())
```

Read stdout into a zeroized buffer, parse dotenv assignments manually, and return the named value only.  Load `secrets.local.env` first when it exists, then `secrets.env`, matching the shim's precedence.  Never construct `BrokerClient` on this path.  `HumanNames::load` must use `read_dir`, accept only validated `*.env` stems, sort through `BTreeSet`, and never open/decrypt a file.

In `cli::run`, determine human membership before calling `AgentStore`.  If membership is human, call the Task 4 broker path; if both stores contain the name, return `CliError::AmbiguousKey`.  For `edit*`, replace the process with `sops <the same current target path>`; for injection, resolve every value before `Command::exec` with `key=value` `OsString`s.  Require a `--` separator and command exactly as the shim does.

Make `fake-sops-ok` fail unless both `--input-type dotenv` and `--output-type dotenv` appear as adjacent argv pairs; keep its invocation log but never log fake secret output.

- [ ] **Step 4: Run the compatibility gate**

Run: `cargo nextest run --test client && env -i PATH="$PATH" HOME="$HOME" DOTFILES_DIR="$(mktemp -d)" target/debug/secrets get MISSING`

Expected: all client tests pass; the smoke command exits nonzero with `secrets: secret 'MISSING' not found`, not an `XDG_RUNTIME_DIR` or broker error.

---

### Task 3: Remove the announcement gate

**Parallel-safe:** No — run after Task 1 has settled `src/proto.rs` and `src/lib.rs`, and before Tasks 4, 6, 8, and 9 consume the resulting protocol, `Config`, broker harness, and packaged-unit contract.  Task 2 may run alongside this task after Task 1 because it is disjoint from these daemon files; do not overlap this task with any task that edits `src/proto.rs`, `src/lib.rs`, `tests/broker.rs`, or either systemd unit.

**Files:**
- Delete: `src/announce.rs`, including `Announcement`, `Announcer`, `Notifier`, `CommandNotifier`, `render`, and every test in that module.
- Modify: `src/lib.rs`, `src/proto.rs`, `src/requests.rs`, `src/server.rs`, `src/server/dispatch.rs`, `src/server/worker.rs`, `tests/broker.rs`, `tests/broker/grants.rs`, `systemd/secretsd.service`, `systemd/secretsd.socket`, `docs/design.md`, and `AGENTS.md`.
- Remove `notify_argv` and `envoy_argv` from `Config`, `Config::from_env`, every test configuration, daemon state construction, and every systemd/deployment example.  Delete `SECRETSD_NOTIFY_CMD` and `SECRETSD_ENVOY_CMD`; no compatibility alias or no-op command remains.

**Decision and rationale:** Remove the gate rather than replacing its transport.  A pending decrypt makes the YubiKey on the operator's desk blink; that physical, out-of-band signal cannot be spoofed by software and already tells the operator exactly when a touch matters.  The operator initiates every request, including requests delegated to an agent, so this workflow has no unattributed-blink case.  The prior concern was unexplained blinks, which is answered after the fact by the existing structured journald request event recording key name, scope kind, peer PID, and decision.

The touch remains the authorization gesture: the daemon starts the requested decrypt, the YubiKey blinks, and the human touches it or does not.  The journald request log is now the sole audit mechanism; retain its structured attribution fields and never log secret plaintext or session-token bytes.  A pre-decrypt software message is redundant and harmful: a missing `notify-send` made grants fail with `NOT_ANNOUNCED`, and making Envoy mandatory converted credential access into a network-service dependency.  The headless-notifier problem therefore disappears, as does the devbox `SECRETSD_NOTIFY_CMD=true` stub and one `~/.dotfiles` reference in the systemd service.

- [ ] **Step 1: Write failing removal and audit regressions**

In `tests/broker/grants.rs`, replace the gate test with `request_without_a_notifier_reaches_the_hardware_gate`: start the existing fake-sops `Harness` without any notification command, register a token scope, request a human key, and assert that fake sops is invoked once and the request receives its normal successful result.  This is deliberately the inverse of the old policy: absence of a notification command must never suppress a hardware prompt.  Production hardware still requires the physical touch; the fake decryptor only proves that configuration no longer inserts a software gate before it.

Keep the existing structured journald event as the sole audit record.  Add a server logging regression beside the request-handler tests that captures `request handled` and asserts its `key`, `scope_kind`, kernel-derived `peer_pid`, and `decision` fields are present, while secret plaintext and session-token bytes are absent.  Do not reintroduce client-supplied session metadata solely for logging.

Apply these explicit dispositions to every announcement test:

| Existing test | Disposition | Does its guarded property survive? |
|---|---|---|
| `announce_fails_closed_when_no_channels_are_configured` | Delete with `src/announce.rs`. | No. It required a configured software delivery channel before a decrypt could start; authorization is now the YubiKey touch. The replacement broker test covers the intended new invariant: no notification configuration may block the hardware prompt. |
| `announce_fails_closed_when_every_channel_fails` | Delete with `src/announce.rs`. | No. A failed software message is no longer an authorization signal or a reason to suppress the hardware prompt. No replacement notification behavior is added. |
| `render_sanitizes_metadata_so_it_cannot_forge_lines` | Delete with `render`. | No. Its free-text, human-visible rendering target no longer exists, so there is no remaining line-oriented metadata channel to sanitize. The distinct surviving audit-attribution requirement is covered by the structured journald regression above. |
| `no_announcement_channel_means_no_grant` | Rewrite as `request_without_a_notifier_reaches_the_hardware_gate`. | No. Its original assertion that a missing channel prevents sops is intentionally reversed. The rewritten test covers the surviving requirement that an unconfigured headless environment is not denied before the YubiKey can request a touch. |

Delete the other renderer and delivery tests with their module; do not preserve any assertion that counts calls to a notifier or waits for a client acknowledgement.

- [ ] **Step 2: Verify the removal regression fails**

Run: `cargo nextest run --test broker request_without_a_notifier_reaches_the_hardware_gate`

Expected: the regression proves that missing delivery configuration never
suppresses the hardware prompt.

- [ ] **Step 3: Delete the gate instead of substituting another precondition**

Delete `src/announce.rs`; remove its public module from `src/lib.rs`; remove all announcer imports, state, construction, test fixtures, worker jobs, and call sites from `src/server.rs` and `src/server/worker.rs`.  The worker must proceed directly from `Queue::mark_decrypting` to `Decryptor::decrypt_with_start`; remove `request_metadata` and `fail_request` if they are then dead.  Preserve the existing pending/decrypting, expiry, denial, single-flight, and process-group-kill behavior.  In `src/requests.rs`, remove the announcement-specific wording for request IDs but do not add a replacement waiting state.

Remove any interim `Request::Acknowledge`, acknowledgement parser, announcement response, and `Outcome::Announcement` from `src/proto.rs`, `src/server/dispatch.rs`, and client-facing dispatch paths.  Remove `ErrCode::NotAnnounced` and its `NOT_ANNOUNCED` wire mapping.  This is a protocol-surface change, but **do not bump `PROTOCOL_VERSION`**: the only consumers are this repository's client and plugin, both ship with this restructuring release, and mixed old/new peers are not a supported deployment.  Keeping version 1 avoids claiming a compatibility boundary that the release does not provide; a future independently deployed consumer would require a version bump before incompatible interoperation.

Delete `SECRETSD_NOTIFY_CMD` and `SECRETSD_ENVOY_CMD` parsing from `Config::from_env`, their `Config` fields, all explicit test `Config` literals, and the command construction in `State::new`.  Delete both environment assignments from the packaged systemd service and every deployment/drop-in example.  A headless machine has no special credential-access configuration: it follows the same hardware-touch flow as any other machine, without a `true` stub, desktop utility, network service, or companion-repository command.

Retain the existing `tracing::info!` request event with structured key name, scope kind, peer PID, and decision fields.  It is the sole audit mechanism and records attribution after the fact; it must not gain a pre-decrypt notification, a free-text renderer, secret plaintext, or session-token bytes.

- [ ] **Step 4: Run removal, broker, and protocol checks**

Run: `cargo nextest run --lib && cargo nextest run --test broker && cargo nextest run proto`

Expected: the no-notifier broker regression reaches fake sops, the structured request-log regression retains attribution without secrets, all broker tests pass, and the protocol has neither acknowledgement frames nor the removed error code.

---

### Task 4: Complete human-tier CLI transport and all failure messages

**Parallel-safe:** No — follows Tasks 1 and 3, which settle the ordinary human request frames and remove the obsolete error code.

**Files:**
- Modify: `src/client.rs`, `src/bin/secrets.rs`, `tests/client.rs`

**Interfaces:**
- `HumanClient::get(&self, key: &SecretName) -> Result<SecretBytes, CliError>` sends one typed human request and handles its ordinary terminal response.
- `CliError::from_broker(ErrCode)` is exhaustive and has a distinct message for every protocol error.

- [ ] **Step 1: Add end-to-end fake-broker tests**

Use the typed `FakeBroker` in `tests/client.rs` to assert exact wire frames and visible, retry-safe guidance:

```rust
#[test]
fn human_get_sends_tty_once_without_a_software_gate() {
    let broker = FakeBroker::script([
        Reply::Hello, Reply::Bytes(b"human-value"),
    ]);
    let fixture = Fixture::human("HUMAN", broker.socket());
    fixture.unset_token_file();
    let output = fixture.run_in_tty(["get", "HUMAN"]);
    assert_eq!(output.stdout, b"human-value\n");
    assert_eq!(broker.frames(), ["HELLO\tversion=1", "GET\tkey=HUMAN\ttty=/dev/pts/test"]);
}

#[test]
fn token_file_path_is_read_but_its_token_is_not_rendered_on_error() {
    let broker = FakeBroker::script([Reply::Hello, Reply::Error("UNKNOWN_TOKEN", "registered session missing")]);
    let fixture = Fixture::human("HUMAN", broker.socket());
    fixture.write_token("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    let output = fixture.run(["get", "HUMAN"]);
    assert_ne!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stderr).contains("broker restarted"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("0123456789"));
}

#[test]
fn every_daemon_error_has_clear_agent_guidance() {
    for code in ["BAD_REQUEST", "UNKNOWN_OP", "VERSION_MISMATCH", "UNKNOWN_TOKEN", "NO_SCOPE", "AGENT_TTY", "NOT_HUMAN_KEY", "DENIED", "TIMEOUT", "YUBIKEY_UNREACHABLE", "TOO_MANY_PENDING", "INTERNAL"] {
        let text = CliError::from_wire_error(code, "detail").to_string();
        assert!(!text.is_empty());
        assert!(text.contains("AGENT NOTICE"), "{code}: {text}");
    }
}
```

- [ ] **Step 2: Verify red tests**

Run: `cargo nextest run --test client human_get_sends_tty_once_without_a_software_gate`

Expected: FAIL because the typed human client is absent.

- [ ] **Step 3: Implement exact reads, retry and error mapping**

For each broker call, use `BrokerClient::call` so HELLO and frame parsing cannot drift from daemon types.  `HumanClient::get` sends exactly one GET after HELLO and returns its terminal response; it does not print a pre-decrypt message, issue an acknowledgement frame, or retry the request.

`read_token_file` must use `std::fs::read`, reject missing/empty/non-UTF-8/whitespace-padded token content, and remove the byte vector with `zeroize()` after parsing.  `caller_tty` returns `None` where no controlling terminal exists; it never makes agent-tier use fail.  Keep token scope authoritative: if a token-file variable is set but invalid, do not downgrade to tokenless.

Map errors as follows: `VERSION_MISMATCH` → update/restart client and daemon; `UNKNOWN_TOKEN` → broker restarted, request human re-approval; `NO_SCOPE`/`AGENT_TTY` → request from a human terminal or use the OpenCode token path; `NOT_HUMAN_KEY` → malformed/moved human key; `DENIED`/`TIMEOUT` → human declined/was unavailable; `YUBIKEY_UNREACHABLE` → connect the configured hardware path; `TOO_MANY_PENDING` → stop retrying and ask the human; `BAD_REQUEST`, `UNKNOWN_OP`, `INTERNAL` → report broker failure.  Prefix all broker-derived CLI failures with `AGENT NOTICE: ask the human; do not retry-loop.`

- [ ] **Step 4: Run the client acceptance tests**

Run: `cargo nextest run --test client && cargo +nightly miri nextest run --all-features -E 'test(/^(client|proto)::tests::/)'`

Expected: client transport and pure parser tests pass under both test runners; no frame assertion includes a token value.

---

### Task 5: Fail safely before `MCL_FUTURE` can abort the daemon

**Parallel-safe:** Yes — disjoint from client/plugin work; merge before the final test task.

**Files:**
- Modify: `src/hardening.rs`, `src/lib.rs`, `src/bin/secrets.rs`, `tests/hardening.rs`, `docs/design.md`, `AGENTS.md`

**Interfaces:**
- Produces `hardening::validate_memlock_limit() -> Result<(), HardeningError>` and `HardeningError::InsufficientMemlock { soft, hard }`.
- The executable calls the validator before `mlockall(MCL_CURRENT | MCL_FUTURE)`, thread creation, socket serving, or daemon state allocation.

- [ ] **Step 1: Write a subprocess regression test with a low limit**

Add this to `tests/hardening.rs`; the helper process avoids changing the test runner's own limit:

```rust
#[test]
fn low_memlock_limit_exits_with_actionable_diagnostic_instead_of_sigabrt() {
    let binary = env!("CARGO_BIN_EXE_secrets");
    let output = Command::new("sh")
        .args(["-c", "ulimit -l 8; exec \"$1\" serve", "sh", binary])
        .env("SECRETSD_SOCKET", tempfile::tempdir().unwrap().path().join("broker.sock"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("RLIMIT_MEMLOCK"));
    assert!(stderr.contains("LimitMEMLOCK=infinity"));
    assert!(!stderr.contains("panicked"));
}
```

- [ ] **Step 2: Prove the regression test currently fails**

Run: `cargo nextest run --test hardening low_memlock_limit_exits_with_actionable_diagnostic_instead_of_sigabrt`

Expected: FAIL because the child aborts after `mlockall` makes its later thread allocation fail.

- [ ] **Step 3: Preflight the resource limit and make the error actionable**

Call `nix::sys::resource::getrlimit(Resource::RLIMIT_MEMLOCK)` before hardening.  Treat both a finite soft limit and a finite hard limit below `RLIM_INFINITY` as insufficient: `MCL_FUTURE` requires capacity for all later allocations, not merely pages currently mapped.  Return a display string exactly in this form:

```text
RLIMIT_MEMLOCK is insufficient for mlockall(MCL_CURRENT|MCL_FUTURE); start secretsd through systemd with LimitMEMLOCK=infinity
```

Do not make memlock optional for the production binary and do not call `mlockall` after this preflight failure.  Preserve `MemlockPolicy::Optional` exclusively for existing isolated hardening tests; its implementation must still avoid `MCL_FUTURE` when a finite cap would poison future allocation.

- [ ] **Step 4: Run the regression and hardening suite**

Run: `cargo nextest run --test hardening && cargo clippy --all-targets --all-features -- -D warnings`

Expected: all hardening tests pass; low-limit execution exits 1 with the `RLIMIT_MEMLOCK` and systemd-limit wording, never signal 6/SIGABRT.

---

### Task 6: Keep a hardware-free daemon/client end-to-end harness in the repository

**Parallel-safe:** Yes — after Tasks 1 and 3 interfaces are fixed; it touches only integration-test support and fixtures.

**Files:**
- Modify: `tests/broker/support.rs`, `tests/fixtures/fake-sops-ok`
- Create: `tests/e2e_client.rs`

**Interfaces:**
- `ClientHarness::start() -> Result<Self, TestError>` starts a scratch daemon on a unique Unix socket with `SECRETSD_HUMAN_DIR` and `SECRETSD_SOPS_BIN`, with no notification command fixture.
- `ClientHarness::register(token, session)` and `ClientHarness::cli(args, env)` drive the real `secrets` binary.

- [ ] **Step 1: Write the full acceptance test**

Create `tests/e2e_client.rs`:

```rust
mod broker;

use broker::support::ClientHarness;

#[test]
fn registered_agent_gets_a_human_value_from_a_scratch_daemon_without_hardware() {
    let harness = ClientHarness::start().unwrap();
    harness.write_human_ciphertext("HUMAN");
    harness.register("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "session-a").unwrap();
    let token_file = harness.write_token_file("session-a", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    let result = harness.cli(
        ["get", "HUMAN"],
        [("SECRETSD_SESSION_TOKEN_FILE", token_file.as_os_str())],
    );

    assert_eq!(result.status.code(), Some(0));
    assert_eq!(result.stdout, b"value-for-HUMAN\n");
    assert_eq!(harness.sops_arguments(), vec![vec!["-d", "--input-type", "dotenv", "--output-type", "dotenv"]]);
    assert!(!String::from_utf8_lossy(&result.stderr).contains("value-for-HUMAN"));
}
```

- [ ] **Step 2: Verify it fails before the harness exists**

Run: `cargo nextest run --test e2e_client`

Expected: FAIL because `ClientHarness` and the installed `secrets` executable test path do not exist.

- [ ] **Step 3: Build the scratch deployment rather than a mock protocol server**

Extend the existing `Harness` support rather than duplicating socket code.  It must start `secretsd::run(Config { socket_path, human_dir, sops_bin: fake_sops, .. })` in a thread with `MemlockPolicy::Optional` only for the test process.  Spawn the actual `CARGO_BIN_EXE_secrets` with `SECRETSD_SOCK` set to the scratch socket and no `XDG_RUNTIME_DIR`; use a real `REGISTER` frame before the CLI call.  The fake sops must produce the single expected dotenv assignment and reject a missing input/output dotenv flag.

This test is specifically the regression harness for the production flow: it exercises `REGISTER -> CLI token-file read -> HELLO -> GET -> fake sops -> framed bytes`, not a hand-written substitute for any of those links.  Production substitutes the fake decryptor with the blinking YubiKey and its physical touch requirement.

- [ ] **Step 4: Run acceptance and baseline tests**

Run: `cargo nextest run --test e2e_client && cargo nextest run --workspace --all-targets --all-features`

Expected: the new hardware-free flow passes and the full suite remains at least 105 tests (the pre-change baseline was 104).

---

### Task 7: Relocate and continuously test the OpenCode plugin

**Parallel-safe:** Yes — source relocation is disjoint from Rust code; CI changes must be sequenced after the files are present.

**Files:**
- Create: `opencode/plugins/secretsd.ts`, `opencode/plugins/secretsd.test.ts`, `opencode/package.json`
- Modify: `.github/workflows/ci.yml`, `docs/design.md`, `AGENTS.md`

**Interfaces:**
- Preserves `createSecretsdPlugin`, `issueTokenFile`, `removeTokenFile`, `REQUEST_TIMEOUT_MS`, OpenCode hook names, and the full token-file contract without a behavioral rewrite.
- Produces `bun --cwd opencode test plugins/secretsd.test.ts` as a repository CI gate.

- [ ] **Step 1: Relocate byte-for-byte and prove test discovery**

Copy, do not rewrite, the currently deployed source and test:

```bash
mkdir -p opencode/plugins
cp /home/sami/.dotfiles/opencode/plugins/secretsd.ts opencode/plugins/secretsd.ts
cp /home/sami/.dotfiles/opencode/plugins/secretsd.test.ts opencode/plugins/secretsd.test.ts
```

Create `opencode/package.json`:

```json
{
  "private": true,
  "type": "module",
  "devDependencies": { "@opencode-ai/plugin": "1.3.0" },
  "scripts": { "test:secretsd-plugin": "bun test plugins/secretsd.test.ts" }
}
```

Run: `bun --cwd opencode install --frozen-lockfile && bun --cwd opencode run test:secretsd-plugin`

Expected: FAIL before the lockfile/dependency is established, then PASS with the pre-existing plugin assertions unchanged.

- [ ] **Step 2: Make plugin verification part of CI**

Add this step after Rust test setup in `.github/workflows/ci.yml`:

```yaml
      - uses: oven-sh/setup-bun@v2
      - name: Test OpenCode secretsd plugin
        run: bun --cwd opencode install --frozen-lockfile && bun --cwd opencode run test:secretsd-plugin
```

Commit the generated `opencode/bun.lock`; do not commit a repository-root `node_modules` directory.

- [ ] **Step 3: Record the deployment binding**

In `docs/design.md`, replace the out-of-tree client/plugin ownership claim with the installed release contract: package installation places the exact tested plugin at `~/.local/share/secretsd/opencode/plugins/secretsd.ts`, and dotfiles loads `file://{env:HOME}/.local/share/secretsd/opencode/plugins/secretsd.ts`.

Choose the absolute installed path, not a dotfiles-created symlink: the daemon release owns its plugin version, the OpenCode configuration has a stable path, and a partial dotfiles checkout cannot leave a release plugin pointing at unrelated working-tree code.  Preserve `${XDG_RUNTIME_DIR}/secretsd/<sessionID>.token`, directory `0700`, file `0600`, and only `SECRETSD_SESSION_TOKEN_FILE=<path>` in every environment injection.

- [ ] **Step 4: Run both plugin and Rust gates**

Run: `bun --cwd opencode run test:secretsd-plugin && cargo nextest run --workspace --all-targets --all-features`

Expected: plugin tests retain every existing token lifecycle, reconnect, error mapping, and redaction assertion; Rust tests stay green.

---

### Task 8: Package generic systemd units and the companion cutover contract

**Parallel-safe:** No — execute after Tasks 3 and 5: Task 3 removes the obsolete unit environment and deployment assumptions, and Task 5 supplies the memlock diagnostic that this task documents.

**Files:**
- Modify: `systemd/secretsd.service`, `systemd/secretsd.socket`, `docs/design.md`, `AGENTS.md`
- Create: `docs/dotfiles-cutover.md`

**Interfaces:**
- The packaged service invokes `%h/.local/bin/secrets serve` through an absolute
  `ExecStart`; deployment-specific configuration belongs in consumer-owned
  `secretsd.service.d/*.conf` drop-ins.
- The package contains no software announcement or agent-transport configuration; a human-tier request reaches the hardware touch flow on every supported machine.

- [ ] **Step 1: Replace the service unit with this complete portable content**

Write `systemd/secretsd.service` exactly:

```ini
[Unit]
Description=secretsd session secrets broker
Requires=secretsd.socket
After=secretsd.socket

[Service]
Type=simple
# `%h` expands to an absolute path before execution; `Environment=PATH` does
# not resolve `ExecStart`.
ExecStart=%h/.local/bin/secrets serve
Environment=PATH=%h/.local/bin:/usr/local/bin:/usr/bin
# A deployment drop-in must replace this empty value with an absolute directory.
Environment=SECRETSD_HUMAN_DIR=
LimitMEMLOCK=infinity
LimitCORE=0
Restart=on-failure
RestartSec=1
NoNewPrivileges=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes

[Install]
WantedBy=default.target
```

Write `systemd/secretsd.socket` exactly:

```ini
[Unit]
Description=secretsd session secrets broker socket

[Socket]
ListenStream=%t/secretsd.sock
SocketMode=0600
Accept=no
RemoveOnStop=yes

[Install]
WantedBy=sockets.target
```

- [ ] **Step 2: Validate the packaged units**

Run: `systemd-analyze --user verify systemd/secretsd.service systemd/secretsd.socket && ! grep -R --line-number --fixed-strings '.dotfiles' systemd`

Expected: `systemd-analyze` and the negative search exit 0 with no matching output.

- [ ] **Step 3: Write the consuming-dotfiles contract in `docs/dotfiles-cutover.md`**

Document this exact drop-in example, owned by dotfiles rather than this package:

```ini
# ~/.config/systemd/user/secretsd.service.d/deployment.conf
[Service]
Environment=SECRETSD_HUMAN_DIR=/home/alice/.config/secretsd/secrets.human.d
Environment=SECRETSD_SOPS_BIN=/home/alice/.local/share/mise/installs/sops/3.10.2/sops
Environment=PATH=/home/alice/.local/bin:/home/alice/.local/share/mise/installs/age-plugin-yubikey/0.5.0:/usr/local/bin:/usr/bin
Environment=PCSCLITE_CSOCK_NAME=/run/user/1000/pcscd.comm
```

Then list the required dotfiles-only changes precisely:

1. Pin the released `secretsd` package/version in `mise.toml`, exposing `~/.local/bin/secrets` plus `~/.local/share/secretsd/opencode/plugins/secretsd.ts`.
2. Change the OpenCode plugin entry to `file://{env:HOME}/.local/share/secretsd/opencode/plugins/secretsd.ts`.
3. Delete `shims/secrets` and `shims/tests/test_secrets_shim.py`; delete the moved plugin and `opencode/plugins/secretsd.test.ts`.
4. Shrink `installers/secretsd.sh` to installing/enabling the two packaged units, creating the drop-in, and importing `PCSCLITE_CSOCK_NAME`; it must not copy a personal command or a dotfiles path into this repository's unit.
5. **Cutover order:** install the Rust release on laptop and devbox; run its full tests; on **both machines** run `env -i PATH="$PATH" HOME="$HOME" DOTFILES_DIR="$HOME/.dotfiles" secrets get ANTHROPIC_API_KEY` through non-interactive SSH and confirm success with no daemon socket/runtime directory; only after both checks pass may the bash shim be removed.  Then install the plugin path, reload user systemd, and verify agent-tier consumers (Legion, Dojo, skill MCPs) before enabling human-tier requests.

State explicitly that a headless devbox follows the same direct hardware-touch flow for agent-initiated human-tier grants as any other machine; no desktop session or auxiliary service is required.

- [ ] **Step 4: Run packaging/document checks**

Run: `systemd-analyze --user verify systemd/secretsd.service systemd/secretsd.socket && cargo +nightly fmt --all -- --check`

Expected: unit syntax is valid and Rust formatting remains clean; no command decrypts a file under `secrets.human.d`.

---

### Task 9: Remove remaining layout assumptions and perform the release-quality verification

**Parallel-safe:** No — final integration task; execute after Tasks 1–8.

**Files:**
- Modify: `src/lib.rs`, `src/bin/secrets.rs`, `.github/workflows/ci.yml`, `docs/design.md`, `AGENTS.md`

**Interfaces:**
- `Config::from_env() -> Result<Config, ConfigError>` requires `SECRETSD_HUMAN_DIR` for the daemon; it no longer defaults to `%h/.dotfiles/secrets.human.d`.
- `SECRETSD_SOCKET` remains daemon-only test/deployment configuration; `SECRETSD_SOCK` remains the lazy CLI override.

- [ ] **Step 1: Write configuration and control-operation regression tests**

Add these exact tests:

```rust
#[test]
fn daemon_requires_a_deployment_owned_human_directory() {
    let environment = EnvGuard::without("SECRETSD_HUMAN_DIR");
    let result = secretsd::Config::from_env();
    drop(environment);
    assert!(matches!(result, Err(secretsd::ConfigError::MissingHumanDir)));
}

#[test]
fn cli_control_operations_have_the_unchanged_surface() {
    let broker = FakeBroker::script([Reply::Hello, Reply::Bytes(b"pending=0\n"), Reply::Hello, Reply::Ok, Reply::Hello, Reply::Ok]);
    let fixture = Fixture::human("HUMAN", broker.socket());
    assert_eq!(fixture.run(["grants"]).stdout, b"pending=0\n");
    assert_eq!(fixture.run(["deny", "7"]).status.code(), Some(0));
    assert_eq!(fixture.run(["lock"]).status.code(), Some(0));
    assert_eq!(broker.frames(), ["HELLO\tversion=1", "GRANTS", "HELLO\tversion=1", "DENY\tid=7", "HELLO\tversion=1", "LOCK"]);
}
```

- [ ] **Step 2: Verify they fail**

Run: `cargo nextest run --test client daemon_requires_a_deployment_owned_human_directory`

Expected: FAIL because `Config::from_env` supplies the old dotfiles default.

- [ ] **Step 3: Remove the last daemon-specific personal default**

Replace `Config::from_env() -> Self` with `Config::from_env() -> Result<Self, ConfigError>`.  Delete its `HOME` lookup and its `%h/.dotfiles/secrets.human.d` fallback; use only a nonempty `SECRETSD_HUMAN_DIR`, returning `MissingHumanDir` otherwise.  Update `serve_main()`, all tests, and test harness constructors to propagate this error without `unwrap`/`expect` outside test code.  Keep defaults only for safe daemon behavior (`SECRETSD_SOCKET`, sops command, timeouts) and do not permit a client to select any daemon configuration path.

Add all project gates to CI in this order: nightly format, clippy with `-D warnings`, nextest, the pure-module Miri filter extended to `client`, `cargo machete`, `cargo deny check all`, and the Bun plugin test.  The CI YAML must invoke `cargo +nightly fmt --all -- --check`, not stable `cargo fmt`.

- [ ] **Step 4: Run the single final verification pass**

Run exactly:

```bash
cargo +nightly fmt --all -- --check && \
cargo clippy --workspace --all-targets --all-features -- -D warnings && \
cargo nextest run --workspace --all-targets --all-features && \
cargo +nightly miri nextest run --all-features -E 'test(/^(secret|grants|requests|proto|client)::tests::/)' && \
```

Expected: every command exits 0; the Rust count is at least 105 tests; plugin tests pass; systemd units validate.  Then inspect the scoped change only with `jj diff --git -- docs/plans/2026-07-25-self-contained-client.md` while this plan is being authored, and during implementation inspect the intended changed paths only.  Do not run an unscoped restore.

---

## Requirement Coverage Check

- Shared Rust protocol/client and one explicit binary: Tasks 1–4 and 9.
- Drop-in CLI surface, unattended agent tier, filename-only list, duplicate failure, exact frames, token-file/TTY/lazy socket/error guidance: Tasks 2 and 4.
- In-repository OpenCode plugin, token contract, Bun CI, installed-path binding: Task 7.
- Complete announcement-gate removal, direct physical-touch authorization, headless parity, and journald-only attribution: Task 3.
- Generic portable systemd units and load-bearing socket/memlock invariants: Task 8.
- Low-`RLIMIT_MEMLOCK` early diagnostic regression: Task 5.
- Hardware-free scratch daemon REGISTER/GET harness and strict fake sops: Task 6.
- Dotfiles-only changes and safe two-machine cutover order: Task 8.
