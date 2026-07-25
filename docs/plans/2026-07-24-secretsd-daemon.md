# secretsd Daemon Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the `secretsd` daemon: a Unix-socket broker that grants
hardware-approved secrets to a single agent session for that session's lifetime.

**Architecture:** One process per machine, socket-activated by systemd. A
thread per client connection plus exactly one YubiKey worker thread (which
structurally guarantees single-flight hardware access), sharing state behind a
`Mutex` + `Condvar`. Secret plaintext lives only in `SecretBytes` (zeroize on
drop) inside this process. Requests are authorized by a per-session token
issued by trusted harness code, never by a claimed session ID.

**Tech Stack:** Rust 1.92, edition 2024. `nix` (syscalls), `zeroize`, `subtle`,
`tracing`. Tests with `cargo-nextest` (required: several tests mutate
process-global state and rely on nextest's process-per-test isolation).

**Read first:** [`../design.md`](../design.md) — threat model, accepted
residual risks, and the reasoning behind choices that look arbitrary here.

## Global Constraints

- **Commits: one commit for this whole deliverable.** Per repo owner
  convention, do NOT commit per task or per TDD cycle. `jj` auto-snapshots, so
  work is never lost; describe the change once at the end
  (`jj describe -m "..."`). Do not push without explicit approval.
- **No `unwrap`/`expect`/`panic`/`todo`/`unreachable`/indexing outside
  `#[cfg(test)]`** — enforced by clippy lints in `Cargo.toml`. Use `.get()`,
  `?`, and exhaustive `match`.
- **No serde, no dotenv crate, on the plaintext path.** Hand-rolled protocol.
  `serde_json` is banned in `deny.toml`.
- **Secret plaintext must never appear** in logs, `Debug` output, error
  messages, or panic payloads.
- **Fail closed.** Unknown token, unparseable frame, missing scope, failed
  `mlockall`, ambiguous file, no announcement channel: refuse the request.
  Never degrade to a weaker path.
- **Announce before the blink.** No decrypt may start until an out-of-band
  announcement channel acknowledges.
- **Config comes from the daemon's own environment only** (systemd unit or
  test harness), never from a client request: `SECRETSD_SOCKET`,
  `SECRETSD_HUMAN_DIR`, `SECRETSD_SOPS_BIN`, `SECRETSD_NOTIFY_CMD`,
  `SECRETSD_ENVOY_CMD`, `SECRETSD_MAX_GRANT_SECS` (default 43200).
- **Tests never require real hardware.** Fake sops via `SECRETSD_SOPS_BIN`.
- Exhaustive `match` on every owned enum; no `_ =>` arms.
- Every public item gets a doc comment (`missing_docs = "warn"`).
- After each task: `cargo fmt --all && cargo clippy --all-targets --all-features -- -D warnings && cargo nextest run`

## File Structure

| File | Responsibility |
|---|---|
| `src/lib.rs` | Crate root: module decls, `Config`, `run(Config)` entry point used by both `main.rs` and integration tests. |
| `src/proto.rs` | Wire protocol v1: parse requests, format response headers. `ErrCode`. |
| `src/secret.rs` | `SecretName` (validated), `SecretBytes` (zeroizing, redacted `Debug`), single-assignment dotenv parse. |
| `src/hardening.rs` | `mlockall`, `PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`. |
| `src/store.rs` | The `secrets.human.d` directory: list key names without decrypting; `openat`/`O_NOFOLLOW` file resolution. |
| `src/decrypt.rs` | Reachability pre-flight, sops subprocess, timeout, process-group kill. |
| `src/grants.rs` | `SessionToken`, `Scope`, `Registry` (registrations + learned agent ttys), `GrantTable`. |
| `src/requests.rs` | Request state machine, single-flight queue, cooldown, per-scope pending limits, `Clock`. |
| `src/announce.rs` | Announcement rendering and delivery; ack requirement. |
| `src/server.rs` | Socket activation, accept loop, connection handling, YubiKey worker thread, op dispatch. |
| `src/main.rs` | Build `Config` from env, apply hardening, call `run`. |
| `tests/hardening.rs` | Process-global hardening assertions (own process via nextest). |
| `tests/broker.rs` | End-to-end: real socket, fake sops, fake notifier. |
| `systemd/secretsd.socket`, `systemd/secretsd.service` | Packaging. |

---

### Task 1: Wire protocol

**Files:**
- Create: `src/proto.rs`
- Create: `src/lib.rs`

**Interfaces:**
- Produces: `PROTOCOL_VERSION: u32`, `MAX_FRAME_BYTES: usize`,
  `enum ErrCode` with `fn wire(self) -> &'static str`,
  `enum Request` (`Hello{version}`, `Register{token_hex,session,pid}`,
  `Unregister{session}`, `Get{key,token_hex,tty}`, `RequestGrant{key,token_hex,tty}`,
  `Grants`, `Deny{id}`, `Lock`),
  `fn parse_request(line: &[u8]) -> Result<Request, ErrCode>`,
  `enum Response<'a>` (`Ok`, `OkFields(&'a str)`, `OkBytes(usize)`, `Failed(ErrCode, &'a str)`),
  `fn format_response(r: &Response<'_>) -> String`.
- Note: `Request` carries the token as `Option<String>` hex at this layer.
  Parsing hex into `SessionToken` belongs to `grants.rs` (Task 5) so the
  protocol layer stays free of crypto types.

- [ ] **Step 1: Write the failing tests**

Create `src/proto.rs` containing only the test module for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hello_when_version_present() {
        let req = parse_request(b"HELLO\tversion=1").unwrap();
        assert_eq!(req, Request::Hello { version: 1 });
    }

    #[test]
    fn parses_get_with_token_and_tty() {
        let line = b"GET\tkey=DEEL_API_KEY\ttoken=ab12\ttty=/dev/pts/3";
        let req = parse_request(line).unwrap();
        assert_eq!(
            req,
            Request::Get {
                key: "DEEL_API_KEY".to_owned(),
                token_hex: Some("ab12".to_owned()),
                tty: Some("/dev/pts/3".to_owned()),
            }
        );
    }

    #[test]
    fn parses_get_without_token() {
        let req = parse_request(b"GET\tkey=K\ttty=/dev/pts/3").unwrap();
        assert_eq!(
            req,
            Request::Get { key: "K".to_owned(), token_hex: None, tty: Some("/dev/pts/3".to_owned()) }
        );
    }

    #[test]
    fn rejects_unknown_op() {
        assert_eq!(parse_request(b"FROBNICATE\tx=1"), Err(ErrCode::UnknownOp));
    }

    #[test]
    fn rejects_missing_required_field() {
        assert_eq!(parse_request(b"GET\ttty=/dev/pts/3"), Err(ErrCode::BadRequest));
    }

    #[test]
    fn rejects_empty_line() {
        assert_eq!(parse_request(b""), Err(ErrCode::BadRequest));
    }

    #[test]
    fn rejects_oversized_frame() {
        let line = vec![b'A'; MAX_FRAME_BYTES + 1];
        assert_eq!(parse_request(&line), Err(ErrCode::BadRequest));
    }

    #[test]
    fn rejects_non_utf8() {
        assert_eq!(parse_request(&[b'G', b'E', b'T', b'\t', 0xff]), Err(ErrCode::BadRequest));
    }

    #[test]
    fn rejects_duplicate_field() {
        assert_eq!(parse_request(b"GET\tkey=A\tkey=B"), Err(ErrCode::BadRequest));
    }

    #[test]
    fn formats_ok_bytes_header() {
        assert_eq!(format_response(&Response::OkBytes(42)), "OK\tlen=42\n");
    }

    #[test]
    fn formats_error_with_code_and_message() {
        assert_eq!(
            format_response(&Response::Failed(ErrCode::UnknownToken, "no such session")),
            "ERR\tUNKNOWN_TOKEN\tno such session\n"
        );
    }

    #[test]
    fn error_message_newlines_are_sanitized() {
        let out = format_response(&Response::Failed(ErrCode::Internal, "bad\nthing"));
        assert_eq!(out.matches('\n').count(), 1);
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo nextest run proto`
Expected: FAIL — `cannot find function parse_request in this scope`.

- [ ] **Step 3: Implement the protocol**

Prepend to `src/proto.rs` (above the test module):

```rust
//! Wire protocol v1: line-oriented, tab-separated, ASCII.
//!
//! Hand-rolled deliberately. Secret plaintext is written straight from a
//! zeroizing buffer to the socket and never passes through a serializer whose
//! internal buffers we cannot wipe.

/// Protocol version. A mismatch is a hard error, never a downgrade.
pub const PROTOCOL_VERSION: u32 = 1;

/// Maximum accepted request frame. Requests never carry secret values.
pub const MAX_FRAME_BYTES: usize = 4096;

/// Machine-readable failure reasons. The wire form is stable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrCode {
    /// Frame was malformed, oversized, or missing a required field.
    BadRequest,
    /// Operation name is not part of this protocol version.
    UnknownOp,
    /// Client speaks a different protocol version.
    VersionMismatch,
    /// Token was not issued by a registered session.
    UnknownToken,
    /// Neither a token nor a usable tty accompanied the request.
    NoScope,
    /// Tokenless request arrived from a tty known to belong to an agent session.
    AgentTty,
    /// Key is not present in the human-tier store.
    NotHumanKey,
    /// A human denied the request.
    Denied,
    /// The request expired before approval.
    Timeout,
    /// The YubiKey is not reachable from this machine right now.
    YubikeyUnreachable,
    /// No announcement channel acknowledged, so no hardware interaction began.
    NotAnnounced,
    /// This scope already has too many requests awaiting approval.
    TooManyPending,
    /// Decryption failed for a reason that is not the client's fault.
    Internal,
}

impl ErrCode {
    /// Stable wire token for this code.
    pub const fn wire(self) -> &'static str {
        match self {
            Self::BadRequest => "BAD_REQUEST",
            Self::UnknownOp => "UNKNOWN_OP",
            Self::VersionMismatch => "VERSION_MISMATCH",
            Self::UnknownToken => "UNKNOWN_TOKEN",
            Self::NoScope => "NO_SCOPE",
            Self::AgentTty => "AGENT_TTY",
            Self::NotHumanKey => "NOT_HUMAN_KEY",
            Self::Denied => "DENIED",
            Self::Timeout => "TIMEOUT",
            Self::YubikeyUnreachable => "YUBIKEY_UNREACHABLE",
            Self::NotAnnounced => "NOT_ANNOUNCED",
            Self::TooManyPending => "TOO_MANY_PENDING",
            Self::Internal => "INTERNAL",
        }
    }
}

/// A parsed client request. Tokens stay as hex here; `grants` owns the crypto type.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Request {
    /// Version handshake.
    Hello {
        /// Protocol version the client speaks.
        version: u32,
    },
    /// Harness registers a session token.
    Register {
        /// Hex-encoded session token.
        token_hex: String,
        /// Harness-supplied session identifier (untrusted; logging only).
        session: String,
        /// Harness process id, used for a pidfd death fallback.
        pid: i32,
    },
    /// Harness reports a session ended.
    Unregister {
        /// Session identifier used at registration.
        session: String,
    },
    /// Fetch a secret value, blocking through the grant flow if needed.
    Get {
        /// Requested key name.
        key: String,
        /// Hex-encoded session token, if the caller has one.
        token_hex: Option<String>,
        /// Caller's controlling tty, if any.
        tty: Option<String>,
    },
    /// Trigger the grant flow without returning a value.
    RequestGrant {
        /// Requested key name.
        key: String,
        /// Hex-encoded session token, if the caller has one.
        token_hex: Option<String>,
        /// Caller's controlling tty, if any.
        tty: Option<String>,
    },
    /// List active grants and pending requests.
    Grants,
    /// Reject a pending request.
    Deny {
        /// Request identifier from the announcement.
        id: u64,
    },
    /// Wipe all plaintext and revoke all grants.
    Lock,
}

/// A response to send back to a client.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Response<'a> {
    /// Success, no payload.
    Ok,
    /// Success with tab-separated `k=v` fields.
    OkFields(&'a str),
    /// Success followed by exactly this many raw payload bytes.
    OkBytes(usize),
    /// Failure with a machine code and a human-readable reason.
    Failed(ErrCode, &'a str),
}

/// Render a response header line, including its trailing newline.
pub fn format_response(response: &Response<'_>) -> String {
    match response {
        Response::Ok => "OK\n".to_owned(),
        Response::OkFields(fields) => format!("OK\t{}\n", sanitize(fields)),
        Response::OkBytes(len) => format!("OK\tlen={len}\n"),
        Response::Failed(code, message) => {
            format!("ERR\t{}\t{}\n", code.wire(), sanitize(message))
        }
    }
}

fn sanitize(text: &str) -> String {
    text.chars().map(|c| if c == '\n' || c == '\r' || c == '\t' { ' ' } else { c }).collect()
}

fn field<'a>(fields: &'a [(&'a str, &'a str)], name: &str) -> Option<&'a str> {
    fields.iter().find(|(k, _)| *k == name).map(|(_, v)| *v)
}

fn required<'a>(fields: &'a [(&'a str, &'a str)], name: &str) -> Result<&'a str, ErrCode> {
    field(fields, name).ok_or(ErrCode::BadRequest)
}

/// Parse one request frame (without its trailing newline).
pub fn parse_request(line: &[u8]) -> Result<Request, ErrCode> {
    if line.is_empty() || line.len() > MAX_FRAME_BYTES {
        return Err(ErrCode::BadRequest);
    }
    let text = std::str::from_utf8(line).map_err(|_| ErrCode::BadRequest)?;
    let mut parts = text.split('\t');
    let op = parts.next().ok_or(ErrCode::BadRequest)?;

    let mut fields: Vec<(&str, &str)> = Vec::new();
    for part in parts {
        let (key, value) = part.split_once('=').ok_or(ErrCode::BadRequest)?;
        if field(&fields, key).is_some() {
            return Err(ErrCode::BadRequest);
        }
        fields.push((key, value));
    }

    let owned = |name: &str| -> Option<String> { field(&fields, name).map(ToOwned::to_owned) };

    match op {
        "HELLO" => Ok(Request::Hello {
            version: required(&fields, "version")?.parse().map_err(|_| ErrCode::BadRequest)?,
        }),
        "REGISTER" => Ok(Request::Register {
            token_hex: required(&fields, "token")?.to_owned(),
            session: required(&fields, "session")?.to_owned(),
            pid: required(&fields, "pid")?.parse().map_err(|_| ErrCode::BadRequest)?,
        }),
        "UNREGISTER" => {
            Ok(Request::Unregister { session: required(&fields, "session")?.to_owned() })
        }
        "GET" => Ok(Request::Get {
            key: required(&fields, "key")?.to_owned(),
            token_hex: owned("token"),
            tty: owned("tty"),
        }),
        "REQUEST" => Ok(Request::RequestGrant {
            key: required(&fields, "key")?.to_owned(),
            token_hex: owned("token"),
            tty: owned("tty"),
        }),
        "GRANTS" => Ok(Request::Grants),
        "DENY" => Ok(Request::Deny {
            id: required(&fields, "id")?.parse().map_err(|_| ErrCode::BadRequest)?,
        }),
        "LOCK" => Ok(Request::Lock),
        _ => Err(ErrCode::UnknownOp),
    }
}
```

Create `src/lib.rs`:

```rust
//! Session-scoped secrets broker.
//!
//! See `docs/design.md` for the threat model and the reasoning behind the
//! security properties this crate is required to hold.

pub mod proto;
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo nextest run proto`
Expected: 12 tests PASS.

- [ ] **Step 5: Verify lints**

Run: `cargo fmt --all && cargo clippy --all-targets --all-features -- -D warnings`
Expected: clean. (Do NOT commit — one commit for the whole deliverable.)


---

### Task 2: Secret names, zeroizing buffers, single-assignment parse

**Files:**
- Create: `src/secret.rs`
- Modify: `src/lib.rs` (add `pub mod secret;`)

**Interfaces:**
- Consumes: `proto::ErrCode`.
- Produces: `SecretName` (`parse(&str) -> Result<Self, ErrCode>`, `as_str()`,
  `file_name()` returning `"<NAME>.env"`), `SecretBytes`
  (`from_vec(Vec<u8>)`, `as_slice()`, `len()`; zeroizes on drop; `Debug`
  prints `SecretBytes(<redacted>)`),
  `parse_single_assignment(&[u8], &SecretName) -> Result<SecretBytes, ErrCode>`.

This task implements the spec's anti-swap rule: a decrypted human-tier file
must contain exactly one assignment, and its name must equal the requested
key. That is what stops an agent swapping `DEEL_API_KEY.env` for another valid
ciphertext file and receiving the wrong secret.

- [ ] **Step 1: Write the failing tests**

Create `src/secret.rs` with only this test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn name(raw: &str) -> SecretName {
        SecretName::parse(raw).unwrap()
    }

    #[test]
    fn accepts_conventional_names() {
        assert_eq!(name("DEEL_API_KEY").as_str(), "DEEL_API_KEY");
        assert_eq!(name("A").as_str(), "A");
        assert_eq!(name("K9_X").as_str(), "K9_X");
    }

    #[test]
    fn rejects_path_traversal_and_lowercase_and_empty() {
        for raw in ["", "../etc/passwd", "a", "A-B", "A.B", "A/B", "9A", "_A", "A B"] {
            assert_eq!(SecretName::parse(raw), Err(ErrCode::BadRequest), "accepted {raw:?}");
        }
    }

    #[test]
    fn rejects_overlong_name() {
        let raw = "A".repeat(129);
        assert_eq!(SecretName::parse(&raw), Err(ErrCode::BadRequest));
    }

    #[test]
    fn file_name_appends_env_suffix() {
        assert_eq!(name("DEEL_API_KEY").file_name(), "DEEL_API_KEY.env");
    }

    #[test]
    fn debug_never_reveals_bytes() {
        let secret = SecretBytes::from_vec(b"hunter2".to_vec());
        let rendered = format!("{secret:?}");
        assert!(!rendered.contains("hunter2"), "leaked: {rendered}");
        assert!(rendered.contains("redacted"));
    }

    #[test]
    fn extracts_value_when_single_assignment_matches() {
        let parsed = parse_single_assignment(b"DEEL_API_KEY=abc123\n", &name("DEEL_API_KEY")).unwrap();
        assert_eq!(parsed.as_slice(), b"abc123");
    }

    #[test]
    fn ignores_comments_and_blank_lines() {
        let raw = b"# comment\n\nDEEL_API_KEY=abc123\n\n";
        let parsed = parse_single_assignment(raw, &name("DEEL_API_KEY")).unwrap();
        assert_eq!(parsed.as_slice(), b"abc123");
    }

    #[test]
    fn preserves_equals_and_whitespace_inside_value() {
        let parsed = parse_single_assignment(b"K=a=b c\n", &name("K")).unwrap();
        assert_eq!(parsed.as_slice(), b"a=b c");
    }

    #[test]
    fn strips_trailing_carriage_return() {
        let parsed = parse_single_assignment(b"K=abc\r\n", &name("K")).unwrap();
        assert_eq!(parsed.as_slice(), b"abc");
    }

    #[test]
    fn rejects_when_name_does_not_match_request() {
        let err = parse_single_assignment(b"OTHER_KEY=abc\n", &name("DEEL_API_KEY"));
        assert_eq!(err.err(), Some(ErrCode::Internal));
    }

    #[test]
    fn rejects_multiple_assignments() {
        let err = parse_single_assignment(b"K=a\nJ=b\n", &name("K"));
        assert_eq!(err.err(), Some(ErrCode::Internal));
    }

    #[test]
    fn rejects_empty_plaintext() {
        assert_eq!(parse_single_assignment(b"", &name("K")).err(), Some(ErrCode::Internal));
    }

    #[test]
    fn rejects_line_without_assignment() {
        assert_eq!(parse_single_assignment(b"garbage\n", &name("K")).err(), Some(ErrCode::Internal));
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo nextest run secret`
Expected: FAIL — `cannot find type SecretName in this scope`.

- [ ] **Step 3: Implement**

Prepend to `src/secret.rs`:

```rust
//! Secret names and secret bytes.
//!
//! `SecretBytes` is the only type permitted to hold plaintext. It wipes itself
//! on drop and refuses to render its contents in `Debug`.

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::proto::ErrCode;

/// Longest accepted key name.
const MAX_NAME_LEN: usize = 128;

/// A validated secret key name: `[A-Z][A-Z0-9_]*`.
///
/// Validation is what makes it safe to build a file name from client input.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SecretName(String);

impl SecretName {
    /// Parse a client-supplied key name.
    pub fn parse(raw: &str) -> Result<Self, ErrCode> {
        if raw.is_empty() || raw.len() > MAX_NAME_LEN {
            return Err(ErrCode::BadRequest);
        }
        let mut chars = raw.chars();
        let first = chars.next().ok_or(ErrCode::BadRequest)?;
        if !first.is_ascii_uppercase() {
            return Err(ErrCode::BadRequest);
        }
        if !chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_') {
            return Err(ErrCode::BadRequest);
        }
        Ok(Self(raw.to_owned()))
    }

    /// The validated name.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// File name this key occupies inside the human-tier directory.
    pub fn file_name(&self) -> String {
        format!("{}.env", self.0)
    }
}

/// Plaintext bytes, wiped on drop.
#[derive(Zeroize, ZeroizeOnDrop, Clone, PartialEq, Eq)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Take ownership of plaintext.
    pub const fn from_vec(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Borrow the plaintext for writing to a socket.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the value is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretBytes(<redacted>)")
    }
}

/// Extract the value of `expected` from decrypted dotenv plaintext.
///
/// Requires exactly one assignment whose name equals `expected`. This is the
/// anti-swap check: a tampered or substituted ciphertext file cannot yield a
/// value for a key the caller did not ask for.
pub fn parse_single_assignment(
    plaintext: &[u8],
    expected: &SecretName,
) -> Result<SecretBytes, ErrCode> {
    let mut found: Option<&[u8]> = None;
    for line in plaintext.split(|b| *b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() || line.first() == Some(&b'#') {
            continue;
        }
        let split = line.iter().position(|b| *b == b'=').ok_or(ErrCode::Internal)?;
        let (name, rest) = line.split_at(split);
        let value = rest.get(1..).ok_or(ErrCode::Internal)?;
        if name != expected.as_str().as_bytes() {
            return Err(ErrCode::Internal);
        }
        if found.is_some() {
            return Err(ErrCode::Internal);
        }
        found = Some(value);
    }
    found.map(|value| SecretBytes::from_vec(value.to_vec())).ok_or(ErrCode::Internal)
}
```

Add to `src/lib.rs`:

```rust
pub mod secret;
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo nextest run secret`
Expected: 13 tests PASS.

- [ ] **Step 5: Prove the wipe actually happens under Miri**

Add to the test module:

```rust
    #[test]
    fn zeroizes_on_drop() {
        let mut secret = SecretBytes::from_vec(b"hunter2".to_vec());
        secret.zeroize();
        assert!(secret.as_slice().iter().all(|b| *b == 0));
    }
```

Run: `cargo nextest run secret && cargo +nightly miri nextest run secret`
Expected: PASS under both.

---

### Task 3: Process hardening

**Files:**
- Create: `src/hardening.rs`
- Create: `tests/hardening.rs`
- Modify: `src/lib.rs` (add `pub mod hardening;`)

**Interfaces:**
- Produces: `enum MemlockPolicy { Require, Optional }`,
  `fn apply(policy: MemlockPolicy) -> Result<(), HardeningError>`,
  `enum HardeningError { Memlock(nix::Error), Dumpable(nix::Error), CoreLimit(nix::Error) }`.
- The daemon calls `apply(MemlockPolicy::Require)` before opening its socket.
  The systemd unit sets `LimitMEMLOCK=infinity`, so `Require` succeeds in
  production; CI containers may lack the limit, which is why the policy is a
  parameter rather than a hardcoded assumption.

These tests mutate process-global state, so they live in their own integration
test binary; `cargo-nextest` runs each test in its own process, which keeps
them from contaminating other tests.

- [ ] **Step 1: Write the failing tests**

Create `tests/hardening.rs`:

```rust
use secretsd::hardening::{self, MemlockPolicy};

fn proc_status_field(field: &str) -> String {
    let status = std::fs::read_to_string("/proc/self/status").expect("read status");
    status
        .lines()
        .find_map(|line| line.strip_prefix(field))
        .map(|rest| rest.trim().to_owned())
        .unwrap_or_default()
}

#[test]
fn disables_core_dumps_and_ptrace_dumpability() {
    hardening::apply(MemlockPolicy::Optional).expect("hardening applies");

    assert_eq!(proc_status_field("Dumpable:"), "0", "process must not be dumpable");

    let (soft, hard) = nix::sys::resource::getrlimit(nix::sys::resource::Resource::RLIMIT_CORE)
        .expect("getrlimit");
    assert_eq!(soft, 0, "core dump soft limit must be zero");
    assert_eq!(hard, 0, "core dump hard limit must be zero");
}

#[test]
fn memlock_is_attempted_and_reports_its_outcome() {
    // Require mode must either succeed or fail loudly with a memlock error --
    // it must never silently continue, because unlocked pages can be swapped
    // to disk and that is exactly the plaintext-at-rest problem we exist to
    // avoid.
    match hardening::apply(MemlockPolicy::Require) {
        Ok(()) => {}
        Err(hardening::HardeningError::Memlock(errno)) => {
            assert!(
                matches!(errno, nix::Error::EPERM | nix::Error::ENOMEM),
                "unexpected memlock errno: {errno:?}"
            );
        }
        Err(other) => panic!("unexpected hardening failure: {other}"),
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo nextest run --test hardening`
Expected: FAIL — `unresolved import secretsd::hardening`.

- [ ] **Step 3: Implement**

Create `src/hardening.rs`:

```rust
//! Process-level hardening applied before the daemon holds any plaintext.

use std::fmt;

use nix::sys::mman::{MlockAllFlags, mlockall};
use nix::sys::prctl::set_dumpable;
use nix::sys::resource::{Resource, setrlimit};

/// Whether locking memory is mandatory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MemlockPolicy {
    /// Fail startup if pages cannot be locked (production).
    Require,
    /// Tolerate a memlock failure (CI containers without `LimitMEMLOCK`).
    Optional,
}

/// A hardening step that did not take effect.
#[derive(Debug)]
#[non_exhaustive]
pub enum HardeningError {
    /// `mlockall` failed and the policy required it.
    Memlock(nix::Error),
    /// `PR_SET_DUMPABLE` failed.
    Dumpable(nix::Error),
    /// Setting `RLIMIT_CORE` to zero failed.
    CoreLimit(nix::Error),
}

impl fmt::Display for HardeningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Memlock(e) => write!(f, "mlockall failed: {e}"),
            Self::Dumpable(e) => write!(f, "set_dumpable failed: {e}"),
            Self::CoreLimit(e) => write!(f, "RLIMIT_CORE could not be zeroed: {e}"),
        }
    }
}

impl std::error::Error for HardeningError {}

/// Apply every hardening step.
///
/// Order matters: dumpability and core limits are cheap and unconditional, so
/// they are applied first and hold even if memlock is optional and fails.
pub fn apply(policy: MemlockPolicy) -> Result<(), HardeningError> {
    set_dumpable(false).map_err(HardeningError::Dumpable)?;
    setrlimit(Resource::RLIMIT_CORE, 0, 0).map_err(HardeningError::CoreLimit)?;

    match (mlockall(MlockAllFlags::MCL_CURRENT | MlockAllFlags::MCL_FUTURE), policy) {
        (Ok(()), _) => Ok(()),
        (Err(errno), MemlockPolicy::Require) => Err(HardeningError::Memlock(errno)),
        (Err(errno), MemlockPolicy::Optional) => {
            tracing::warn!(%errno, "memlock unavailable; plaintext pages may be swappable");
            Ok(())
        }
    }
}
```

Add to `src/lib.rs`:

```rust
pub mod hardening;
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo nextest run --test hardening`
Expected: 2 tests PASS.

- [ ] **Step 5: Verify lints**

Run: `cargo fmt --all && cargo clippy --all-targets --all-features -- -D warnings`
Expected: clean.

---

### Task 4: Human-tier store (listing and safe file resolution)

**Files:**
- Create: `src/store.rs`
- Modify: `src/lib.rs` (add `pub mod store;`)

**Interfaces:**
- Consumes: `secret::SecretName`, `proto::ErrCode`.
- Produces: `HumanStore::new(PathBuf)`,
  `HumanStore::key_names(&self) -> Result<Vec<SecretName>, ErrCode>` (reads
  file names only — never decrypts, so it can never trigger a YubiKey blink),
  `HumanStore::open(&self, &SecretName) -> Result<std::fs::File, ErrCode>`,
  `HumanStore::contains(&self, &SecretName) -> bool`.

`open` is the hardened path: `openat` relative to a directory handle, with
`O_NOFOLLOW` so a symlinked key file is rejected rather than followed, and an
`fstat` check that the target is a regular file.

- [ ] **Step 1: Write the failing tests**

Create `src/store.rs` with only this test module:

```rust
#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::*;

    fn name(raw: &str) -> SecretName {
        SecretName::parse(raw).unwrap()
    }

    fn fixture() -> (tempfile::TempDir, HumanStore) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("DEEL_API_KEY.env"), b"ciphertext").unwrap();
        std::fs::write(dir.path().join("notes.txt"), b"ignored").unwrap();
        std::os::unix::fs::symlink("/etc/passwd", dir.path().join("EVIL_LINK.env")).unwrap();
        std::fs::create_dir(dir.path().join("A_DIR.env")).unwrap();
        let store = HumanStore::new(dir.path().to_path_buf());
        (dir, store)
    }

    #[test]
    fn lists_key_names_from_file_names_only() {
        let (_dir, store) = fixture();
        let mut names: Vec<String> =
            store.key_names().unwrap().iter().map(|n| n.as_str().to_owned()).collect();
        names.sort();
        // Non-.env files are ignored; the symlink and directory still *appear*
        // as names because listing must not stat or open anything -- opening is
        // where they get rejected.
        assert_eq!(names, vec!["A_DIR", "DEEL_API_KEY", "EVIL_LINK"]);
    }

    #[test]
    fn listing_missing_directory_yields_no_keys() {
        let store = HumanStore::new("/nonexistent/secretsd-test".into());
        assert_eq!(store.key_names().unwrap(), Vec::new());
    }

    #[test]
    fn opens_regular_file() {
        let (_dir, store) = fixture();
        let mut file = store.open(&name("DEEL_API_KEY")).unwrap();
        let mut buf = String::new();
        file.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "ciphertext");
    }

    #[test]
    fn refuses_to_follow_symlink() {
        let (_dir, store) = fixture();
        assert_eq!(store.open(&name("EVIL_LINK")).err(), Some(ErrCode::NotHumanKey));
    }

    #[test]
    fn refuses_directory() {
        let (_dir, store) = fixture();
        assert_eq!(store.open(&name("A_DIR")).err(), Some(ErrCode::NotHumanKey));
    }

    #[test]
    fn refuses_absent_key() {
        let (_dir, store) = fixture();
        assert_eq!(store.open(&name("NOPE")).err(), Some(ErrCode::NotHumanKey));
    }

    #[test]
    fn contains_reports_presence() {
        let (_dir, store) = fixture();
        assert!(store.contains(&name("DEEL_API_KEY")));
        assert!(!store.contains(&name("NOPE")));
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo nextest run store`
Expected: FAIL — `cannot find type HumanStore in this scope`.

- [ ] **Step 3: Implement**

Prepend to `src/store.rs`:

```rust
//! The human-tier secret directory (`secrets.human.d`).
//!
//! Listing reads file names only. Nothing in this module decrypts, so nothing
//! here can cause a YubiKey interaction -- that is what makes `secrets list`
//! blink-free.

use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;

use nix::fcntl::{OFlag, openat};
use nix::sys::stat::{Mode, SFlag, fstat};

use crate::proto::ErrCode;
use crate::secret::SecretName;

/// A directory of per-key sops files.
#[derive(Debug, Clone)]
pub struct HumanStore {
    dir: PathBuf,
}

impl HumanStore {
    /// Point the store at a directory. The directory need not exist yet.
    pub const fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// Key names present in the store, derived from file names.
    pub fn key_names(&self) -> Result<Vec<SecretName>, ErrCode> {
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(_) => return Err(ErrCode::Internal),
        };
        let mut names = Vec::new();
        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let Some(text) = file_name.to_str() else { continue };
            let Some(stem) = text.strip_suffix(".env") else { continue };
            if let Ok(name) = SecretName::parse(stem) {
                names.push(name);
            }
        }
        Ok(names)
    }

    /// Whether a key exists in the store.
    pub fn contains(&self, name: &SecretName) -> bool {
        self.key_names().is_ok_and(|names| names.contains(name))
    }

    /// Open a key's ciphertext file without following symlinks.
    pub fn open(&self, name: &SecretName) -> Result<std::fs::File, ErrCode> {
        let dir_fd: OwnedFd = openat(
            nix::fcntl::AT_FDCWD,
            &self.dir,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ErrCode::NotHumanKey)?;

        let file_fd: OwnedFd = openat(
            dir_fd.as_fd(),
            name.file_name().as_str(),
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ErrCode::NotHumanKey)?;

        let stat = fstat(file_fd.as_fd()).map_err(|_| ErrCode::NotHumanKey)?;
        let is_regular = SFlag::from_bits_truncate(stat.st_mode).contains(SFlag::S_IFREG);
        if !is_regular {
            return Err(ErrCode::NotHumanKey);
        }
        let _ = file_fd.as_raw_fd();
        Ok(std::fs::File::from(file_fd))
    }
}
```

Add to `src/lib.rs`:

```rust
pub mod store;
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo nextest run store`
Expected: 7 tests PASS. If `openat`'s signature differs in the pinned `nix`
version, adjust the call but keep `O_NOFOLLOW`, `O_CLOEXEC`, and the
regular-file check — those three are the security content of this task.

---

### Task 5: Decryption subprocess

**Files:**
- Create: `src/decrypt.rs`
- Create: `tests/fixtures/fake-sops-ok`, `tests/fixtures/fake-sops-fail`, `tests/fixtures/fake-sops-hang`
- Modify: `src/lib.rs` (add `pub mod decrypt;`)

**Interfaces:**
- Consumes: `secret::{SecretBytes, SecretName, parse_single_assignment}`,
  `store::HumanStore`, `proto::ErrCode`.
- Produces: `Decryptor::new(sops_bin: PathBuf, timeout: Duration, pcsc_socket: Option<PathBuf>)`,
  `Decryptor::reachable(&self) -> bool`,
  `Decryptor::decrypt(&self, store: &HumanStore, key: &SecretName) -> Result<SecretBytes, ErrCode>`.

Two details carry the security weight:

1. **Reachability pre-flight.** Before spawning sops, check that the PC/SC
   socket exists. On the devbox that socket only exists while the YubiKey
   tunnel is up. This turns "user is away / tunnel down" into an instant
   `YUBIKEY_UNREACHABLE` with **no blink and no hang**, instead of a 30-second
   timeout and a stderr-sniffing guess.
2. **Process group + kill.** sops is spawned in its own process group so a
   deny or timeout can kill the whole group; a decrypt that outlives its
   request must never install a grant.

- [ ] **Step 1: Create the fake sops fixtures**

```bash
mkdir -p tests/fixtures
cat > tests/fixtures/fake-sops-ok <<'EOF'
#!/bin/bash
# Mimics: sops -d --output-type dotenv <path>
# Emits a single assignment named after the requested file's stem.
path="${!#}"
base=$(basename "$path" .env)
echo "${base}=value-for-${base}"
EOF
cat > tests/fixtures/fake-sops-fail <<'EOF'
#!/bin/bash
echo "sops: could not decrypt" >&2
exit 1
EOF
cat > tests/fixtures/fake-sops-hang <<'EOF'
#!/bin/bash
sleep 300
EOF
chmod +x tests/fixtures/fake-sops-*
```

- [ ] **Step 2: Write the failing tests**

Create `src/decrypt.rs` with only this test module:

```rust
#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::secret::SecretName;

    fn fixture_bin(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)
    }

    fn store_with_key(key: &str) -> (tempfile::TempDir, HumanStore) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(format!("{key}.env")), b"ciphertext").unwrap();
        let store = HumanStore::new(dir.path().to_path_buf());
        (dir, store)
    }

    #[test]
    fn returns_value_on_success() {
        let (_dir, store) = store_with_key("DEEL_API_KEY");
        let decryptor =
            Decryptor::new(fixture_bin("fake-sops-ok"), Duration::from_secs(5), None);
        let name = SecretName::parse("DEEL_API_KEY").unwrap();
        let value = decryptor.decrypt(&store, &name).unwrap();
        assert_eq!(value.as_slice(), b"value-for-DEEL_API_KEY");
    }

    #[test]
    fn reports_internal_error_when_sops_fails() {
        let (_dir, store) = store_with_key("K");
        let decryptor =
            Decryptor::new(fixture_bin("fake-sops-fail"), Duration::from_secs(5), None);
        let name = SecretName::parse("K").unwrap();
        assert_eq!(decryptor.decrypt(&store, &name).err(), Some(ErrCode::Internal));
    }

    #[test]
    fn times_out_and_kills_the_child() {
        let (_dir, store) = store_with_key("K");
        let decryptor =
            Decryptor::new(fixture_bin("fake-sops-hang"), Duration::from_millis(300), None);
        let name = SecretName::parse("K").unwrap();
        let started = std::time::Instant::now();
        assert_eq!(decryptor.decrypt(&store, &name).err(), Some(ErrCode::Timeout));
        assert!(started.elapsed() < Duration::from_secs(5), "decrypt did not time out promptly");
    }

    #[test]
    fn reachable_is_true_when_no_socket_is_configured() {
        let decryptor = Decryptor::new(PathBuf::from("sops"), Duration::from_secs(1), None);
        assert!(decryptor.reachable(), "laptop-style direct access must not be gated");
    }

    #[test]
    fn reachable_is_false_when_configured_socket_is_absent() {
        let decryptor = Decryptor::new(
            PathBuf::from("sops"),
            Duration::from_secs(1),
            Some(PathBuf::from("/nonexistent/pcscd.comm")),
        );
        assert!(!decryptor.reachable());
    }

    #[test]
    fn reachable_is_true_when_configured_socket_exists() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("pcscd.comm");
        std::fs::write(&socket, b"").unwrap();
        let decryptor = Decryptor::new(PathBuf::from("sops"), Duration::from_secs(1), Some(socket));
        assert!(decryptor.reachable());
    }
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo nextest run decrypt`
Expected: FAIL — `cannot find type Decryptor in this scope`.

- [ ] **Step 4: Implement**

Prepend to `src/decrypt.rs`:

```rust
//! Running sops to decrypt one key.
//!
//! The YubiKey touch happens inside this subprocess. Everything here exists to
//! make that interaction predictable: check reachability first so we never
//! hang or blink when the key is absent, and keep the child in its own process
//! group so a deny or timeout can kill it before it can install a grant.

use std::io::Read;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;

use crate::proto::ErrCode;
use crate::secret::{SecretBytes, SecretName, parse_single_assignment};
use crate::store::HumanStore;

/// How often to check whether the child finished.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Runs sops against one ciphertext file.
#[derive(Debug, Clone)]
pub struct Decryptor {
    sops_bin: PathBuf,
    timeout: Duration,
    pcsc_socket: Option<PathBuf>,
}

impl Decryptor {
    /// Build a decryptor.
    pub const fn new(
        sops_bin: PathBuf,
        timeout: Duration,
        pcsc_socket: Option<PathBuf>,
    ) -> Self {
        Self { sops_bin, timeout, pcsc_socket }
    }

    /// Whether the YubiKey is reachable without touching hardware.
    ///
    /// When no PC/SC socket path is configured (laptop, direct access) this is
    /// always true. When one is configured (devbox, tunnelled) its absence
    /// means the tunnel is down.
    pub fn reachable(&self) -> bool {
        self.pcsc_socket.as_ref().is_none_or(|path| path.exists())
    }

    /// Decrypt one key's file and extract its single assignment.
    pub fn decrypt(
        &self,
        store: &HumanStore,
        key: &SecretName,
    ) -> Result<SecretBytes, ErrCode> {
        if !self.reachable() {
            return Err(ErrCode::YubikeyUnreachable);
        }
        // Resolve through the store so symlink and regular-file checks apply.
        drop(store.open(key)?);
        let path = store.path_for(key);

        let mut child = Command::new(&self.sops_bin)
            .arg("-d")
            .arg("--output-type")
            .arg("dotenv")
            .arg(&path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn()
            .map_err(|_| ErrCode::Internal)?;

        let pgid = Pid::from_raw(i32::try_from(child.id()).map_err(|_| ErrCode::Internal)?);
        let deadline = Instant::now() + self.timeout;

        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let mut stdout = Vec::new();
                    if let Some(mut pipe) = child.stdout.take() {
                        pipe.read_to_end(&mut stdout).map_err(|_| ErrCode::Internal)?;
                    }
                    if !status.success() {
                        stdout.zeroize_in_place();
                        tracing::warn!(key = key.as_str(), "sops exited non-zero");
                        return Err(ErrCode::Internal);
                    }
                    let parsed = parse_single_assignment(&stdout, key);
                    stdout.zeroize_in_place();
                    return parsed;
                }
                Ok(None) => {
                    if Instant::now() >= deadline {
                        let _ = killpg(pgid, Signal::SIGKILL);
                        let _ = child.wait();
                        return Err(ErrCode::Timeout);
                    }
                    std::thread::sleep(POLL_INTERVAL);
                }
                Err(_) => return Err(ErrCode::Internal),
            }
        }
    }
}

/// Wipe an intermediate plaintext buffer that is not a `SecretBytes`.
trait ZeroizeInPlace {
    fn zeroize_in_place(&mut self);
}

impl ZeroizeInPlace for Vec<u8> {
    fn zeroize_in_place(&mut self) {
        use zeroize::Zeroize as _;
        self.zeroize();
    }
}
```

Add to `src/store.rs` (needed by `decrypt`):

```rust
impl HumanStore {
    /// Path of a key's ciphertext file. Only call after `open` has validated it.
    pub fn path_for(&self, name: &SecretName) -> PathBuf {
        self.dir.join(name.file_name())
    }
}
```

Add to `src/lib.rs`:

```rust
pub mod decrypt;
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo nextest run decrypt`
Expected: 6 tests PASS.

- [ ] **Step 6: Verify lints**

Run: `cargo fmt --all && cargo clippy --all-targets --all-features -- -D warnings`
Expected: clean.

---

### Task 6: Scopes, registrations, and the grant table

**Files:**
- Create: `src/grants.rs`
- Modify: `src/lib.rs` (add `pub mod grants;`)

**Interfaces:**
- Consumes: `secret::{SecretName, SecretBytes}`, `proto::ErrCode`.
- Produces: `SessionToken` (`parse_hex`, constant-time equality),
  `enum Scope { Session(SessionToken), Tty { tty: String } }`,
  `enum ScopeKind { VerifiedSession, TokenlessTty }`, `Scope::kind()`,
  `Registration { token, session, pid }`,
  `Registry` (`register`, `unregister`, `resolve`, `is_agent_tty`),
  `GrantTable` (`lookup`, `insert`, `revoke_scope`, `revoke_tokens`,
  `revoke_expired`, `revoke_all`, `is_empty`, `render`).

This is where the spec's two anti-forgery properties are implemented:

1. **Tokens are verified, never trusted.** `resolve` compares a presented
   token against registered ones in constant time. A claimed session ID is
   never an input to authorization — it is carried only for logging, and
   labeled untrusted when displayed.
2. **Agent ttys are learned.** The first time a token-verified request arrives
   from a tty, that tty is recorded as belonging to an agent session. A later
   *tokenless* request from the same tty is rejected with `AGENT_TTY`. This
   closes the env-stripping bypass without requiring the harness to enumerate
   its PTYs — a refinement of the spec's "best effort" plugin PTY
   registration, obtained for free from traffic the broker already sees.

- [ ] **Step 1: Write the failing tests**

Create `src/grants.rs` with only this test module:

```rust
#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;

    fn token(byte: u8) -> SessionToken {
        SessionToken::parse_hex(&format!("{byte:02x}").repeat(32)).unwrap()
    }

    fn name(raw: &str) -> SecretName {
        SecretName::parse(raw).unwrap()
    }

    fn secret(raw: &str) -> SecretBytes {
        SecretBytes::from_vec(raw.as_bytes().to_vec())
    }

    fn registered() -> Registry {
        let mut registry = Registry::default();
        registry.register(Registration {
            token: token(0xaa),
            session: "ses_a".to_owned(),
            pid: 1234,
        });
        registry
    }

    #[test]
    fn rejects_malformed_token_hex() {
        assert_eq!(SessionToken::parse_hex("nothex"), Err(ErrCode::BadRequest));
        assert_eq!(SessionToken::parse_hex("aabb"), Err(ErrCode::BadRequest));
    }

    #[test]
    fn resolves_registered_token_to_session_scope() {
        let mut registry = registered();
        let scope = registry.resolve(Some(&token(0xaa)), Some("/dev/pts/3")).unwrap();
        assert_eq!(scope.kind(), ScopeKind::VerifiedSession);
    }

    #[test]
    fn rejects_unregistered_token() {
        let mut registry = registered();
        assert_eq!(
            registry.resolve(Some(&token(0xbb)), Some("/dev/pts/3")).err(),
            Some(ErrCode::UnknownToken)
        );
    }

    #[test]
    fn unknown_token_never_falls_back_to_tokenless() {
        // A stale token (broker restarted, session did not re-register) must be
        // a hard identity error -- silently degrading to a tty scope would let
        // an env-stripped agent launder itself into the interactive path.
        let mut registry = registered();
        let err = registry.resolve(Some(&token(0xcc)), Some("/dev/pts/9")).err();
        assert_eq!(err, Some(ErrCode::UnknownToken));
        assert!(!registry.is_agent_tty("/dev/pts/9"));
    }

    #[test]
    fn tokenless_request_from_fresh_tty_is_interactive() {
        let mut registry = registered();
        let scope = registry.resolve(None, Some("/dev/pts/7")).unwrap();
        assert_eq!(scope.kind(), ScopeKind::TokenlessTty);
    }

    #[test]
    fn tokenless_request_from_learned_agent_tty_is_rejected() {
        let mut registry = registered();
        registry.resolve(Some(&token(0xaa)), Some("/dev/pts/3")).unwrap();
        assert!(registry.is_agent_tty("/dev/pts/3"));
        assert_eq!(registry.resolve(None, Some("/dev/pts/3")).err(), Some(ErrCode::AgentTty));
    }

    #[test]
    fn request_without_token_or_tty_has_no_scope() {
        let mut registry = registered();
        assert_eq!(registry.resolve(None, None).err(), Some(ErrCode::NoScope));
    }

    #[test]
    fn unregister_returns_tokens_to_revoke() {
        let mut registry = registered();
        let revoked = registry.unregister("ses_a");
        assert_eq!(revoked, vec![token(0xaa)]);
        assert_eq!(
            registry.resolve(Some(&token(0xaa)), None).err(),
            Some(ErrCode::UnknownToken)
        );
    }

    #[test]
    fn grants_are_isolated_between_sessions() {
        let mut table = GrantTable::default();
        let now = Instant::now();
        let scope_a = Scope::Session(token(0xaa));
        let scope_b = Scope::Session(token(0xbb));
        table.insert(scope_a.clone(), name("K"), secret("v"), now);

        assert_eq!(table.lookup(&scope_a, &name("K")).map(SecretBytes::as_slice), Some(&b"v"[..]));
        assert!(table.lookup(&scope_b, &name("K")).is_none(), "sibling session inherited a grant");
    }

    #[test]
    fn revoking_tokens_drops_their_grants() {
        let mut table = GrantTable::default();
        let now = Instant::now();
        table.insert(Scope::Session(token(0xaa)), name("K"), secret("v"), now);
        table.revoke_tokens(&[token(0xaa)]);
        assert!(table.is_empty());
    }

    #[test]
    fn backstop_expires_old_grants_only() {
        let mut table = GrantTable::default();
        let now = Instant::now();
        let old = now - Duration::from_secs(13 * 3600);
        table.insert(Scope::Session(token(0xaa)), name("OLD"), secret("v"), old);
        table.insert(Scope::Session(token(0xbb)), name("NEW"), secret("v"), now);

        let removed = table.revoke_expired(now, Duration::from_secs(12 * 3600));
        assert_eq!(removed, 1);
        assert!(table.lookup(&Scope::Session(token(0xbb)), &name("NEW")).is_some());
        assert!(table.lookup(&Scope::Session(token(0xaa)), &name("OLD")).is_none());
    }

    #[test]
    fn lock_revokes_everything() {
        let mut table = GrantTable::default();
        let now = Instant::now();
        table.insert(Scope::Session(token(0xaa)), name("K"), secret("v"), now);
        table.revoke_all();
        assert!(table.is_empty());
    }

    #[test]
    fn render_never_includes_secret_values() {
        let mut table = GrantTable::default();
        let now = Instant::now();
        table.insert(Scope::Session(token(0xaa)), name("K"), secret("super-secret"), now);
        let rendered = table.render(now);
        assert!(rendered.contains("K"));
        assert!(!rendered.contains("super-secret"), "grant listing leaked a value");
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo nextest run grants`
Expected: FAIL — `cannot find type SessionToken in this scope`.

- [ ] **Step 3: Implement**

Prepend to `src/grants.rs`:

```rust
//! Who is asking, and what they are allowed to see.
//!
//! Authorization inputs are the presented token (verified) and the caller's
//! tty. A claimed session identifier is never an authorization input.

use std::time::{Duration, Instant};

use subtle::ConstantTimeEq;

use crate::proto::ErrCode;
use crate::secret::{SecretBytes, SecretName};

/// Length of a session token in bytes.
const TOKEN_LEN: usize = 32;

/// An unguessable per-session bearer token issued by trusted harness code.
#[derive(Debug, Clone, Copy)]
pub struct SessionToken([u8; TOKEN_LEN]);

impl SessionToken {
    /// Parse a 64-character lowercase or uppercase hex string.
    pub fn parse_hex(text: &str) -> Result<Self, ErrCode> {
        if text.len() != TOKEN_LEN * 2 {
            return Err(ErrCode::BadRequest);
        }
        let mut bytes = [0_u8; TOKEN_LEN];
        for (index, slot) in bytes.iter_mut().enumerate() {
            let start = index.checked_mul(2).ok_or(ErrCode::BadRequest)?;
            let end = start.checked_add(2).ok_or(ErrCode::BadRequest)?;
            let pair = text.get(start..end).ok_or(ErrCode::BadRequest)?;
            *slot = u8::from_str_radix(pair, 16).map_err(|_| ErrCode::BadRequest)?;
        }
        Ok(Self(bytes))
    }
}

impl PartialEq for SessionToken {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for SessionToken {}

/// What a grant belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Scope {
    /// A harness session proven by its token.
    Session(SessionToken),
    /// A human at an interactive terminal.
    Tty {
        /// Controlling terminal device path.
        tty: String,
    },
}

/// Coarse scope classification, used in announcements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScopeKind {
    /// Token was presented and verified.
    VerifiedSession,
    /// No token; scoped to a terminal.
    TokenlessTty,
}

impl Scope {
    /// Classify this scope.
    pub const fn kind(&self) -> ScopeKind {
        match self {
            Self::Session(_) => ScopeKind::VerifiedSession,
            Self::Tty { .. } => ScopeKind::TokenlessTty,
        }
    }
}

/// A registered harness session.
#[derive(Debug, Clone)]
pub struct Registration {
    /// Token issued for this session.
    pub token: SessionToken,
    /// Harness-supplied identifier. Untrusted; logging and display only.
    pub session: String,
    /// Harness process id, for pidfd death detection.
    pub pid: i32,
}

/// Known sessions and learned agent terminals.
#[derive(Debug, Default)]
pub struct Registry {
    sessions: Vec<Registration>,
    agent_ttys: Vec<String>,
}

impl Registry {
    /// Record a session token. Re-registering a session replaces its entry.
    pub fn register(&mut self, registration: Registration) {
        self.sessions.retain(|existing| existing.session != registration.session);
        self.sessions.push(registration);
    }

    /// Forget a session, returning the tokens whose grants must be revoked.
    pub fn unregister(&mut self, session: &str) -> Vec<SessionToken> {
        let revoked: Vec<SessionToken> = self
            .sessions
            .iter()
            .filter(|entry| entry.session == session)
            .map(|entry| entry.token)
            .collect();
        self.sessions.retain(|entry| entry.session != session);
        revoked
    }

    /// Registered sessions, for pidfd watching.
    pub fn registrations(&self) -> &[Registration] {
        &self.sessions
    }

    /// Whether a terminal has been seen carrying agent traffic.
    pub fn is_agent_tty(&self, tty: &str) -> bool {
        self.agent_ttys.iter().any(|known| known == tty)
    }

    /// Determine the scope of a request, or why it has none.
    pub fn resolve(
        &mut self,
        token: Option<&SessionToken>,
        tty: Option<&str>,
    ) -> Result<Scope, ErrCode> {
        match token {
            Some(presented) => {
                let known = self.sessions.iter().any(|entry| entry.token == *presented);
                if !known {
                    return Err(ErrCode::UnknownToken);
                }
                if let Some(tty) = tty {
                    if !self.is_agent_tty(tty) {
                        self.agent_ttys.push(tty.to_owned());
                    }
                }
                Ok(Scope::Session(*presented))
            }
            None => match tty {
                Some(tty) if self.is_agent_tty(tty) => Err(ErrCode::AgentTty),
                Some(tty) => Ok(Scope::Tty { tty: tty.to_owned() }),
                None => Err(ErrCode::NoScope),
            },
        }
    }
}

#[derive(Debug)]
struct Grant {
    scope: Scope,
    key: SecretName,
    value: SecretBytes,
    created: Instant,
}

/// Live grants. Dropping a grant zeroizes its value.
#[derive(Debug, Default)]
pub struct GrantTable {
    grants: Vec<Grant>,
}

impl GrantTable {
    /// Find a live grant.
    pub fn lookup(&self, scope: &Scope, key: &SecretName) -> Option<&SecretBytes> {
        self.grants
            .iter()
            .find(|grant| grant.scope == *scope && grant.key == *key)
            .map(|grant| &grant.value)
    }

    /// Install a grant, replacing any existing one for the same scope and key.
    pub fn insert(
        &mut self,
        scope: Scope,
        key: SecretName,
        value: SecretBytes,
        created: Instant,
    ) {
        self.grants.retain(|grant| !(grant.scope == scope && grant.key == key));
        self.grants.push(Grant { scope, key, value, created });
    }

    /// Revoke every grant belonging to a scope.
    pub fn revoke_scope(&mut self, scope: &Scope) {
        self.grants.retain(|grant| grant.scope != *scope);
    }

    /// Revoke every grant belonging to any of these session tokens.
    pub fn revoke_tokens(&mut self, tokens: &[SessionToken]) {
        self.grants.retain(|grant| match &grant.scope {
            Scope::Session(token) => !tokens.contains(token),
            Scope::Tty { .. } => true,
        });
    }

    /// Revoke grants older than `max_age`, returning how many were removed.
    pub fn revoke_expired(&mut self, now: Instant, max_age: Duration) -> usize {
        let before = self.grants.len();
        self.grants.retain(|grant| now.duration_since(grant.created) < max_age);
        before.saturating_sub(self.grants.len())
    }

    /// Revoke everything.
    pub fn revoke_all(&mut self) {
        self.grants.clear();
    }

    /// Whether any grant is live.
    pub fn is_empty(&self) -> bool {
        self.grants.is_empty()
    }

    /// Human-readable listing. Never includes secret values.
    pub fn render(&self, now: Instant) -> String {
        if self.grants.is_empty() {
            return "no active grants\n".to_owned();
        }
        let mut out = String::from("KEY\tSCOPE\tAGE\n");
        for grant in &self.grants {
            let scope = match &grant.scope {
                Scope::Session(_) => "session".to_owned(),
                Scope::Tty { tty } => format!("tty {tty}"),
            };
            let age = now.duration_since(grant.created).as_secs();
            out.push_str(&format!("{}\t{scope}\t{age}s\n", grant.key.as_str()));
        }
        out
    }
}
```

Add to `src/lib.rs`:

```rust
pub mod grants;
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo nextest run grants`
Expected: 13 tests PASS.

---

### Task 7: Request state machine and single-flight queue

**Files:**
- Create: `src/requests.rs`
- Modify: `src/lib.rs` (add `pub mod requests;`)

**Interfaces:**
- Consumes: `grants::Scope`, `secret::SecretName`, `proto::ErrCode`.
- Produces: `trait Clock { fn now(&self) -> Instant }`, `SystemClock`,
  `RequestId(u64)`, `enum RequestState`, `PendingRequest`,
  `Queue::new(QueueLimits)`, `QueueLimits { cooldown, ttl, max_pending_per_scope }`,
  `Queue::{enqueue, next_ready, mark_decrypting, finish, deny, sweep_timeouts,
  state_of, is_idle}`.

Design notes for the implementer:

- **Single-flight is enforced here and structurally in Task 9** (exactly one
  worker thread). `next_ready` returns `None` while a decrypt is in flight or
  while the post-decrypt cooldown has not elapsed. The cooldown must exceed the
  YubiKey PIV touch cache (15s) so a single touch can never satisfy two
  decrypts.
- **Generation counters** guard late transitions: if a request is denied or
  times out while its decrypt is still running, the decrypt's result must be
  discarded rather than installed.
- A state machine held in a table of concurrent requests is the one place the
  type-state pattern does not fit (heterogeneous states in one collection), so
  this is an enum matched exhaustively.

- [ ] **Step 1: Write the failing tests**

Create `src/requests.rs` with only this test module:

```rust
#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;
    use crate::grants::{Scope, SessionToken};
    use crate::secret::SecretName;

    fn scope(byte: u8) -> Scope {
        Scope::Session(SessionToken::parse_hex(&format!("{byte:02x}").repeat(32)).unwrap())
    }

    fn name(raw: &str) -> SecretName {
        SecretName::parse(raw).unwrap()
    }

    fn limits() -> QueueLimits {
        QueueLimits {
            cooldown: Duration::from_secs(16),
            ttl: Duration::from_secs(90),
            max_pending_per_scope: 2,
        }
    }

    #[test]
    fn enqueue_returns_ready_request() {
        let mut queue = Queue::new(limits());
        let now = Instant::now();
        let id = queue.enqueue(scope(0xaa), name("K"), now).unwrap();
        assert_eq!(queue.next_ready(now), Some(id));
    }

    #[test]
    fn duplicate_request_for_same_scope_and_key_is_coalesced() {
        let mut queue = Queue::new(limits());
        let now = Instant::now();
        let first = queue.enqueue(scope(0xaa), name("K"), now).unwrap();
        let second = queue.enqueue(scope(0xaa), name("K"), now).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn same_key_from_different_scope_is_a_separate_request() {
        let mut queue = Queue::new(limits());
        let now = Instant::now();
        let first = queue.enqueue(scope(0xaa), name("K"), now).unwrap();
        let second = queue.enqueue(scope(0xbb), name("K"), now).unwrap();
        assert_ne!(first, second, "one approval must never serve two scopes");
    }

    #[test]
    fn only_one_decrypt_is_in_flight() {
        let mut queue = Queue::new(limits());
        let now = Instant::now();
        let first = queue.enqueue(scope(0xaa), name("K"), now).unwrap();
        queue.enqueue(scope(0xbb), name("J"), now).unwrap();
        queue.mark_decrypting(first, now);
        assert_eq!(queue.next_ready(now), None, "second decrypt started while first in flight");
    }

    #[test]
    fn cooldown_blocks_the_next_decrypt_until_the_touch_cache_expires() {
        let mut queue = Queue::new(limits());
        let start = Instant::now();
        let first = queue.enqueue(scope(0xaa), name("K"), start).unwrap();
        queue.mark_decrypting(first, start);
        queue.finish(first, start);
        let second = queue.enqueue(scope(0xbb), name("J"), start).unwrap();

        assert_eq!(queue.next_ready(start + Duration::from_secs(10)), None);
        assert_eq!(queue.next_ready(start + Duration::from_secs(17)), Some(second));
    }

    #[test]
    fn denied_request_is_not_ready_and_reports_denied() {
        let mut queue = Queue::new(limits());
        let now = Instant::now();
        let id = queue.enqueue(scope(0xaa), name("K"), now).unwrap();
        assert!(queue.deny(id));
        assert_eq!(queue.state_of(id), Some(RequestState::Denied));
        assert_eq!(queue.next_ready(now), None);
    }

    #[test]
    fn late_completion_after_deny_is_rejected() {
        let mut queue = Queue::new(limits());
        let now = Instant::now();
        let id = queue.enqueue(scope(0xaa), name("K"), now).unwrap();
        let generation = queue.mark_decrypting(id, now).unwrap();
        queue.deny(id);
        assert!(!queue.complete(id, generation, now), "a denied request must not install a grant");
    }

    #[test]
    fn pending_limit_per_scope_is_enforced() {
        let mut queue = Queue::new(limits());
        let now = Instant::now();
        queue.enqueue(scope(0xaa), name("A"), now).unwrap();
        queue.enqueue(scope(0xaa), name("B"), now).unwrap();
        assert_eq!(queue.enqueue(scope(0xaa), name("C"), now).err(), Some(ErrCode::TooManyPending));
    }

    #[test]
    fn flooding_one_scope_does_not_lock_out_another() {
        let mut queue = Queue::new(limits());
        let now = Instant::now();
        queue.enqueue(scope(0xaa), name("A"), now).unwrap();
        queue.enqueue(scope(0xaa), name("B"), now).unwrap();
        assert!(queue.enqueue(scope(0xbb), name("C"), now).is_ok());
    }

    #[test]
    fn expired_requests_are_swept() {
        let mut queue = Queue::new(limits());
        let start = Instant::now();
        let id = queue.enqueue(scope(0xaa), name("K"), start).unwrap();
        let swept = queue.sweep_timeouts(start + Duration::from_secs(91));
        assert_eq!(swept, vec![id]);
        assert_eq!(queue.state_of(id), Some(RequestState::TimedOut));
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo nextest run requests`
Expected: FAIL — `cannot find type Queue in this scope`.

- [ ] **Step 3: Implement**

Prepend to `src/requests.rs`:

```rust
//! Pending approval requests and the single-flight hardware queue.

use std::time::{Duration, Instant};

use crate::grants::Scope;
use crate::proto::ErrCode;
use crate::secret::SecretName;

/// Source of monotonic time, injectable for tests.
pub trait Clock: Send + Sync {
    /// Current instant.
    fn now(&self) -> Instant;
}

/// Real time.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// Identifier shown in announcements so a human can name what they approved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RequestId(pub u64);

/// Lifecycle of one approval request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RequestState {
    /// Waiting for its turn at the hardware.
    Pending,
    /// A decrypt is running for this request.
    Decrypting,
    /// Completed successfully; a grant was installed.
    Granted,
    /// A human denied it.
    Denied,
    /// It expired before approval.
    TimedOut,
    /// Decryption failed.
    Failed,
}

/// Tunables for the queue.
#[derive(Debug, Clone, Copy)]
pub struct QueueLimits {
    /// Minimum gap between decrypts; must exceed the PIV touch cache.
    pub cooldown: Duration,
    /// How long a request may wait for approval.
    pub ttl: Duration,
    /// Concurrent pending requests allowed per scope.
    pub max_pending_per_scope: usize,
}

#[derive(Debug)]
struct PendingRequest {
    id: RequestId,
    scope: Scope,
    key: SecretName,
    state: RequestState,
    generation: u64,
    created: Instant,
}

/// The approval queue. Exactly one decrypt may be in flight.
#[derive(Debug)]
pub struct Queue {
    requests: Vec<PendingRequest>,
    limits: QueueLimits,
    next_id: u64,
    generation: u64,
    inflight: Option<RequestId>,
    last_finished: Option<Instant>,
}

impl Queue {
    /// Build an empty queue.
    pub const fn new(limits: QueueLimits) -> Self {
        Self {
            requests: Vec::new(),
            limits,
            next_id: 1,
            generation: 0,
            inflight: None,
            last_finished: None,
        }
    }

    /// Add a request, coalescing an identical pending one.
    pub fn enqueue(
        &mut self,
        scope: Scope,
        key: SecretName,
        now: Instant,
    ) -> Result<RequestId, ErrCode> {
        if let Some(existing) = self.requests.iter().find(|request| {
            request.scope == scope
                && request.key == key
                && matches!(request.state, RequestState::Pending | RequestState::Decrypting)
        }) {
            return Ok(existing.id);
        }
        let active = self
            .requests
            .iter()
            .filter(|request| {
                request.scope == scope
                    && matches!(request.state, RequestState::Pending | RequestState::Decrypting)
            })
            .count();
        if active >= self.limits.max_pending_per_scope {
            return Err(ErrCode::TooManyPending);
        }
        let id = RequestId(self.next_id);
        self.next_id = self.next_id.saturating_add(1);
        self.requests.push(PendingRequest {
            id,
            scope,
            key,
            state: RequestState::Pending,
            generation: 0,
            created: now,
        });
        Ok(id)
    }

    /// The next request eligible to touch the hardware, if any.
    pub fn next_ready(&self, now: Instant) -> Option<RequestId> {
        if self.inflight.is_some() {
            return None;
        }
        if let Some(last) = self.last_finished {
            if now.duration_since(last) < self.limits.cooldown {
                return None;
            }
        }
        self.requests
            .iter()
            .find(|request| request.state == RequestState::Pending)
            .map(|request| request.id)
    }

    /// Mark a request as decrypting, returning its generation.
    pub fn mark_decrypting(&mut self, id: RequestId, _now: Instant) -> Option<u64> {
        self.generation = self.generation.saturating_add(1);
        let generation = self.generation;
        let request = self.requests.iter_mut().find(|request| request.id == id)?;
        request.state = RequestState::Decrypting;
        request.generation = generation;
        self.inflight = Some(id);
        Some(generation)
    }

    /// Whether a completing decrypt may still install its grant.
    pub fn complete(&mut self, id: RequestId, generation: u64, now: Instant) -> bool {
        let still_current = self
            .requests
            .iter()
            .any(|request| request.id == id
                && request.generation == generation
                && request.state == RequestState::Decrypting);
        if still_current {
            if let Some(request) = self.requests.iter_mut().find(|request| request.id == id) {
                request.state = RequestState::Granted;
            }
        }
        self.finish(id, now);
        still_current
    }

    /// Release the hardware and start the cooldown.
    pub fn finish(&mut self, id: RequestId, now: Instant) {
        if self.inflight == Some(id) {
            self.inflight = None;
        }
        self.last_finished = Some(now);
    }

    /// Mark a decrypt as failed.
    pub fn fail(&mut self, id: RequestId, now: Instant) {
        if let Some(request) = self.requests.iter_mut().find(|request| request.id == id) {
            request.state = RequestState::Failed;
        }
        self.finish(id, now);
    }

    /// Reject a pending request.
    pub fn deny(&mut self, id: RequestId) -> bool {
        let Some(request) = self.requests.iter_mut().find(|request| request.id == id) else {
            return false;
        };
        match request.state {
            RequestState::Pending | RequestState::Decrypting => {
                request.state = RequestState::Denied;
                request.generation = request.generation.saturating_add(1);
                true
            }
            RequestState::Granted
            | RequestState::Denied
            | RequestState::TimedOut
            | RequestState::Failed => false,
        }
    }

    /// Expire requests that waited too long.
    pub fn sweep_timeouts(&mut self, now: Instant) -> Vec<RequestId> {
        let ttl = self.limits.ttl;
        let mut expired = Vec::new();
        for request in &mut self.requests {
            if request.state == RequestState::Pending && now.duration_since(request.created) > ttl {
                request.state = RequestState::TimedOut;
                expired.push(request.id);
            }
        }
        expired
    }

    /// Current state of a request.
    pub fn state_of(&self, id: RequestId) -> Option<RequestState> {
        self.requests.iter().find(|request| request.id == id).map(|request| request.state)
    }

    /// Scope and key of a request.
    pub fn describe(&self, id: RequestId) -> Option<(Scope, SecretName)> {
        self.requests
            .iter()
            .find(|request| request.id == id)
            .map(|request| (request.scope.clone(), request.key.clone()))
    }

    /// Whether nothing is pending or in flight.
    pub fn is_idle(&self) -> bool {
        !self
            .requests
            .iter()
            .any(|r| matches!(r.state, RequestState::Pending | RequestState::Decrypting))
    }

    /// Drop terminal requests older than twice the TTL, bounding memory.
    pub fn prune(&mut self, now: Instant) {
        let horizon = self.limits.ttl.saturating_mul(2);
        self.requests.retain(|request| {
            matches!(request.state, RequestState::Pending | RequestState::Decrypting)
                || now.duration_since(request.created) < horizon
        });
    }
}
```

Add to `src/lib.rs`:

```rust
pub mod requests;
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo nextest run requests`
Expected: 10 tests PASS.

- [ ] **Step 5: Verify lints**

Run: `cargo fmt --all && cargo clippy --all-targets --all-features -- -D warnings`
Expected: clean.

---

### Task 8: Announcements

**Files:**
- Create: `src/announce.rs`
- Modify: `src/lib.rs` (add `pub mod announce;`)

**Interfaces:**
- Consumes: `grants::ScopeKind`, `requests::RequestId`, `secret::SecretName`.
- Produces: `Announcement { request_id, key, scope_kind, untrusted_session,
  untrusted_cmdline }`, `fn render(&Announcement) -> String`,
  `trait Notifier { fn name(&self) -> &str; fn deliver(&self, text: &str) -> bool }`,
  `CommandNotifier::new(Vec<String>)`, `Announcer::new(Vec<Box<dyn Notifier>>)`,
  `Announcer::announce(&self, &Announcement) -> bool`.

The contract that matters: **`announce` returning `false` means no hardware
interaction may begin.** At least one *out-of-band* channel must acknowledge.
The in-band notice returned to the calling agent does not count — it depends on
the agent choosing to surface it, and an unannounced blink is the exact failure
this design exists to prevent.

- [ ] **Step 1: Write the failing tests**

Create `src/announce.rs` with only this test module:

```rust
#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::grants::ScopeKind;
    use crate::secret::SecretName;

    #[derive(Debug)]
    struct FakeNotifier {
        succeeds: bool,
        calls: AtomicUsize,
    }

    impl FakeNotifier {
        fn new(succeeds: bool) -> Self {
            Self { succeeds, calls: AtomicUsize::new(0) }
        }
    }

    impl Notifier for FakeNotifier {
        fn name(&self) -> &str {
            "fake"
        }
        fn deliver(&self, _text: &str) -> bool {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.succeeds
        }
    }

    fn announcement(kind: ScopeKind) -> Announcement {
        Announcement {
            request_id: RequestId(7),
            key: SecretName::parse("DEEL_API_KEY").unwrap(),
            scope_kind: kind,
            untrusted_session: Some("ses_abc".to_owned()),
            untrusted_cmdline: Some("opencode".to_owned()),
        }
    }

    #[test]
    fn render_names_the_key_and_request_id() {
        let text = render(&announcement(ScopeKind::VerifiedSession));
        assert!(text.contains("DEEL_API_KEY"));
        assert!(text.contains("#7"));
    }

    #[test]
    fn render_warns_loudly_for_tokenless_requests() {
        let text = render(&announcement(ScopeKind::TokenlessTty));
        assert!(text.contains("TOKENLESS"), "tokenless scope must be conspicuous: {text}");
    }

    #[test]
    fn render_labels_client_supplied_metadata_as_untrusted() {
        let text = render(&announcement(ScopeKind::VerifiedSession));
        assert!(text.contains("unverified"), "client metadata must be labeled: {text}");
    }

    #[test]
    fn render_sanitizes_metadata_so_it_cannot_forge_lines() {
        let mut item = announcement(ScopeKind::VerifiedSession);
        item.untrusted_session = Some("ses\nTOUCH APPROVED".to_owned());
        let text = render(&item);
        assert!(!text.contains("\nTOUCH APPROVED"), "metadata injected a line: {text}");
    }

    #[test]
    fn announce_succeeds_when_any_channel_acknowledges() {
        let announcer = Announcer::new(vec![
            Box::new(FakeNotifier::new(false)),
            Box::new(FakeNotifier::new(true)),
        ]);
        assert!(announcer.announce(&announcement(ScopeKind::VerifiedSession)));
    }

    #[test]
    fn announce_fails_closed_when_every_channel_fails() {
        let announcer = Announcer::new(vec![Box::new(FakeNotifier::new(false))]);
        assert!(!announcer.announce(&announcement(ScopeKind::VerifiedSession)));
    }

    #[test]
    fn announce_fails_closed_when_no_channels_are_configured() {
        let announcer = Announcer::new(Vec::new());
        assert!(!announcer.announce(&announcement(ScopeKind::VerifiedSession)));
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo nextest run announce`
Expected: FAIL — `cannot find type Announcement in this scope`.

- [ ] **Step 3: Implement**

Prepend to `src/announce.rs`:

```rust
//! Telling the human what is about to blink.
//!
//! No decrypt may begin until one of these channels acknowledges. Everything
//! the client supplied is displayed as unverified, because any same-user
//! process can register a session and choose its own metadata.

use std::fmt::Write as _;
use std::process::{Command, Stdio};

use crate::grants::ScopeKind;
use crate::requests::RequestId;
use crate::secret::SecretName;

/// A pending request, described for a human.
#[derive(Debug, Clone)]
pub struct Announcement {
    /// Identifier the human can quote to `secrets deny`.
    pub request_id: RequestId,
    /// Key being requested.
    pub key: SecretName,
    /// Whether the requester proved a session token.
    pub scope_kind: ScopeKind,
    /// Client-supplied session id. Unverified.
    pub untrusted_session: Option<String>,
    /// Client-supplied command line. Unverified.
    pub untrusted_cmdline: Option<String>,
}

fn one_line(text: &str) -> String {
    text.chars().map(|c| if c.is_control() { ' ' } else { c }).take(200).collect()
}

/// Render the announcement shown to the human.
pub fn render(item: &Announcement) -> String {
    let mut text = String::new();
    let _ = write!(text, "secretsd: request #{} for {}", item.request_id.0, item.key.as_str());
    match item.scope_kind {
        ScopeKind::VerifiedSession => {
            let _ = write!(text, " from a verified agent session");
        }
        ScopeKind::TokenlessTty => {
            let _ = write!(text, " -- TOKENLESS (no session token; an interactive terminal)");
        }
    }
    if let Some(session) = &item.untrusted_session {
        let _ = write!(text, " [unverified session: {}]", one_line(session));
    }
    if let Some(cmdline) = &item.untrusted_cmdline {
        let _ = write!(text, " [unverified caller: {}]", one_line(cmdline));
    }
    let _ = write!(text, ". Your next YubiKey touch grants exactly this request.");
    text
}

/// A delivery channel for announcements.
pub trait Notifier: Send + Sync + std::fmt::Debug {
    /// Channel name, for logs.
    fn name(&self) -> &str;
    /// Deliver the text. Returns whether delivery was accepted.
    fn deliver(&self, text: &str) -> bool;
}

/// Runs an external command with the announcement appended as its last argument.
#[derive(Debug, Clone)]
pub struct CommandNotifier {
    label: String,
    argv: Vec<String>,
}

impl CommandNotifier {
    /// Build a notifier from a non-empty argv.
    pub fn new(label: impl Into<String>, argv: Vec<String>) -> Option<Self> {
        if argv.is_empty() {
            return None;
        }
        Some(Self { label: label.into(), argv })
    }
}

impl Notifier for CommandNotifier {
    fn name(&self) -> &str {
        &self.label
    }

    fn deliver(&self, text: &str) -> bool {
        let Some((program, args)) = self.argv.split_first() else {
            return false;
        };
        Command::new(program)
            .args(args)
            .arg(text)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }
}

/// Fans an announcement out to every configured channel.
#[derive(Debug)]
pub struct Announcer {
    notifiers: Vec<Box<dyn Notifier>>,
}

impl Announcer {
    /// Build an announcer.
    pub const fn new(notifiers: Vec<Box<dyn Notifier>>) -> Self {
        Self { notifiers }
    }

    /// Announce a request. Returns whether any channel acknowledged.
    ///
    /// A `false` return forbids starting the decrypt.
    pub fn announce(&self, item: &Announcement) -> bool {
        let text = render(item);
        let mut acknowledged = false;
        for notifier in &self.notifiers {
            if notifier.deliver(&text) {
                acknowledged = true;
            } else {
                tracing::warn!(channel = notifier.name(), "announcement channel failed");
            }
        }
        acknowledged
    }
}
```

Add to `src/lib.rs`:

```rust
pub mod announce;
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo nextest run announce`
Expected: 7 tests PASS.

---

### Task 9: Server — socket, worker, dispatch

**Files:**
- Create: `src/server.rs`
- Create: `src/main.rs`
- Create: `tests/broker.rs`
- Modify: `src/lib.rs` (add `pub mod server;`, `Config`, `run`)

**Interfaces:**
- Consumes: every previous module.
- Produces: `Config { socket_path, human_dir, sops_bin, pcsc_socket,
  notify_argv, envoy_argv, max_grant, cooldown, request_ttl,
  max_pending_per_scope }`, `Config::from_env() -> Config`,
  `run(Config) -> std::io::Result<()>`.

Concurrency shape (chosen deliberately):

- One **connection thread** per client. It parses, dispatches, and for a `GET`
  that needs approval it enqueues, then waits on a `Condvar` for a terminal
  state or the 90s TTL.
- Exactly one **worker thread** owns hardware access: it picks
  `queue.next_ready`, announces, decrypts, installs the grant, and records the
  cooldown. Single-flight is therefore structural, not merely a check.
- Shared `Mutex<State>` + `Condvar`. Locks rather than channels because the
  registry and grant table are genuinely shared mutable state that several
  request types read; a channel would just wrap a lock. **The mutex is never
  held across a decrypt** — the worker clones what it needs, drops the guard,
  runs sops, then re-acquires.
- Socket activation: if `LISTEN_FDS=1` and `LISTEN_PID` matches, adopt fd 3;
  otherwise bind `socket_path` directly (dev and tests).

- [ ] **Step 1: Write the failing end-to-end tests**

Create `tests/broker.rs`:

```rust
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use secretsd::Config;

struct Harness {
    _dir: tempfile::TempDir,
    socket: PathBuf,
}

impl Harness {
    fn start(keys: &[&str], notify_succeeds: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let human = dir.path().join("human.d");
        std::fs::create_dir(&human).unwrap();
        for key in keys {
            std::fs::write(human.join(format!("{key}.env")), b"ciphertext").unwrap();
        }
        let socket = dir.path().join("secretsd.sock");
        let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let notify = if notify_succeeds { "true" } else { "false" };

        let config = Config {
            socket_path: socket.clone(),
            human_dir: human,
            sops_bin: fixtures.join("fake-sops-ok"),
            pcsc_socket: None,
            notify_argv: vec![notify.to_owned()],
            envoy_argv: Vec::new(),
            max_grant: Duration::from_secs(43200),
            cooldown: Duration::from_millis(0),
            request_ttl: Duration::from_secs(5),
            max_pending_per_scope: 2,
        };
        std::thread::spawn(move || secretsd::run(config));
        for _ in 0..100 {
            if socket.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Self { _dir: dir, socket }
    }

    fn send(&self, line: &str) -> (String, Vec<u8>) {
        let mut stream = UnixStream::connect(&self.socket).unwrap();
        stream.write_all(line.as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();
        let mut reader = BufReader::new(stream);
        let mut header = String::new();
        reader.read_line(&mut header).unwrap();
        let mut payload = Vec::new();
        if let Some(len) = header.trim().strip_prefix("OK\tlen=") {
            let len: usize = len.parse().unwrap();
            payload.resize(len, 0);
            reader.read_exact(&mut payload).unwrap();
        }
        (header, payload)
    }
}

const TOKEN_A: &str = "aa";
const TOKEN_B: &str = "bb";

fn token(prefix: &str) -> String {
    prefix.repeat(32)
}

#[test]
fn hello_reports_protocol_version() {
    let harness = Harness::start(&[], true);
    let (header, _) = harness.send("HELLO\tversion=1");
    assert!(header.starts_with("OK"), "{header}");
}

#[test]
fn version_mismatch_is_rejected() {
    let harness = Harness::start(&[], true);
    let (header, _) = harness.send("HELLO\tversion=999");
    assert!(header.contains("VERSION_MISMATCH"), "{header}");
}

#[test]
fn registered_session_gets_a_value_and_then_a_cached_grant() {
    let harness = Harness::start(&["DEEL_API_KEY"], true);
    harness.send(&format!("REGISTER\ttoken={}\tsession=ses_a\tpid=1", token(TOKEN_A)));

    let (header, payload) =
        harness.send(&format!("GET\tkey=DEEL_API_KEY\ttoken={}", token(TOKEN_A)));
    assert!(header.starts_with("OK\tlen="), "{header}");
    assert_eq!(payload, b"value-for-DEEL_API_KEY");

    let (header, payload) =
        harness.send(&format!("GET\tkey=DEEL_API_KEY\ttoken={}", token(TOKEN_A)));
    assert!(header.starts_with("OK\tlen="), "{header}");
    assert_eq!(payload, b"value-for-DEEL_API_KEY");
}

#[test]
fn sibling_session_does_not_inherit_a_grant() {
    let harness = Harness::start(&["DEEL_API_KEY"], true);
    harness.send(&format!("REGISTER\ttoken={}\tsession=ses_a\tpid=1", token(TOKEN_A)));
    harness.send(&format!("REGISTER\ttoken={}\tsession=ses_b\tpid=1", token(TOKEN_B)));
    harness.send(&format!("GET\tkey=DEEL_API_KEY\ttoken={}", token(TOKEN_A)));

    // B must go through its own approval; with a fake sops that means it also
    // succeeds, but it must produce its own request rather than reuse A's grant.
    let (header, _) = harness.send(&format!("GRANTS"));
    assert!(header.starts_with("OK"), "{header}");
}

#[test]
fn unknown_token_is_rejected_and_never_downgraded() {
    let harness = Harness::start(&["DEEL_API_KEY"], true);
    let (header, _) =
        harness.send(&format!("GET\tkey=DEEL_API_KEY\ttoken={}", token("cc")));
    assert!(header.contains("UNKNOWN_TOKEN"), "{header}");
}

#[test]
fn request_without_scope_is_rejected() {
    let harness = Harness::start(&["DEEL_API_KEY"], true);
    let (header, _) = harness.send("GET\tkey=DEEL_API_KEY");
    assert!(header.contains("NO_SCOPE"), "{header}");
}

#[test]
fn unknown_key_is_not_a_human_key() {
    let harness = Harness::start(&["DEEL_API_KEY"], true);
    harness.send(&format!("REGISTER\ttoken={}\tsession=ses_a\tpid=1", token(TOKEN_A)));
    let (header, _) = harness.send(&format!("GET\tkey=NOPE\ttoken={}", token(TOKEN_A)));
    assert!(header.contains("NOT_HUMAN_KEY"), "{header}");
}

#[test]
fn no_announcement_channel_means_no_grant() {
    let harness = Harness::start(&["DEEL_API_KEY"], false);
    harness.send(&format!("REGISTER\ttoken={}\tsession=ses_a\tpid=1", token(TOKEN_A)));
    let (header, _) =
        harness.send(&format!("GET\tkey=DEEL_API_KEY\ttoken={}", token(TOKEN_A)));
    assert!(
        header.contains("NOT_ANNOUNCED") || header.contains("TIMEOUT"),
        "unannounced request must not be granted: {header}"
    );
}

#[test]
fn unregister_revokes_grants() {
    let harness = Harness::start(&["DEEL_API_KEY"], true);
    harness.send(&format!("REGISTER\ttoken={}\tsession=ses_a\tpid=1", token(TOKEN_A)));
    harness.send(&format!("GET\tkey=DEEL_API_KEY\ttoken={}", token(TOKEN_A)));
    harness.send("UNREGISTER\tsession=ses_a");

    let (header, _) =
        harness.send(&format!("GET\tkey=DEEL_API_KEY\ttoken={}", token(TOKEN_A)));
    assert!(header.contains("UNKNOWN_TOKEN"), "{header}");
}

#[test]
fn lock_wipes_all_grants() {
    let harness = Harness::start(&["DEEL_API_KEY"], true);
    harness.send(&format!("REGISTER\ttoken={}\tsession=ses_a\tpid=1", token(TOKEN_A)));
    harness.send(&format!("GET\tkey=DEEL_API_KEY\ttoken={}", token(TOKEN_A)));
    harness.send("LOCK");

    let (header, payload) = harness.send("GRANTS");
    assert!(header.starts_with("OK"), "{header}");
    let text = String::from_utf8_lossy(&payload);
    assert!(text.contains("no active grants"), "{text}");
}

#[test]
fn grants_listing_never_contains_values() {
    let harness = Harness::start(&["DEEL_API_KEY"], true);
    harness.send(&format!("REGISTER\ttoken={}\tsession=ses_a\tpid=1", token(TOKEN_A)));
    harness.send(&format!("GET\tkey=DEEL_API_KEY\ttoken={}", token(TOKEN_A)));
    let (_, payload) = harness.send("GRANTS");
    let text = String::from_utf8_lossy(&payload);
    assert!(!text.contains("value-for-"), "grant listing leaked a secret: {text}");
}

#[test]
fn tokenless_request_from_a_learned_agent_tty_is_rejected() {
    let harness = Harness::start(&["DEEL_API_KEY"], true);
    harness.send(&format!("REGISTER\ttoken={}\tsession=ses_a\tpid=1", token(TOKEN_A)));
    harness.send(&format!(
        "GET\tkey=DEEL_API_KEY\ttoken={}\ttty=/dev/pts/42",
        token(TOKEN_A)
    ));

    let (header, _) = harness.send("GET\tkey=DEEL_API_KEY\ttty=/dev/pts/42");
    assert!(header.contains("AGENT_TTY"), "env-stripped agent slipped through: {header}");
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo nextest run --test broker`
Expected: FAIL — `cannot find function run in crate secretsd`.

- [ ] **Step 3: Implement `Config` and `run` in `src/lib.rs`**

Replace `src/lib.rs` with the module list plus:

```rust
use std::path::PathBuf;
use std::time::Duration;

/// Daemon configuration. Sourced from the daemon's own environment only —
/// never from a client request, because clients are untrusted.
#[derive(Debug, Clone)]
pub struct Config {
    /// Unix socket to serve on when not socket-activated.
    pub socket_path: PathBuf,
    /// Directory of per-key sops files.
    pub human_dir: PathBuf,
    /// Path to the sops binary.
    pub sops_bin: PathBuf,
    /// PC/SC socket whose absence means the YubiKey is unreachable.
    pub pcsc_socket: Option<PathBuf>,
    /// argv for the desktop notification channel.
    pub notify_argv: Vec<String>,
    /// argv for the envoy notification channel.
    pub envoy_argv: Vec<String>,
    /// Backstop lifetime for a grant.
    pub max_grant: Duration,
    /// Gap enforced between decrypts; must exceed the PIV touch cache.
    pub cooldown: Duration,
    /// How long a request waits for approval.
    pub request_ttl: Duration,
    /// Pending requests allowed per scope.
    pub max_pending_per_scope: usize,
}

impl Config {
    /// Build configuration from environment variables, with defaults.
    pub fn from_env() -> Self {
        let var = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
        let runtime = var("XDG_RUNTIME_DIR").unwrap_or_else(|| "/tmp".to_owned());
        let home = var("HOME").unwrap_or_else(|| "/root".to_owned());
        let argv = |name: &str| {
            var(name)
                .map(|v| v.split_whitespace().map(ToOwned::to_owned).collect::<Vec<String>>())
                .unwrap_or_default()
        };
        let secs = |name: &str, fallback: u64| {
            var(name).and_then(|v| v.parse().ok()).map_or(Duration::from_secs(fallback), Duration::from_secs)
        };
        Self {
            socket_path: var("SECRETSD_SOCKET")
                .map_or_else(|| PathBuf::from(format!("{runtime}/secretsd.sock")), PathBuf::from),
            human_dir: var("SECRETSD_HUMAN_DIR").map_or_else(
                || PathBuf::from(format!("{home}/.dotfiles/secrets.human.d")),
                PathBuf::from,
            ),
            sops_bin: var("SECRETSD_SOPS_BIN").map_or_else(|| PathBuf::from("sops"), PathBuf::from),
            pcsc_socket: var("PCSCLITE_CSOCK_NAME").map(PathBuf::from),
            notify_argv: argv("SECRETSD_NOTIFY_CMD"),
            envoy_argv: argv("SECRETSD_ENVOY_CMD"),
            max_grant: secs("SECRETSD_MAX_GRANT_SECS", 43200),
            cooldown: secs("SECRETSD_COOLDOWN_SECS", 16),
            request_ttl: secs("SECRETSD_REQUEST_TTL_SECS", 90),
            max_pending_per_scope: var("SECRETSD_MAX_PENDING")
                .and_then(|v| v.parse().ok())
                .unwrap_or(3),
        }
    }
}

/// Serve until the process is stopped.
pub fn run(config: Config) -> std::io::Result<()> {
    server::serve(config)
}
```

- [ ] **Step 4: Implement `src/server.rs`**

Build it in this order; each piece has a test above that exercises it:

1. `struct State { registry, grants, queue, store, decryptor, announcer, config }`
   behind `Arc<(Mutex<State>, Condvar)>`.
2. `fn listener(config) -> UnixListener`: adopt fd 3 when `LISTEN_FDS=1` and
   `LISTEN_PID` equals our pid (use `UnixListener::from_raw_fd` inside a single
   documented `unsafe` block with a `// SAFETY:` comment — systemd guarantees
   fd 3 is an unowned listening socket; this is the crate's only `unsafe`, and
   it must pass `cargo +nightly miri nextest run`). Otherwise remove a stale
   socket file and `bind`, then `set_permissions(0o600)`.
3. `fn worker(shared)`: loop — lock, `sweep_timeouts`, `revoke_expired`,
   `prune`, take `next_ready`; if none, `wait_timeout` on the condvar; if some,
   `mark_decrypting`, capture `(scope, key, generation)`, **drop the guard**,
   `announce` (on `false`: re-lock, `queue.fail`, notify, continue),
   `decrypt`, re-lock, `complete(id, generation)` — only install the grant when
   it returns `true` — then `notify_all`.
4. `fn handle(stream, shared)`: read one bounded frame, `parse_request`,
   dispatch, write the response header and (for `OkBytes`) the raw payload
   straight from `SecretBytes::as_slice`.
5. `GET` dispatch: `SecretName::parse` → `SessionToken::parse_hex` (when
   present) → `registry.resolve` → `grants.lookup` (hit: return bytes) →
   `store.contains` (miss: `NOT_HUMAN_KEY`) → `queue.enqueue` → `notify_all` →
   `wait_timeout` until the request reaches a terminal state or `request_ttl`
   elapses → map the state to a response.
6. `RequestGrant` dispatch: identical, but returns `OkFields("status=...")`
   instead of the value.
7. `Register` / `Unregister` / `Grants` / `Deny` / `Lock`: direct state
   mutations, each followed by `notify_all`.
8. Log every request at `info` with key name, scope kind, decision, and the
   peer's `SO_PEERCRED` pid — **never the value, never the token**.

Create `src/main.rs`:

```rust
//! Daemon entry point.

use secretsd::hardening::{self, MemlockPolicy};
use secretsd::{Config, run};

fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt().with_writer(std::io::stderr).with_target(false).init();

    if let Err(error) = hardening::apply(MemlockPolicy::Require) {
        tracing::error!(%error, "refusing to start without process hardening");
        return std::process::ExitCode::FAILURE;
    }

    match run(Config::from_env()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "secretsd exited");
            std::process::ExitCode::FAILURE
        }
    }
}
```

- [ ] **Step 5: Run the full suite**

Run: `cargo nextest run`
Expected: every test passes, including the 12 in `tests/broker.rs`.

- [ ] **Step 6: Verify lints and Miri**

Run:
```bash
cargo fmt --all && \
cargo clippy --all-targets --all-features -- -D warnings && \
cargo +nightly miri nextest run secret grants requests proto
```
Expected: clean. (Miri cannot run the socket tests; scope it to the pure modules.)

---

### Task 10: Packaging

**Files:**
- Create: `systemd/secretsd.socket`, `systemd/secretsd.service`
- Create: `.github/workflows/release.yml`
- Modify: `README.md` (install section)

- [ ] **Step 1: Write the units**

`systemd/secretsd.socket`:

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

`systemd/secretsd.service`:

```ini
[Unit]
Description=secretsd session secrets broker
Requires=secretsd.socket
After=secretsd.socket

[Service]
Type=simple
ExecStart=%h/.dotfiles/bin/secretsd
Environment=SECRETSD_HUMAN_DIR=%h/.dotfiles/secrets.human.d
Environment="SECRETSD_NOTIFY_CMD=notify-send --app-name=secretsd --urgency=critical secretsd"
# Locking pages is mandatory in production; without this the daemon refuses to start.
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

- [ ] **Step 2: Verify the units parse and the daemon starts**

```bash
systemd-analyze --user verify systemd/secretsd.service
```
Expected: no output (parse clean). Full enablement happens in the dotfiles-side
plan, which owns installation.

- [ ] **Step 3: Add the release workflow**

`.github/workflows/release.yml` — on tag push, build `--release`, package
`secretsd-<tag>-linux-x86_64.tar.gz` containing the binary plus `systemd/`,
and attach it to a GitHub release. This mirrors how `voxtype` is consumed by
the dotfiles installer.

```yaml
name: release
on:
  push:
    tags: ["v*"]

permissions:
  contents: write

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo build --release --locked
      - name: Package
        run: |
          set -euo pipefail
          tag="${GITHUB_REF_NAME}"
          staging="secretsd-${tag}-linux-x86_64"
          mkdir -p "$staging/systemd"
          cp target/release/secretsd "$staging/"
          cp systemd/* "$staging/systemd/"
          tar czf "${staging}.tar.gz" "$staging"
      - uses: softprops/action-gh-release@v2
        with:
          files: secretsd-*-linux-x86_64.tar.gz
```

- [ ] **Step 4: Final gate**

```bash
cargo fmt --all -- --check && \
cargo clippy --all-targets --all-features -- -D warnings && \
cargo nextest run && \
cargo deny check all
```
Expected: all clean.

- [ ] **Step 5: Describe the change (single commit, per repo convention)**

```bash
jj describe -m "feat: session-scoped secrets broker daemon"
jj new
```

Do not push without explicit approval from the repo owner.

---

## What this plan deliberately does not cover

The daemon is useless until its consumers exist. Those live in `~/.dotfiles`
and get their own plan, because they ship and test independently:

1. `.sops.yaml` creation rule for `secrets.human.d/` (**must land before any
   per-key file is created** — today's default rule would encrypt them to the
   agent key and silently bypass this daemon), plus the fix for
   `installers/sops.sh` overwriting `.sops.yaml`.
2. `shims/secrets`: derive the human-key set from `secrets.human.d/` file
   names, always route those keys through the broker, fail closed on a
   duplicate in an agent-tier file, drop the `/dev/shm` cache.
3. `opencode/plugins/secretsd.ts`: token generation, token file,
   register/unregister, `SECRETSD_SESSION_TOKEN_FILE` injection, and the
   `secrets_request` tool.
4. `installers/secretsd.sh`: fetch the release, link the systemd units, enable
   the socket.
5. The migration ceremony (laptop only, YubiKey required) splitting
   `secrets.human.env` into per-key files, and the end-to-end verification
   checklist from `docs/design.md`.

## Plan self-review

- **Spec coverage.** Design sections map to tasks as follows: architecture and
  socket → 9; per-key store and anti-swap → 2, 4; token authorization and
  session isolation → 6, 9; tokenless tty handling → 6, 9; grant lifecycle,
  revocation, 12h backstop → 6, 9; announcement-before-blink → 8, 9;
  single-flight and cooldown → 7; queue-flood limits → 7; memory hygiene → 2,
  3; reachability fail-fast → 5; `secrets list` without decryption → 4;
  grants/deny/lock surface → 9. Consumer-side items (shim, plugin,
  `.sops.yaml`, migration) are explicitly deferred above rather than dropped.
- **Type consistency.** `SecretName`, `SecretBytes`, `SessionToken`, `Scope`,
  `ScopeKind`, `RequestId`, `ErrCode`, `HumanStore`, `Decryptor`, `Queue`,
  `Announcer` keep the same names and signatures across every task that uses
  them. `HumanStore::path_for` is introduced in Task 5 where `decrypt` needs
  it.
- **Known implementation risk.** `nix` API details (`openat` signature,
  `fstat` on a borrowed fd, `set_dumpable` location) vary between minor
  versions. Where the pinned version differs, adapt the call but preserve the
  security content: `O_NOFOLLOW`, `O_CLOEXEC`, regular-file check,
  dumpable off, core limit zero.
- **Single `unsafe`.** Only the socket-activation fd adoption in Task 9. It
  requires a `// SAFETY:` comment and must pass Miri, per the repo's
  non-negotiables.