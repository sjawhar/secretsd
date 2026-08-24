//! Wire protocol v3: line-oriented, tab-separated, ASCII.
//!
//! Hand-rolled deliberately. Secret plaintext is written straight from a
//! zeroizing buffer to the socket and never passes through a serializer whose
//! internal buffers we cannot wipe.

use std::fmt;

use zeroize::Zeroizing;

/// Protocol version. A mismatch is a hard error, never a downgrade.
pub const PROTOCOL_VERSION: u32 = 3;

/// Maximum accepted request frame. Requests never carry secret values.
pub const MAX_FRAME_BYTES: usize = 4096;

mod response;

pub use response::{Response, format_response};

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
    /// Token was presented by a process outside its session's process tree.
    ForeignCaller,
    /// Key is not present in the human-tier store.
    NotHumanKey,
    /// Key resolves to more than one human-tier file, so access is refused.
    AmbiguousKey,
    /// A human denied the request.
    Denied,
    /// The request expired before approval.
    Timeout,
    /// The `YubiKey` is not reachable from this machine right now.
    YubikeyUnreachable,
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
            Self::ForeignCaller => "FOREIGN_CALLER",
            Self::NotHumanKey => "NOT_HUMAN_KEY",
            Self::AmbiguousKey => "AMBIGUOUS_KEY",
            Self::Denied => "DENIED",
            Self::Timeout => "TIMEOUT",
            Self::YubikeyUnreachable => "YUBIKEY_UNREACHABLE",
            Self::TooManyPending => "TOO_MANY_PENDING",
            Self::Internal => "INTERNAL",
        }
    }

    /// Parse a stable wire token into its protocol error code.
    pub fn parse_wire(token: &str) -> Option<Self> {
        match token {
            "BAD_REQUEST" => Some(Self::BadRequest),
            "UNKNOWN_OP" => Some(Self::UnknownOp),
            "VERSION_MISMATCH" => Some(Self::VersionMismatch),
            "UNKNOWN_TOKEN" => Some(Self::UnknownToken),
            "NO_SCOPE" => Some(Self::NoScope),
            "AGENT_TTY" => Some(Self::AgentTty),
            "FOREIGN_CALLER" => Some(Self::ForeignCaller),
            "NOT_HUMAN_KEY" => Some(Self::NotHumanKey),
            "AMBIGUOUS_KEY" => Some(Self::AmbiguousKey),
            "DENIED" => Some(Self::Denied),
            "TIMEOUT" => Some(Self::Timeout),
            "YUBIKEY_UNREACHABLE" => Some(Self::YubikeyUnreachable),
            "TOO_MANY_PENDING" => Some(Self::TooManyPending),
            "INTERNAL" => Some(Self::Internal),
            _ => None,
        }
    }
}

/// A parsed client request. Tokens stay as hex here; `grants` owns the crypto type.
#[derive(Clone, PartialEq, Eq)]
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
        token_hex: Zeroizing<String>,
        /// Harness-supplied session identifier, untrusted and used only for logging.
        session: String,
        /// Harness process id, shown as unverified caller metadata.
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
        token_hex: Option<Zeroizing<String>>,
        /// Caller's controlling tty, if any.
        tty: Option<String>,
    },
    /// Trigger the grant flow without returning a value.
    RequestGrant {
        /// Requested key name.
        key: String,
        /// Hex-encoded session token, if the caller has one.
        token_hex: Option<Zeroizing<String>>,
        /// Caller's controlling tty, if any.
        tty: Option<String>,
    },
    /// Run the grant ceremony for a named capability; returns no value, only
    /// a single-use receipt attesting the authorization.
    Authorize {
        /// Capability name, `[a-z][a-z0-9_]*`; the daemon derives the backing
        /// `CAP_<NAME>` key.
        cap: String,
        /// Hex-encoded session token, if the caller has one.
        token_hex: Option<Zeroizing<String>>,
        /// Caller's controlling tty, if any.
        tty: Option<String>,
    },
    /// Consume a receipt minted by a successful AUTHORIZE.
    Redeem {
        /// Hex-encoded receipt.
        receipt_hex: Zeroizing<String>,
        /// Capability this receipt must attest.
        cap: String,
    },
    /// List active grants and pending requests.
    Grants,
    /// Reject a pending request.
    Deny {
        /// Pending request identifier.
        id: u64,
    },
    /// Wipe all plaintext and revoke all grants.
    Lock,
}

impl fmt::Debug for Request {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hello { version } => formatter
                .debug_struct("Hello")
                .field("version", version)
                .finish(),
            Self::Register { session, pid, .. } => formatter
                .debug_struct("Register")
                .field("token_hex", &"<redacted>")
                .field("session", session)
                .field("pid", pid)
                .finish(),
            Self::Unregister { session } => formatter
                .debug_struct("Unregister")
                .field("session", session)
                .finish(),
            Self::Get { key, tty, .. } => formatter
                .debug_struct("Get")
                .field("key", key)
                .field("token_hex", &"<redacted>")
                .field("tty", tty)
                .finish(),
            Self::RequestGrant { key, tty, .. } => formatter
                .debug_struct("RequestGrant")
                .field("key", key)
                .field("token_hex", &"<redacted>")
                .field("tty", tty)
                .finish(),
            Self::Authorize { cap, tty, .. } => formatter
                .debug_struct("Authorize")
                .field("cap", cap)
                .field("token_hex", &"<redacted>")
                .field("tty", tty)
                .finish(),
            Self::Redeem { cap, .. } => formatter
                .debug_struct("Redeem")
                .field("receipt_hex", &"<redacted>")
                .field("cap", cap)
                .finish(),
            Self::Grants => formatter.write_str("Grants"),
            Self::Deny { id } => formatter.debug_struct("Deny").field("id", id).finish(),
            Self::Lock => formatter.write_str("Lock"),
        }
    }
}

fn field<'a>(fields: &'a [(&'a str, &'a str)], name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(key, _)| *key == name)
        .map(|(_, value)| *value)
}

fn required<'a>(fields: &'a [(&'a str, &'a str)], name: &str) -> Result<&'a str, ErrCode> {
    field(fields, name).ok_or(ErrCode::BadRequest)
}

/// Parse one request frame without its trailing newline.
pub fn parse_request(line: &[u8]) -> Result<Request, ErrCode> {
    if line.is_empty() || line.len() > MAX_FRAME_BYTES {
        return Err(ErrCode::BadRequest);
    }

    let text = std::str::from_utf8(line).map_err(|_| ErrCode::BadRequest)?;
    let mut parts = text.split('\t');
    let op = parts.next().ok_or(ErrCode::BadRequest)?;
    let mut fields = Vec::new();

    for part in parts {
        let (key, value) = part.split_once('=').ok_or(ErrCode::BadRequest)?;
        if field(&fields, key).is_some() {
            return Err(ErrCode::BadRequest);
        }
        fields.push((key, value));
    }

    let owned = |name: &str| field(&fields, name).map(ToOwned::to_owned);
    let credential =
        |name: &str| field(&fields, name).map(|value| Zeroizing::new(value.to_owned()));

    match op {
        "HELLO" => Ok(Request::Hello {
            version: required(&fields, "version")?
                .parse()
                .map_err(|_| ErrCode::BadRequest)?,
        }),
        "REGISTER" => Ok(Request::Register {
            token_hex: Zeroizing::new(required(&fields, "token")?.to_owned()),
            session: required(&fields, "session")?.to_owned(),
            pid: required(&fields, "pid")?
                .parse()
                .map_err(|_| ErrCode::BadRequest)?,
        }),
        "UNREGISTER" => Ok(Request::Unregister {
            session: required(&fields, "session")?.to_owned(),
        }),
        "GET" => Ok(Request::Get {
            key: required(&fields, "key")?.to_owned(),
            token_hex: credential("token"),
            tty: owned("tty"),
        }),
        "REQUEST" => Ok(Request::RequestGrant {
            key: required(&fields, "key")?.to_owned(),
            token_hex: credential("token"),
            tty: owned("tty"),
        }),
        "AUTHORIZE" => Ok(Request::Authorize {
            cap: required(&fields, "cap")?.to_owned(),
            token_hex: credential("token"),
            tty: owned("tty"),
        }),
        "REDEEM" => Ok(Request::Redeem {
            receipt_hex: Zeroizing::new(required(&fields, "receipt")?.to_owned()),
            cap: required(&fields, "cap")?.to_owned(),
        }),
        "GRANTS" => Ok(Request::Grants),
        "DENY" => Ok(Request::Deny {
            id: required(&fields, "id")?
                .parse()
                .map_err(|_| ErrCode::BadRequest)?,
        }),
        "LOCK" => Ok(Request::Lock),
        _ => Err(ErrCode::UnknownOp),
    }
}

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
                token_hex: Some(Zeroizing::new("ab12".to_owned())),
                tty: Some("/dev/pts/3".to_owned()),
            }
        );
    }

    #[test]
    fn request_debug_redacts_bearer_credentials() {
        let register = parse_request(b"REGISTER\ttoken=deadbeef\tsession=session\tpid=1").unwrap();
        let redeem = parse_request(b"REDEEM\treceipt=feedface\tcap=browser").unwrap();

        assert!(!format!("{register:?}").contains("deadbeef"));
        assert!(!format!("{redeem:?}").contains("feedface"));
    }

    #[test]
    fn parses_get_without_token() {
        let req = parse_request(b"GET\tkey=K\ttty=/dev/pts/3").unwrap();
        assert_eq!(
            req,
            Request::Get {
                key: "K".to_owned(),
                token_hex: None,
                tty: Some("/dev/pts/3".to_owned()),
            }
        );
    }

    #[test]
    fn rejects_unknown_op() {
        assert_eq!(parse_request(b"FROBNICATE\tx=1"), Err(ErrCode::UnknownOp));
    }

    #[test]
    fn ambiguous_key_error_round_trips_its_wire_token() {
        assert_eq!(
            ErrCode::parse_wire("AMBIGUOUS_KEY"),
            Some(ErrCode::AmbiguousKey)
        );
        assert_eq!(ErrCode::AmbiguousKey.wire(), "AMBIGUOUS_KEY");
    }

    #[test]
    fn rejects_removed_announcement_frames_and_errors() {
        assert_eq!(parse_request(b"ACK\tid=9"), Err(ErrCode::UnknownOp));
        assert_eq!(ErrCode::parse_wire("NOT_ANNOUNCED"), None);
    }

    #[test]
    fn rejects_missing_required_field() {
        assert_eq!(
            parse_request(b"GET\ttty=/dev/pts/3"),
            Err(ErrCode::BadRequest)
        );
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
        assert_eq!(
            parse_request(&[b'G', b'E', b'T', b'\t', 0xff]),
            Err(ErrCode::BadRequest)
        );
    }

    #[test]
    fn rejects_duplicate_field() {
        assert_eq!(
            parse_request(b"GET\tkey=A\tkey=B"),
            Err(ErrCode::BadRequest)
        );
    }

    #[test]
    fn parses_authorize_with_token_and_redeem() {
        let req = parse_request(b"AUTHORIZE\tcap=browser\ttoken=ab12").unwrap();
        assert_eq!(
            req,
            Request::Authorize {
                cap: "browser".to_owned(),
                token_hex: Some(Zeroizing::new("ab12".to_owned())),
                tty: None,
            }
        );
        let req = parse_request(b"REDEEM\treceipt=deadbeef\tcap=browser").unwrap();
        assert_eq!(
            req,
            Request::Redeem {
                receipt_hex: Zeroizing::new("deadbeef".to_owned()),
                cap: "browser".to_owned(),
            }
        );
    }

    #[test]
    fn authorize_requires_a_cap_and_redeem_a_receipt() {
        assert_eq!(
            parse_request(b"AUTHORIZE\ttoken=ab"),
            Err(ErrCode::BadRequest)
        );
        assert_eq!(
            parse_request(b"REDEEM\tcap=browser"),
            Err(ErrCode::BadRequest)
        );
        assert_eq!(
            parse_request(b"REDEEM\treceipt=deadbeef"),
            Err(ErrCode::BadRequest)
        );
    }

    #[test]
    fn rejects_duplicate_authorize_capability_fields() {
        assert_eq!(
            parse_request(b"AUTHORIZE\tcap=browser\tcap=admin\ttoken=ab12"),
            Err(ErrCode::BadRequest)
        );
    }

    #[test]
    fn formats_ok_bytes_header() {
        assert_eq!(format_response(&Response::OkBytes(42)), "OK\tlen=42\n");
    }

    #[test]
    fn every_ok_fields_payload_is_space_separated_key_values() {
        // A space separates fields on the wire, and `sanitize` does not protect
        // it, so a value containing one would reach a client as an extra field.
        // Pin the shape of every payload this daemon emits.
        let instance = "ab".repeat(16);
        let handshake = format!("version={PROTOCOL_VERSION} instance={instance}");
        for fields in [handshake.as_str(), "status=granted"] {
            let line = format_response(&Response::OkFields(fields));
            let body = line
                .strip_prefix("OK\t")
                .and_then(|rest| rest.strip_suffix('\n'))
                .unwrap();
            assert!(
                body.split(' ')
                    .all(|field| !field.is_empty() && field.contains('=')),
                "payload is not space-separated k=v: {body}"
            );
        }
    }

    #[test]
    #[should_panic(expected = "not space-separated")]
    fn a_field_value_containing_a_space_is_caught() {
        // The tripwire above must actually fire, or it documents nothing.
        let _ = format_response(&Response::OkFields("note=hello world"));
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
