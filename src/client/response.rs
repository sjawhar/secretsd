use std::fmt;
use std::io::{BufRead, BufReader, Read};
use std::os::unix::net::UnixStream;

use zeroize::Zeroize;

use crate::proto::{ErrCode, MAX_FRAME_BYTES};

/// A successfully decoded broker response.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BrokerResponse {
    /// A successful response without fields or payload.
    Ok,
    /// A successful response with protocol fields.
    Fields(String),
    /// A successful response with a raw, non-NUL payload.
    Bytes(Vec<u8>),
}

impl fmt::Debug for BrokerResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ok => formatter.write_str("Ok"),
            Self::Fields(_) => formatter.write_str("Fields(<redacted>)"),
            Self::Bytes(bytes) => formatter.debug_tuple("Bytes").field(&bytes.len()).finish(),
        }
    }
}

/// A connection, framing, handshake, or broker failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum ClientError {
    /// The Unix socket could not be contacted or read.
    Io(std::io::Error),
    /// An approval-waiting operation got no answer in time; the daemon is likely healthy.
    ApprovalTimeout,
    /// The caller attempted to send an invalid protocol request.
    InvalidRequest,
    /// The broker emitted malformed or unsafe framed data.
    InvalidResponse,
    /// The broker did not confirm the exact protocol version.
    VersionHandshake,
    /// The broker rejected the request with a stable protocol error code.
    Broker(ErrCode),
    /// The inherited session token file could not be safely read as UTF-8.
    TokenFile,
}

impl PartialEq for ClientError {
    fn eq(&self, other: &Self) -> bool {
        match self {
            Self::Io(left) => matches!(other, Self::Io(right) if left.kind() == right.kind()),
            Self::ApprovalTimeout => matches!(other, Self::ApprovalTimeout),
            Self::InvalidRequest => matches!(other, Self::InvalidRequest),
            Self::InvalidResponse => matches!(other, Self::InvalidResponse),
            Self::VersionHandshake => matches!(other, Self::VersionHandshake),
            Self::Broker(left) => matches!(other, Self::Broker(right) if left == right),
            Self::TokenFile => matches!(other, Self::TokenFile),
        }
    }
}

impl Eq for ClientError {}

impl fmt::Display for ClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "could not communicate with secretsd: {error}"),
            Self::ApprovalTimeout => formatter.write_str(
                "timed out waiting for approval; the human may still need to touch the key, and the daemon waits out the hardware cooldown between decrypts",
            ),
            Self::InvalidRequest => {
                formatter.write_str("refusing to send an invalid broker request")
            }
            Self::InvalidResponse => formatter.write_str("secretsd returned an invalid response"),
            Self::VersionHandshake | Self::Broker(ErrCode::VersionMismatch) => {
                formatter.write_str("secretsd protocol version does not match this client")
            }
            Self::Broker(ErrCode::BadRequest) => {
                formatter.write_str("secretsd rejected the request as malformed")
            }
            Self::Broker(ErrCode::UnknownOp) => {
                formatter.write_str("this client requested an unsupported secretsd operation")
            }
            Self::Broker(ErrCode::UnknownToken) => formatter.write_str(
                "this session's registration was lost, usually to a broker restart; the OpenCode plugin re-registers it on the next command",
            ),
            Self::Broker(ErrCode::NoScope) => {
                formatter.write_str("no session token or interactive terminal scope is available")
            }
            Self::Broker(ErrCode::AgentTty) => {
                formatter.write_str("tokenless access from an agent terminal is not permitted")
            }
            Self::Broker(ErrCode::ForeignCaller) => formatter.write_str(
                "the session token was presented from outside that session's process tree",
            ),
            Self::Broker(ErrCode::NotHumanKey) => {
                formatter.write_str("the requested key is not managed by secretsd")
            }
            Self::Broker(ErrCode::Denied) => formatter.write_str("the secret request was denied"),
            Self::Broker(ErrCode::Timeout) => {
                formatter.write_str("the secret request timed out before approval")
            }
            Self::Broker(ErrCode::YubikeyUnreachable) => formatter
                .write_str("the YubiKey is unreachable; connect through the devbox wrapper"),
            Self::Broker(ErrCode::TooManyPending) => {
                formatter.write_str("this session already has too many pending secret requests")
            }
            Self::Broker(ErrCode::Internal) => {
                formatter.write_str("secretsd could not complete the request")
            }
            Self::TokenFile => formatter.write_str("could not safely read the session token file"),
        }
    }
}

impl std::error::Error for ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::ApprovalTimeout
            | Self::InvalidRequest
            | Self::InvalidResponse
            | Self::VersionHandshake
            | Self::Broker(_)
            | Self::TokenFile => None,
        }
    }
}

enum Header {
    Ok,
    Fields(String),
    Bytes(usize),
    Error(ErrCode),
}

/// Parse one complete byte response without converting a secret payload to text.
pub fn parse_response(response: &[u8]) -> Result<BrokerResponse, ClientError> {
    let Some(header_end) = response.iter().position(|byte| *byte == b'\n') else {
        return Err(ClientError::InvalidResponse);
    };
    let (header, rest) = response.split_at(header_end);
    let Some(payload) = rest.strip_prefix(b"\n") else {
        return Err(ClientError::InvalidResponse);
    };
    match parse_header(header)? {
        Header::Bytes(length) => payload_from_slice(payload, length),
        header => {
            if payload.is_empty() {
                finish_header(header)
            } else {
                Err(ClientError::InvalidResponse)
            }
        }
    }
}

pub(super) fn read_response(stream: UnixStream) -> Result<BrokerResponse, ClientError> {
    let mut reader = BufReader::new(stream);
    let mut raw_header = Vec::new();
    let limit = u64::try_from(MAX_FRAME_BYTES + 1).map_err(|_| ClientError::InvalidResponse)?;
    let header_length = reader
        .by_ref()
        .take(limit)
        .read_until(b'\n', &mut raw_header)
        .map_err(ClientError::Io)?;
    let Some(header) = raw_header.strip_suffix(b"\n") else {
        return Err(ClientError::InvalidResponse);
    };
    if header_length == 0 {
        return Err(ClientError::InvalidResponse);
    }

    match parse_header(header)? {
        Header::Bytes(length) => {
            let payload = read_payload(&mut reader, length)?;
            reject_trailing_bytes(&mut reader)?;
            bytes_response(payload)
        }
        header => {
            reject_trailing_bytes(&mut reader)?;
            finish_header(header)
        }
    }
}

fn parse_header(header: &[u8]) -> Result<Header, ClientError> {
    let header_is_valid = !header.is_empty()
        && header
            .iter()
            .all(|byte| byte.is_ascii_graphic() || matches!(*byte, b' ' | b'\t'));
    if !header_is_valid {
        return Err(ClientError::InvalidResponse);
    }
    let text = std::str::from_utf8(header).map_err(|_| ClientError::InvalidResponse)?;
    if text == "OK" {
        return Ok(Header::Ok);
    }
    if let Some(length) = text.strip_prefix("OK\tlen=") {
        let length_is_valid =
            !length.is_empty() && length.bytes().all(|byte| byte.is_ascii_digit());
        if !length_is_valid {
            return Err(ClientError::InvalidResponse);
        }
        return length
            .parse()
            .map(Header::Bytes)
            .map_err(|_| ClientError::InvalidResponse);
    }
    if let Some(fields) = text.strip_prefix("OK\t") {
        return Ok(Header::Fields(fields.to_owned()));
    }
    if let Some(error) = text.strip_prefix("ERR\t") {
        let Some((code, _message)) = error.split_once('\t') else {
            return Err(ClientError::InvalidResponse);
        };
        return ErrCode::parse_wire(code)
            .map(Header::Error)
            .ok_or(ClientError::InvalidResponse);
    }
    Err(ClientError::InvalidResponse)
}

fn finish_header(header: Header) -> Result<BrokerResponse, ClientError> {
    match header {
        Header::Ok => Ok(BrokerResponse::Ok),
        Header::Fields(fields) => Ok(BrokerResponse::Fields(fields)),
        Header::Bytes(_) => Err(ClientError::InvalidResponse),
        Header::Error(code) => Err(ClientError::Broker(code)),
    }
}

fn payload_from_slice(payload: &[u8], length: usize) -> Result<BrokerResponse, ClientError> {
    let payload_is_valid = payload.len() == length && !payload.contains(&0);
    if !payload_is_valid {
        return Err(ClientError::InvalidResponse);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| ClientError::InvalidResponse)?;
    bytes.extend_from_slice(payload);
    Ok(BrokerResponse::Bytes(bytes))
}

fn read_payload(reader: &mut BufReader<UnixStream>, length: usize) -> Result<Vec<u8>, ClientError> {
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(length)
        .map_err(|_| ClientError::InvalidResponse)?;
    payload.resize(length, 0);
    match reader.read_exact(&mut payload) {
        Ok(()) => Ok(payload),
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
            payload.zeroize();
            Err(ClientError::InvalidResponse)
        }
        Err(error) => {
            payload.zeroize();
            Err(ClientError::Io(error))
        }
    }
}

fn reject_trailing_bytes(reader: &mut BufReader<UnixStream>) -> Result<(), ClientError> {
    let mut byte = [0_u8; 1];
    match reader.read(&mut byte) {
        Ok(0) => Ok(()),
        Ok(_) => Err(ClientError::InvalidResponse),
        Err(error) => Err(ClientError::Io(error)),
    }
}

fn bytes_response(mut payload: Vec<u8>) -> Result<BrokerResponse, ClientError> {
    if payload.contains(&0) {
        payload.zeroize();
        return Err(ClientError::InvalidResponse);
    }
    Ok(BrokerResponse::Bytes(payload))
}
