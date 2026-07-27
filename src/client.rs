//! Shared Unix-socket protocol client used by the `secrets` CLI.

use std::io::{IsTerminal, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use zeroize::Zeroize;

use crate::proto::{MAX_FRAME_BYTES, PROTOCOL_VERSION};

const GET_TIMEOUT: Duration = Duration::from_secs(100);
const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);

mod agent;
pub mod cli;
mod error;
mod human;
mod response;
mod status;

pub use agent::AgentStore;
pub use error::CliError;
pub use human::{HumanClient, HumanNames};
pub use response::{BrokerResponse, ClientError, parse_response};

/// A lazily resolved path to the broker's Unix socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketPath(PathBuf);

impl SocketPath {
    /// Resolve a broker socket override, runtime-directory path, or per-user fallback.
    pub fn resolve(override_path: Option<&str>, runtime_dir: Option<&str>, uid: u32) -> Self {
        match (override_path, runtime_dir) {
            (Some(path), _) => Self(PathBuf::from(path)),
            (None, Some(directory)) => Self(Path::new(directory).join("secretsd.sock")),
            (None, None) => Self(PathBuf::from(format!("/run/user/{uid}/secretsd.sock"))),
        }
    }

    /// Borrow the resolved socket path.
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

impl AsRef<Path> for SocketPath {
    fn as_ref(&self) -> &Path {
        self.as_path()
    }
}

/// Typed client for the broker's versioned Unix-socket protocol.
#[derive(Debug, Clone)]
pub struct BrokerClient {
    socket_path: PathBuf,
    get_timeout: Duration,
    control_timeout: Duration,
}

impl BrokerClient {
    /// Build a client connected to `socket_path` on demand.
    pub fn new(socket_path: impl AsRef<Path>) -> Self {
        Self::with_timeouts(socket_path, GET_TIMEOUT, CONTROL_TIMEOUT)
    }

    fn with_timeouts(
        socket_path: impl AsRef<Path>,
        get_timeout: Duration,
        control_timeout: Duration,
    ) -> Self {
        Self {
            socket_path: socket_path.as_ref().to_path_buf(),
            get_timeout,
            control_timeout,
        }
    }

    #[cfg(test)]
    fn with_test_timeouts(
        socket_path: impl AsRef<Path>,
        get_timeout: Duration,
        control_timeout: Duration,
    ) -> Self {
        Self::with_timeouts(socket_path, get_timeout, control_timeout)
    }

    /// Resolve the broker socket only when a broker operation is requested.
    pub fn from_environment() -> Self {
        let socket_override = std::env::var("SECRETSD_SOCK").ok();
        let runtime_directory = std::env::var("XDG_RUNTIME_DIR").ok();
        let socket_path = SocketPath::resolve(
            socket_override.as_deref(),
            runtime_directory.as_deref(),
            nix::unistd::getuid().as_raw(),
        );
        Self::new(socket_path)
    }

    /// Verify that the connected broker speaks exactly this protocol version.
    pub fn hello(&self) -> Result<(), ClientError> {
        let version = PROTOCOL_VERSION.to_string();
        let request = format!("HELLO\tversion={version}");
        let BrokerResponse::Fields(fields) = self.request(&request)? else {
            return Err(ClientError::VersionHandshake);
        };
        // Fields this client does not consume are tolerated -- the daemon also
        // reports its instance id, which only a registering harness needs -- but
        // a missing or differing version must fail rather than degrade.
        if fields
            .split(' ')
            .any(|field| field.strip_prefix("version=") == Some(version.as_str()))
        {
            Ok(())
        } else {
            Err(ClientError::VersionHandshake)
        }
    }

    /// Complete a version handshake, then send one request and parse its typed response.
    pub fn call(&self, request: &str) -> Result<BrokerResponse, ClientError> {
        self.hello()?;
        self.request(request)
    }

    fn request(&self, request: &str) -> Result<BrokerResponse, ClientError> {
        let mut stream = UnixStream::connect(&self.socket_path).map_err(ClientError::Io)?;
        let timeout = if request.starts_with("GET\t") {
            self.get_timeout
        } else {
            self.control_timeout
        };
        stream
            .set_read_timeout(Some(timeout))
            .map_err(ClientError::Io)?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(ClientError::Io)?;
        write_request(&mut stream, request)?;
        response::read_response(stream)
    }
}

fn write_request(stream: &mut UnixStream, request: &str) -> Result<(), ClientError> {
    let request_is_valid = !request.is_empty()
        && request.len() <= MAX_FRAME_BYTES
        && request.is_ascii()
        && !request.contains(['\n', '\r', '\0']);
    if !request_is_valid {
        return Err(ClientError::InvalidRequest);
    }
    stream
        .write_all(request.as_bytes())
        .map_err(ClientError::Io)?;
    stream.write_all(b"\n").map_err(ClientError::Io)
}

/// Read a session token from an inherited token file without exposing its bytes in errors.
pub fn read_token_file(path: impl AsRef<Path>) -> Result<String, ClientError> {
    let mut bytes = std::fs::read(path).map_err(|_| ClientError::TokenFile)?;
    let token = std::str::from_utf8(&bytes)
        .ok()
        .filter(|value| !value.is_empty() && value.trim() == *value)
        .map(ToOwned::to_owned)
        .ok_or(ClientError::TokenFile);
    bytes.zeroize();
    token
}

/// Return the caller's terminal path when standard input is an interactive Unix terminal.
pub fn caller_tty() -> Option<String> {
    if !std::io::stdin().is_terminal() {
        return None;
    }
    let path = std::fs::read_link("/proc/self/fd/0").ok()?;
    let text = path.into_os_string().into_string().ok()?;
    text.starts_with("/dev/").then_some(text)
}

#[cfg(test)]
mod tests;
