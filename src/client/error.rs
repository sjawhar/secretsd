use std::fmt;

use super::ClientError;
use crate::proto::ErrCode;
use crate::secret::SecretName;

const AGENT_NOTICE: &str = "AGENT NOTICE: ask the human; do not retry-loop.";

/// A CLI failure that never renders plaintext secret or session-token bytes.
#[derive(Debug)]
#[non_exhaustive]
pub enum CliError {
    /// The command line did not match the compatible CLI surface.
    Usage,
    /// A key name does not satisfy `[A-Za-z_][A-Za-z0-9_]*`.
    InvalidSecretName,
    /// A requested agent-tier key was absent.
    MissingSecret(SecretName),
    /// A key exists in both storage tiers and access is denied.
    AmbiguousKey(SecretName),
    /// Starting `sops` failed.
    SopsStart(std::io::Error),
    /// `sops` exited unsuccessfully.
    SopsFailed,
    /// Decrypted dotenv bytes were malformed or unsafe.
    InvalidDotenv,
    /// Reading encrypted agent-tier key names failed.
    AgentKeySet(std::io::Error),
    /// Reading the human-tier directory failed.
    HumanDirectory(std::io::Error),
    /// A human-tier filename was not a valid key name.
    InvalidHumanFile,
    /// The broker rejected the request with a stable protocol error code.
    Broker(ErrCode),
    /// Broker transport or framing failed before an error code was available.
    BrokerTransport(ClientError),
    /// Replacing the process for an edit or injection command failed.
    Exec(std::io::Error),
    /// Writing command output to standard output failed.
    Stdout(std::io::Error),
}

impl CliError {
    /// Convert a stable broker error code to retry-safe agent guidance.
    pub const fn from_broker(code: ErrCode) -> Self {
        Self::Broker(code)
    }

    /// Convert a broker client failure without exposing request credentials.
    pub fn from_client(error: ClientError) -> Self {
        match error {
            ClientError::Broker(code) => Self::from_broker(code),
            error => Self::BrokerTransport(error),
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage => formatter.write_str(
                "usage: secrets get KEY [--value|--no-request] | secrets list | secrets grants | secrets deny ID | secrets lock | secrets KEY1 [KEY2 ...] -- command [args...]",
            ),
            Self::InvalidSecretName => formatter.write_str("invalid secret key"),
            Self::MissingSecret(name) => write!(formatter, "secret '{}' not found", name.as_str()),
            Self::AmbiguousKey(name) => write!(
                formatter,
                "key '{}' exists in both agent and human tiers; refusing ambiguous access",
                name.as_str()
            ),
            Self::SopsStart(error) => write!(formatter, "could not start sops: {error}"),
            Self::SopsFailed => formatter.write_str("sops could not decrypt the agent-tier secrets"),
            Self::InvalidDotenv => formatter.write_str("sops returned invalid dotenv data"),
            Self::AgentKeySet(error) => write!(formatter, "could not read agent-tier key set: {error}"),
            Self::HumanDirectory(error) => write!(formatter, "could not list human-tier keys: {error}"),
            Self::InvalidHumanFile => {
                formatter.write_str("human-tier directory contains an invalid key filename")
            }
            Self::Broker(code) => write!(formatter, "{AGENT_NOTICE} {}", broker_guidance(*code)),
            Self::BrokerTransport(error) => write!(formatter, "{AGENT_NOTICE} {error}"),
            Self::Exec(error) => write!(formatter, "could not execute command: {error}"),
            Self::Stdout(error) => write!(formatter, "could not write secret value: {error}"),
        }
    }
}

impl std::error::Error for CliError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SopsStart(error)
            | Self::AgentKeySet(error)
            | Self::HumanDirectory(error)
            | Self::Exec(error)
            | Self::Stdout(error) => Some(error),
            Self::BrokerTransport(error) => Some(error),
            Self::Usage
            | Self::InvalidSecretName
            | Self::MissingSecret(_)
            | Self::AmbiguousKey(_)
            | Self::SopsFailed
            | Self::InvalidDotenv
            | Self::InvalidHumanFile
            | Self::Broker(_) => None,
        }
    }
}

const fn broker_guidance(code: ErrCode) -> &'static str {
    match code {
        ErrCode::BadRequest => {
            "secretsd rejected a malformed request; the human should update or restart the client and daemon."
        }
        ErrCode::UnknownOp => {
            "this client requested an unsupported operation; the human should update the client and daemon together."
        }
        ErrCode::VersionMismatch => {
            "the client and daemon speak different protocol versions; ask the human to run the secretsd installer, which replaces the binary and restarts the daemon, and then to restart OpenCode so its plugin matches."
        }
        ErrCode::UnknownToken => {
            "the broker restarted, losing this session's registration and every grant. The OpenCode plugin re-registers on the next command, so run this command once more -- once, not in a loop -- and expect the human's key to blink, because the first request after a restart needs a fresh touch."
        }
        ErrCode::NoScope => {
            "there is neither a terminal tty nor a session token. This is what non-interactive ssh host 'secrets get KEY' produces; run from a human terminal with a tty or use the OpenCode token path."
        }
        ErrCode::AgentTty => {
            "a tokenless request came from a known agent terminal; use the OpenCode token path instead."
        }
        ErrCode::ForeignCaller => {
            "this session's token was presented from outside that session's process tree, so it was refused; run the request from the session that owns the token."
        }
        ErrCode::NotHumanKey => {
            "the requested human-tier key is missing or was moved; ask the human to check its encrypted file."
        }
        ErrCode::Denied => "the human declined the secret request.",
        ErrCode::Timeout => {
            "the human did not approve the request before it expired; wait for the human instead of retrying."
        }
        ErrCode::YubikeyUnreachable => {
            "the configured YubiKey path is unavailable; ask the human to connect the required hardware path."
        }
        ErrCode::TooManyPending => {
            "this scope already has too many pending requests; stop retrying and wait for the human."
        }
        ErrCode::Internal => {
            "the broker could not complete the request, including a failure to spawn sops; the human should inspect journalctl --user -u secretsd for the daemon's logged sops stderr."
        }
    }
}
