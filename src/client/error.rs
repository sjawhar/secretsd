use std::fmt;
use std::path::PathBuf;

use super::ClientError;
use crate::config::ConfigError;
use crate::proto::ErrCode;
use crate::secret::SecretName;

const AGENT_NOTICE: &str = "AGENT NOTICE: ask the human; do not retry-loop.";

/// A CLI failure that never renders plaintext secret or session-token bytes.
#[derive(Debug)]
#[non_exhaustive]
pub enum CliError {
    /// The command line did not match the compatible CLI surface.
    Usage,
    /// Source-root configuration could not be loaded.
    Config(ConfigError),
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
    /// A key occurs in more than one configured human-tier location.
    DuplicateHumanKey {
        /// Duplicated key name.
        name: SecretName,
        /// First source label in configuration order.
        first: String,
        /// Conflicting source label.
        second: String,
    },
    /// An edit requires a source name because more than one root is configured.
    EditSourceRequired(String),
    /// An edit named no configured source root.
    UnknownEditSource {
        /// Operator-provided source-root name.
        source: String,
        /// Configured source-root names.
        available: String,
    },
    /// An edit flag contradicted an existing human-tier key location.
    EditConflict {
        /// Existing key name.
        name: SecretName,
        /// Actual source label, including `.local` when applicable.
        actual: String,
    },
    /// Creating or opening the private edit scratch file failed.
    EditTemp,
    /// Starting the selected editor failed.
    EditorStart(std::io::Error),
    /// The selected editor exited without producing an accepted edit.
    EditorExited,
    /// A newly created human secret did not retain its required one-key shape.
    InvalidEditedHumanSecret(SecretName),
    /// A newly created human secret retained an empty value.
    EmptyEditedHumanSecret(SecretName),
    /// Encrypting a newly created secret failed for its target file.
    EncryptEditedSecret(PathBuf),
    /// Atomically installing the new ciphertext failed.
    InstallEditedSecret,
    /// Reading the piped secret value failed.
    PipedHumanRead(std::io::Error),
    /// A piped human secret retained an empty value.
    EmptyPipedHumanSecret(SecretName),
    /// A piped human secret was not one assignment for its requested key.
    InvalidPipedHumanSecret(SecretName),
    /// Disabling core dumps before reading a piped secret failed.
    Hardening(crate::hardening::HardeningError),
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
                "usage: secrets get KEY [--value|--no-request] | secrets list | secrets sources | secrets edit [--source NAME] | secrets edit-local [--source NAME] | secrets edit-human KEY [--source NAME] [--local] | secrets grants | secrets deny ID | secrets lock | secrets KEY1 [KEY2 ...] -- command [args...]",
            ),
            Self::Config(error) => error.fmt(formatter),
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
            Self::DuplicateHumanKey {
                name,
                first,
                second,
            } => write!(
                formatter,
                "key '{}' exists in more than one human-tier location ({first}, {second}); remove or rename one file",
                name.as_str()
            ),
            Self::EditSourceRequired(available) => write!(
                formatter,
                "multiple secrets sources are configured; pass --source NAME (available: {available})"
            ),
            Self::UnknownEditSource { source, available } => write!(
                formatter,
                "secrets source '{source}' is not configured (available: {available})"
            ),
            Self::EditConflict { name, actual } => write!(
                formatter,
                "edit flags conflict with key '{}' stored in source {actual}",
                name.as_str()
            ),
            Self::EditTemp => formatter.write_str("could not prepare a private edit file"),
            Self::EditorStart(error) => write!(formatter, "could not start editor: {error}"),
            Self::EditorExited => formatter.write_str("editor exited without creating a secret"),
            Self::InvalidEditedHumanSecret(name) => write!(
                formatter,
                "edited secret must contain exactly one assignment named '{}'",
                name.as_str()
            ),
            Self::EmptyEditedHumanSecret(name) => {
                write!(formatter, "edited secret '{}' value must not be empty", name.as_str())
            }
            Self::EncryptEditedSecret(target) => write!(
                formatter,
                "could not encrypt edited secret for '{}'; ensure .sops.yaml has a matching creation rule",
                target.display()
            ),
            Self::InstallEditedSecret => formatter.write_str("could not install encrypted secret"),
            Self::PipedHumanRead(error) => write!(formatter, "could not read piped secret: {error}"),
            Self::EmptyPipedHumanSecret(name) => {
                write!(formatter, "piped secret '{}' value must not be empty", name.as_str())
            }
            Self::InvalidPipedHumanSecret(name) => write!(
                formatter,
                "piped secret '{}' must be one single-line assignment value",
                name.as_str()
            ),
            Self::Hardening(error) => write!(formatter, "could not disable core dumps: {error}"),
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
            | Self::Stdout(error)
            | Self::EditorStart(error)
            | Self::PipedHumanRead(error) => Some(error),
            Self::Hardening(error) => Some(error),
            Self::Config(error) => Some(error),
            Self::BrokerTransport(error) => Some(error),
            Self::Usage
            | Self::InvalidSecretName
            | Self::MissingSecret(_)
            | Self::AmbiguousKey(_)
            | Self::SopsFailed
            | Self::InvalidDotenv
            | Self::InvalidHumanFile
            | Self::DuplicateHumanKey { .. }
            | Self::EditSourceRequired(_)
            | Self::UnknownEditSource { .. }
            | Self::EditConflict { .. }
            | Self::EditTemp
            | Self::EditorExited
            | Self::InvalidEditedHumanSecret(_)
            | Self::EmptyEditedHumanSecret(_)
            | Self::EncryptEditedSecret(_)
            | Self::InstallEditedSecret
            | Self::EmptyPipedHumanSecret(_)
            | Self::InvalidPipedHumanSecret(_)
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
            "the client and daemon speak different protocol versions; ask the human to move both halves to the same release -- the `secrets` binary and the tag OpenCode pins for its plugin -- then restart the daemon with `systemctl --user restart secretsd.service` and restart OpenCode. Restarting OpenCode while its plugin pin still names the old tag re-fetches the same mismatched plugin, so updating only one half leaves this error in place."
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
            "the requested human-tier key is missing or was moved; ask the human to check its encrypted file. If config.toml just gained a new source root, restart secretsd (systemctl --user restart secretsd.service)."
        }
        ErrCode::AmbiguousKey => {
            "the requested key exists in more than one human-tier location; ask the human to remove or rename one of the duplicate files -- run `secrets list` to see every source."
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
