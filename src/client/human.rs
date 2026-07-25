//! Filename-only discovery for the human tier.

use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;

use zeroize::Zeroizing;

use super::{BrokerClient, BrokerResponse, CliError, ClientError, caller_tty, read_token_file};
use crate::secret::{SecretBytes, SecretName};

/// Validated human-tier key names discovered without reading ciphertext files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HumanNames(BTreeSet<SecretName>);

/// Broker-backed access to a human-tier secret for one caller scope.
pub struct HumanClient {
    broker: BrokerClient,
    token: Option<Zeroizing<String>>,
    tty: Option<String>,
}

impl fmt::Debug for HumanClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HumanClient")
            .field("broker", &self.broker)
            .field("has_token", &self.token.is_some())
            .field("tty", &self.tty)
            .finish()
    }
}

impl HumanClient {
    /// Construct a scoped human-tier client.
    pub fn new(broker: BrokerClient, token: Option<String>, tty: Option<String>) -> Self {
        Self {
            broker,
            token: token.map(Zeroizing::new),
            tty,
        }
    }

    /// Read the inherited token-file path and terminal scope only for a human request.
    pub fn from_environment() -> Result<Self, ClientError> {
        let token = match std::env::var_os("SECRETSD_SESSION_TOKEN_FILE") {
            Some(path) => Some(read_token_file(path)?),
            None => None,
        };
        Ok(Self::new(
            BrokerClient::from_environment(),
            token,
            caller_tty(),
        ))
    }

    /// Request a human-tier value, blocking until the broker reaches its terminal response.
    pub fn get(&self, key: &SecretName) -> Result<SecretBytes, ClientError> {
        let mut request = Zeroizing::new(format!("GET\tkey={}", key.as_str()));
        if let Some(token) = &self.token {
            request.push_str("\ttoken=");
            request.push_str(token);
        }
        if let Some(tty) = &self.tty {
            request.push_str("\ttty=");
            request.push_str(tty);
        }
        match self.broker.call(&request) {
            Ok(BrokerResponse::Bytes(bytes)) => Ok(SecretBytes::from_vec(bytes)),
            Ok(BrokerResponse::Ok | BrokerResponse::Fields(_)) => Err(ClientError::InvalidResponse),
            Err(error) => Err(error),
        }
    }
}

impl HumanNames {
    /// Read validated `*.env` file stems from `directory` without opening the files.
    pub fn load(directory: &Path) -> Result<Self, CliError> {
        if !directory.is_dir() {
            return Ok(Self(BTreeSet::new()));
        }
        let mut names = BTreeSet::new();
        for entry in std::fs::read_dir(directory).map_err(CliError::HumanDirectory)? {
            let entry = entry.map_err(CliError::HumanDirectory)?;
            let path = entry.path();
            if path.extension().is_some_and(|extension| extension == "env") {
                let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
                    return Err(CliError::InvalidHumanFile);
                };
                let name = SecretName::parse(stem).map_err(|_| CliError::InvalidHumanFile)?;
                names.insert(name);
            }
        }
        Ok(Self(names))
    }

    /// Test whether a key belongs to the human tier.
    pub fn contains(&self, name: &SecretName) -> bool {
        self.0.contains(name)
    }

    /// Iterate names in stable lexical order.
    pub fn iter(&self) -> impl Iterator<Item = &SecretName> {
        self.0.iter()
    }
}
