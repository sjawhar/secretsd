//! Direct, daemon-independent access to agent-tier dotenv files.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use zeroize::Zeroize;

use super::CliError;
use crate::secret::{SecretBytes, SecretName};

/// Decrypts the unattended agent tier without connecting to `secretsd`.
#[derive(Debug, Clone)]
pub struct AgentStore {
    dotfiles_dir: PathBuf,
    sops_bin: OsString,
}

impl AgentStore {
    /// Construct an agent-tier store rooted at `dotfiles_dir`.
    pub fn new(dotfiles_dir: impl AsRef<Path>, sops_bin: impl Into<OsString>) -> Self {
        Self {
            dotfiles_dir: dotfiles_dir.as_ref().to_path_buf(),
            sops_bin: sops_bin.into(),
        }
    }

    /// Return a named agent-tier value, with the local overlay taking precedence.
    pub fn value(&self, name: &SecretName) -> Result<SecretBytes, CliError> {
        self.all()?
            .remove(name)
            .ok_or_else(|| CliError::MissingSecret(name.clone()))
    }

    /// Check encrypted dotenv key names without decrypting their values.
    pub fn contains(&self, name: &SecretName) -> Result<bool, CliError> {
        let local = self.dotfiles_dir.join("secrets.local.env");
        let shared = self.dotfiles_dir.join("secrets.env");
        for path in [&local, &shared] {
            if path.is_file() && Self::contains_name(path, name)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Decrypt every agent-tier assignment with local values winning on conflicts.
    pub fn all(&self) -> Result<BTreeMap<SecretName, SecretBytes>, CliError> {
        let mut values = BTreeMap::new();
        let local = self.dotfiles_dir.join("secrets.local.env");
        if local.is_file() {
            Self::merge_first_values(&mut values, self.decrypt_all(&local)?);
        }
        let shared = self.dotfiles_dir.join("secrets.env");
        if shared.is_file() {
            Self::merge_first_values(&mut values, self.decrypt_all(&shared)?);
        }
        Ok(values)
    }

    fn merge_first_values(
        destination: &mut BTreeMap<SecretName, SecretBytes>,
        source: BTreeMap<SecretName, SecretBytes>,
    ) {
        for (name, value) in source {
            destination.entry(name).or_insert(value);
        }
    }

    fn decrypt_all(&self, path: &Path) -> Result<BTreeMap<SecretName, SecretBytes>, CliError> {
        let mut output = Command::new(&self.sops_bin)
            .args(["-d", "--input-type", "dotenv", "--output-type", "dotenv"])
            .arg(path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
            .map_err(CliError::SopsStart)?;
        if !output.status.success() {
            output.stdout.zeroize();
            return Err(CliError::SopsFailed);
        }
        let parsed = parse_dotenv(&output.stdout);
        output.stdout.zeroize();
        parsed
    }

    fn contains_name(path: &Path, target: &SecretName) -> Result<bool, CliError> {
        let encrypted = fs::read(path).map_err(CliError::AgentKeySet)?;
        for line in encrypted.split(|byte| *byte == b'\n') {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            if line.is_empty() || line.first() == Some(&b'#') {
                continue;
            }
            let Some(separator) = line.iter().position(|byte| *byte == b'=') else {
                return Err(CliError::InvalidDotenv);
            };
            let raw_name = line.get(..separator).ok_or(CliError::InvalidDotenv)?;
            let name = std::str::from_utf8(raw_name).map_err(|_| CliError::InvalidDotenv)?;
            let name = SecretName::parse(name).map_err(|_| CliError::InvalidSecretName)?;
            if !name.as_str().starts_with("sops_") && name == *target {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

fn parse_dotenv(plaintext: &[u8]) -> Result<BTreeMap<SecretName, SecretBytes>, CliError> {
    let mut values = BTreeMap::new();
    for line in plaintext.split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() || line.first() == Some(&b'#') {
            continue;
        }
        let Some(separator) = line.iter().position(|byte| *byte == b'=') else {
            return Err(CliError::InvalidDotenv);
        };
        let (raw_name, raw_value) = line.split_at(separator);
        let name = std::str::from_utf8(raw_name).map_err(|_| CliError::InvalidDotenv)?;
        let name = SecretName::parse(name).map_err(|_| CliError::InvalidSecretName)?;
        let Some(value) = raw_value.strip_prefix(b"=") else {
            return Err(CliError::InvalidDotenv);
        };
        if value.contains(&b'\0') {
            return Err(CliError::InvalidDotenv);
        }
        values
            .entry(name)
            .or_insert_with(|| SecretBytes::from_vec(value.to_vec()));
    }
    Ok(values)
}
