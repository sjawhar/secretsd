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
    files: Vec<PathBuf>,
    sops_bin: OsString,
}

impl AgentStore {
    /// Decrypts an ordered list of sops dotenv files; earlier files win on duplicate names.
    pub fn new(files: Vec<PathBuf>, sops_bin: impl Into<OsString>) -> Self {
        Self {
            files,
            sops_bin: sops_bin.into(),
        }
    }

    /// Return a named agent-tier value, with earlier files taking precedence.
    pub fn value(&self, name: &SecretName) -> Result<SecretBytes, CliError> {
        self.all()?
            .remove(name)
            .ok_or_else(|| CliError::MissingSecret(name.clone()))
    }

    /// Check encrypted dotenv key names without decrypting their values.
    pub fn contains(&self, name: &SecretName) -> Result<bool, CliError> {
        for path in &self.files {
            if path.is_file() && Self::names_in(path)?.contains(name) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Decrypt every agent-tier assignment with earlier files winning on conflicts.
    pub fn all(&self) -> Result<BTreeMap<SecretName, SecretBytes>, CliError> {
        let mut values = BTreeMap::new();
        for path in &self.files {
            if path.is_file() {
                Self::merge_first_values(&mut values, self.decrypt_all(path)?);
            }
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

    /// Read non-metadata agent-tier key names without decrypting their values.
    pub(crate) fn names_in(path: &Path) -> Result<Vec<SecretName>, CliError> {
        let encrypted = fs::read(path).map_err(CliError::AgentKeySet)?;
        let mut names = Vec::new();
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
            if !name.as_str().starts_with("sops_") {
                names.push(name);
            }
        }
        Ok(names)
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

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    use super::{AgentStore, CliError};
    use crate::secret::SecretName;

    fn name(raw: &str) -> SecretName {
        SecretName::parse(raw).unwrap()
    }

    fn fake_sops(directory: &tempfile::TempDir) -> PathBuf {
        let path = directory.path().join("fake-sops");
        fs::write(&path, b"#!/bin/bash\ncat \"${!#}\"\n").unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&path, permissions).unwrap();
        path
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn earlier_file_wins_when_a_key_reappears_in_a_later_file() {
        let directory = tempfile::tempdir().unwrap();
        let first = directory.path().join("first.env");
        let second = directory.path().join("second.env");
        let third = directory.path().join("third.env");
        fs::write(&first, b"KEY=first\n").unwrap();
        fs::write(&second, b"OTHER=second\n").unwrap();
        fs::write(&third, b"KEY=third\n").unwrap();
        let store = AgentStore::new(vec![first, second, third], fake_sops(&directory));

        let value = store.value(&name("KEY")).unwrap();

        assert_eq!(value.as_slice(), b"first");
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn listed_but_absent_file_is_skipped() {
        let directory = tempfile::tempdir().unwrap();
        let absent = directory.path().join("absent.env");
        let present = directory.path().join("present.env");
        fs::write(&present, b"KEY=present\n").unwrap();
        let store = AgentStore::new(vec![absent, present], fake_sops(&directory));

        let value = store.value(&name("KEY")).unwrap();

        assert_eq!(value.as_slice(), b"present");
    }

    #[test]
    fn empty_file_list_reports_missing_secret() {
        let name = name("KEY");
        let store = AgentStore::new(Vec::new(), "sops");

        let result = store.value(&name);

        assert!(matches!(result, Err(CliError::MissingSecret(actual)) if actual == name));
    }
}
