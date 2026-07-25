//! Filename-only discovery for the human tier.

use std::collections::BTreeSet;
use std::path::Path;

use super::cli::CliError;
use crate::secret::SecretName;

/// Validated human-tier key names discovered without reading ciphertext files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HumanNames(BTreeSet<SecretName>);

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
