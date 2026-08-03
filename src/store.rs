//! The human-tier secret directory (`secrets.human.d`).
//!
//! Listing reads file names only. Nothing in this module decrypts, so listing
//! cannot cause a `YubiKey` interaction.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::{Path, PathBuf};

use nix::fcntl::{OFlag, openat};
use nix::sys::stat::{Mode, SFlag, fstat};

use crate::audit::sanitize_audit_value;
use crate::proto::ErrCode;
use crate::secret::{HumanFileName, SecretName, parse_human_file_name};

/// A named directory containing human-tier ciphertext files.
#[derive(Debug, Clone)]
#[allow(
    clippy::exhaustive_structs,
    reason = "source labels and paths are an explicit configuration data contract"
)]
pub struct HumanSource {
    /// Stable label identifying the configured source root.
    pub label: String,
    /// Human-tier directory below the configured source root.
    pub dir: PathBuf,
}

/// A human-tier ciphertext file and the source label derived from the same scan.
///
/// Two source labels exist on a granted request: the request audit line
/// carries dispatch's pre-approval `locate` label, while the worker's
/// `grant inserted` event carries this label, taken from the scan that
/// opened the decrypted file. When the two disagree, the file moved between
/// sources during the approval window -- trust this one for attribution.
#[derive(Debug)]
#[allow(
    clippy::exhaustive_structs,
    reason = "the source label must stay paired with the opened ciphertext file"
)]
pub struct OpenedHumanFile {
    /// Label identifying the configured root, with `.local` for local files.
    pub label: String,
    /// Validated ciphertext file opened without following symlinks.
    pub file: std::fs::File,
}

#[derive(Debug)]
struct Candidate {
    label: String,
    dir: PathBuf,
    file_name: String,
}

/// A directory of per-key sops files.
#[derive(Debug, Clone)]
pub struct HumanStore {
    sources: Vec<HumanSource>,
}

impl HumanStore {
    /// Point the store at configured source directories. They need not exist yet.
    pub const fn new(sources: Vec<HumanSource>) -> Self {
        Self { sources }
    }

    /// Key names present in configured sources, derived from file names only.
    ///
    /// This supports tests and a future LIST operation; access authorization must use `locate` so ambiguity is refused.
    pub fn key_names(&self) -> Result<Vec<SecretName>, ErrCode> {
        let mut names = BTreeSet::new();
        for source in &self.sources {
            let Some(entries) = Self::directory_entries(&source.dir)? else {
                continue;
            };
            for entry in entries {
                let entry = entry.map_err(|_| ErrCode::Internal)?;
                let Some((name, _, _)) = Self::human_file_name(source, &entry.file_name())? else {
                    continue;
                };
                names.insert(name);
            }
        }
        Ok(names.into_iter().collect())
    }

    /// Locate the sole backing file for a key and return its audit label.
    pub fn locate(&self, name: &SecretName) -> Result<String, ErrCode> {
        let candidates = self.candidates(name)?;
        match candidates.as_slice() {
            [] => Err(ErrCode::NotHumanKey),
            [candidate] => Ok(candidate.label.clone()),
            [..] => Err(ErrCode::AmbiguousKey),
        }
    }

    /// Open a key's ciphertext file without following symlinks.
    pub fn open(&self, name: &SecretName) -> Result<OpenedHumanFile, ErrCode> {
        let candidates = self.candidates(name)?;
        let candidate = match candidates.as_slice() {
            [] => return Err(ErrCode::NotHumanKey),
            [candidate] => candidate,
            [..] => return Err(ErrCode::AmbiguousKey),
        };
        let dir = std::fs::File::open(&candidate.dir).map_err(|_| ErrCode::NotHumanKey)?;
        let raw_fd = openat(
            Some(dir.as_raw_fd()),
            candidate.file_name.as_str(),
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ErrCode::NotHumanKey)?;
        // SAFETY: `openat` returned a new, valid file descriptor exclusively
        // owned by this call. No other owner is created before this conversion,
        // and the resulting `File` takes exactly one close-on-drop obligation.
        let file = unsafe { std::fs::File::from_raw_fd(raw_fd) };
        let stat = fstat(file.as_raw_fd()).map_err(|_| ErrCode::NotHumanKey)?;
        if !SFlag::from_bits_truncate(stat.st_mode).contains(SFlag::S_IFREG) {
            return Err(ErrCode::NotHumanKey);
        }
        Ok(OpenedHumanFile {
            label: candidate.label.clone(),
            file,
        })
    }

    fn candidates(&self, requested: &SecretName) -> Result<Vec<Candidate>, ErrCode> {
        let mut candidates = Vec::new();
        for source in &self.sources {
            let Some(entries) = Self::directory_entries(&source.dir)? else {
                continue;
            };
            for entry in entries {
                let entry = entry.map_err(|_| ErrCode::Internal)?;
                let Some((name, local, file_name)) =
                    Self::human_file_name(source, &entry.file_name())?
                else {
                    continue;
                };
                if &name == requested {
                    candidates.push(Candidate {
                        label: if local {
                            format!("{}.local", source.label)
                        } else {
                            source.label.clone()
                        },
                        dir: source.dir.clone(),
                        file_name,
                    });
                }
            }
        }
        Ok(candidates)
    }

    fn directory_entries(dir: &Path) -> Result<Option<std::fs::ReadDir>, ErrCode> {
        match std::fs::read_dir(dir) {
            Ok(entries) => Ok(Some(entries)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(ErrCode::Internal),
        }
    }

    fn human_file_name(
        source: &HumanSource,
        file_name: &OsString,
    ) -> Result<Option<(SecretName, bool, String)>, ErrCode> {
        let Some(text) = file_name.to_str() else {
            return Ok(None);
        };
        match parse_human_file_name(text) {
            HumanFileName::Ignored => Ok(None),
            HumanFileName::Invalid => {
                tracing::warn!(
                    source = %sanitize_audit_value(&source.label),
                    file_name = %sanitize_audit_value(text),
                    "invalid human filename"
                );
                Err(ErrCode::Internal)
            }
            HumanFileName::Key { name, local } => Ok(Some((name, local, text.to_owned()))),
        }
    }
}

#[cfg(test)]
mod tests;
