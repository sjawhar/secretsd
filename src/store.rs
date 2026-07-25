//! The human-tier secret directory (`secrets.human.d`).
//!
//! Listing reads file names only. Nothing in this module decrypts, so listing
//! cannot cause a `YubiKey` interaction.

use std::os::fd::{AsRawFd, FromRawFd};
use std::path::PathBuf;

use nix::fcntl::{OFlag, openat};
use nix::sys::stat::{Mode, SFlag, fstat};

use crate::proto::ErrCode;
use crate::secret::SecretName;

/// A directory of per-key sops files.
#[derive(Debug, Clone)]
pub struct HumanStore {
    dir: PathBuf,
}

impl HumanStore {
    /// Point the store at a directory. The directory need not exist yet.
    pub const fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// Key names present in the store, derived from file names only.
    pub fn key_names(&self) -> Result<Vec<SecretName>, ErrCode> {
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(_) => return Err(ErrCode::Internal),
        };
        let mut names = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|_| ErrCode::Internal)?;
            let file_name = entry.file_name();
            let Some(text) = file_name.to_str() else {
                continue;
            };
            let Some(stem) = text.strip_suffix(".env") else {
                continue;
            };
            if let Ok(name) = SecretName::parse(stem) {
                names.push(name);
            }
        }
        Ok(names)
    }

    /// Whether a key exists in the store.
    pub fn contains(&self, name: &SecretName) -> bool {
        self.key_names().is_ok_and(|names| names.contains(name))
    }

    /// Open a key's ciphertext file without following symlinks.
    pub fn open(&self, name: &SecretName) -> Result<std::fs::File, ErrCode> {
        let dir = std::fs::File::open(&self.dir).map_err(|_| ErrCode::NotHumanKey)?;
        let raw_fd = openat(
            Some(dir.as_raw_fd()),
            name.file_name().as_str(),
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
        Ok(file)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::*;

    fn name(raw: &str) -> SecretName {
        SecretName::parse(raw).unwrap()
    }

    fn fixture() -> (tempfile::TempDir, HumanStore) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("DEEL_API_KEY.env"), b"ciphertext").unwrap();
        std::fs::write(dir.path().join("FLEET_LICENSE_KEY.env"), b"ciphertext").unwrap();
        std::fs::write(dir.path().join("notes.txt"), b"ignored").unwrap();
        std::os::unix::fs::symlink("/etc/passwd", dir.path().join("EVIL_LINK.env")).unwrap();
        std::fs::create_dir(dir.path().join("A_DIR.env")).unwrap();
        let store = HumanStore::new(dir.path().to_path_buf());
        (dir, store)
    }

    #[test]
    fn lists_key_names_from_file_names_only() {
        let (_dir, store) = fixture();
        let mut names: Vec<String> = store
            .key_names()
            .unwrap()
            .iter()
            .map(|name| name.as_str().to_owned())
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec!["A_DIR", "DEEL_API_KEY", "EVIL_LINK", "FLEET_LICENSE_KEY"]
        );
    }

    #[test]
    fn listing_missing_directory_yields_no_keys() {
        let store = HumanStore::new("/nonexistent/secretsd-test".into());
        assert_eq!(store.key_names().unwrap(), Vec::new());
    }

    #[test]
    fn opens_regular_file() {
        let (_dir, store) = fixture();
        let mut file = store.open(&name("DEEL_API_KEY")).unwrap();
        let mut buffer = String::new();
        file.read_to_string(&mut buffer).unwrap();
        assert_eq!(buffer, "ciphertext");
    }

    #[test]
    fn refuses_to_follow_symlink() {
        let (_dir, store) = fixture();
        assert_eq!(
            store.open(&name("EVIL_LINK")).err(),
            Some(ErrCode::NotHumanKey)
        );
    }

    #[test]
    fn refuses_directory() {
        let (_dir, store) = fixture();
        assert_eq!(store.open(&name("A_DIR")).err(), Some(ErrCode::NotHumanKey));
    }

    #[test]
    fn refuses_absent_key() {
        let (_dir, store) = fixture();
        assert_eq!(store.open(&name("NOPE")).err(), Some(ErrCode::NotHumanKey));
    }

    #[test]
    fn contains_reports_presence() {
        let (_dir, store) = fixture();
        assert!(store.contains(&name("DEEL_API_KEY")));
        assert!(!store.contains(&name("NOPE")));
    }
}
