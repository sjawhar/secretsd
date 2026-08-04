//! Secure creation flow for a new encrypted secrets file.

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::{Command, Stdio};

use nix::unistd::Uid;
use tempfile::{Builder, TempPath};
use zeroize::Zeroize;

use super::super::{CliError, runtime_dir};
use crate::secret::{SecretBytes, SecretName, parse_single_assignment};

const SCRUB_BLOCK: [u8; 8192] = [0; 8192];
const SCRUB_BLOCK_LEN: u64 = 8192;

pub(super) fn agent(path: &Path, local: bool) -> Result<(), CliError> {
    let role = if local {
        "# local agent-tier secrets\n"
    } else {
        "# shared agent-tier secrets\n"
    };
    create(path, role, None)
}

pub(super) fn human(path: &Path, name: &SecretName) -> Result<(), CliError> {
    create(path, &format!("{}=\n", name.as_str()), Some(name))
}

fn create(path: &Path, prefill: &str, human_name: Option<&SecretName>) -> Result<(), CliError> {
    let mut plaintext = PlaintextTemp::create()?;
    plaintext.write(prefill.as_bytes())?;
    run_editor(plaintext.path())?;
    plaintext.reopen_after_editor()?;
    if let Some(name) = human_name {
        validate_human(&mut plaintext, name)?;
    }
    encrypt(&mut plaintext, path)
}

fn run_editor(path: &Path) -> Result<(), CliError> {
    let editor = std::env::var_os("VISUAL")
        .filter(|value| !value.is_empty())
        .or_else(|| std::env::var_os("EDITOR").filter(|value| !value.is_empty()))
        .unwrap_or_else(|| OsString::from("vi"));
    let status = Command::new(editor)
        .arg(path)
        .status()
        .map_err(CliError::EditorStart)?;
    if status.success() {
        Ok(())
    } else {
        Err(CliError::EditorExited)
    }
}

fn validate_human(plaintext: &mut PlaintextTemp, name: &SecretName) -> Result<(), CliError> {
    let plaintext = plaintext.read()?;
    let value = parse_single_assignment(plaintext.as_slice(), name)
        .map_err(|_| CliError::InvalidEditedHumanSecret(name.clone()))?;
    if value.is_empty() {
        Err(CliError::EmptyEditedHumanSecret(name.clone()))
    } else {
        Ok(())
    }
}

fn encrypt(plaintext: &mut PlaintextTemp, target: &Path) -> Result<(), CliError> {
    let directory = target.parent().ok_or(CliError::InstallEditedSecret)?;
    let ciphertext = Builder::new()
        .prefix(".secretsd-ciphertext-")
        .tempfile_in(directory)
        .map_err(|_| CliError::InstallEditedSecret)?;
    let input = plaintext.duplicate_at_start()?;
    let output = ciphertext
        .as_file()
        .try_clone()
        .map_err(|_| CliError::InstallEditedSecret)?;
    let mut child = Command::new("sops")
        .current_dir(directory)
        .arg("encrypt")
        .arg("--filename-override")
        .arg(target)
        .args(["--input-type", "dotenv", "--output-type", "dotenv"])
        .stdin(Stdio::from(input))
        .stdout(Stdio::from(output))
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| CliError::EncryptEditedSecret(target.to_path_buf()))?;
    let stderr_result = child
        .stderr
        .take()
        .ok_or_else(|| CliError::EncryptEditedSecret(target.to_path_buf()))
        .and_then(|mut stderr| {
            std::io::copy(&mut stderr, &mut std::io::sink())
                .map(|_| ())
                .map_err(|_| CliError::EncryptEditedSecret(target.to_path_buf()))
        });
    let status = child
        .wait()
        .map_err(|_| CliError::EncryptEditedSecret(target.to_path_buf()))?;
    if stderr_result.is_err() || !status.success() {
        return Err(CliError::EncryptEditedSecret(target.to_path_buf()));
    }
    ciphertext
        .persist_noclobber(target)
        .map(|_| ())
        .map_err(|_| CliError::InstallEditedSecret)
}

/// A runtime-scoped plaintext edit file that is scrubbed before it is removed.
struct PlaintextTemp {
    path: TempPath,
    original: File,
    edited: Option<File>,
}

impl PlaintextTemp {
    fn create() -> Result<Self, CliError> {
        let file = Builder::new()
            .prefix(".secretsd-edit-")
            .tempfile_in(runtime_dir())
            .map_err(|_| CliError::EditTemp)?;
        file.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|_| CliError::EditTemp)?;
        let (original, path) = file.into_parts();
        Ok(Self {
            path,
            original,
            edited: None,
        })
    }

    fn path(&self) -> &Path {
        self.path.as_ref()
    }

    fn write(&mut self, contents: &[u8]) -> Result<(), CliError> {
        self.original
            .write_all(contents)
            .and_then(|()| self.original.sync_data())
            .map_err(|_| CliError::EditTemp)
    }

    fn reopen_after_editor(&mut self) -> Result<(), CliError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&self.path)
            .map_err(|_| CliError::EditTemp)?;
        let metadata = file.metadata().map_err(|_| CliError::EditTemp)?;
        if !metadata.is_file() || metadata.uid() != Uid::effective().as_raw() {
            return Err(CliError::EditTemp);
        }
        if metadata.mode() & 0o777 != 0o600 {
            file.set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|_| CliError::EditTemp)?;
        }
        self.edited = Some(file);
        Ok(())
    }

    fn read(&mut self) -> Result<SecretBytes, CliError> {
        let file = self.edited.as_mut().ok_or(CliError::EditTemp)?;
        file.seek(SeekFrom::Start(0))
            .map_err(|_| CliError::EditTemp)?;
        let mut bytes = Vec::new();
        if file.read_to_end(&mut bytes).is_err() {
            bytes.zeroize();
            return Err(CliError::EditTemp);
        }
        Ok(SecretBytes::from_vec(bytes))
    }

    fn duplicate_at_start(&mut self) -> Result<File, CliError> {
        let file = self.edited.as_mut().ok_or(CliError::EditTemp)?;
        file.seek(SeekFrom::Start(0))
            .map_err(|_| CliError::EditTemp)?;
        file.try_clone().map_err(|_| CliError::EditTemp)
    }

    fn scrub(file: &mut File) {
        let Ok(length) = file.metadata().map(|metadata| metadata.len()) else {
            return;
        };
        if file.seek(SeekFrom::Start(0)).is_err() {
            return;
        }
        let mut remaining = length;
        while remaining > 0 {
            let amount = remaining.min(SCRUB_BLOCK_LEN);
            let Ok(chunk_len) = usize::try_from(amount) else {
                return;
            };
            let Some(chunk) = SCRUB_BLOCK.get(..chunk_len) else {
                return;
            };
            if file.write_all(chunk).is_err() {
                return;
            }
            let Some(next) = remaining.checked_sub(amount) else {
                return;
            };
            remaining = next;
        }
        let _ = file.sync_data();
    }
}

impl Drop for PlaintextTemp {
    fn drop(&mut self) {
        if let Some(edited) = self.edited.as_mut() {
            Self::scrub(edited);
        }
        Self::scrub(&mut self.original);
        let _ = std::fs::remove_file(self.path());
    }
}
