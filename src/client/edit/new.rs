//! Secure creation flow for a new encrypted secrets file.

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::{ChildStdout, Command, Stdio};

use nix::fcntl::{Flock, FlockArg};
use nix::sys::signal::{Signal, kill};
use nix::unistd::{Pid, Uid};
use tempfile::{Builder, TempPath};
use zeroize::Zeroize;

use super::super::{CliError, runtime_dir};
use crate::secret::{SecretBytes, SecretName, parse_single_assignment};

const SCRUB_BLOCK: [u8; 8192] = [0; 8192];
const MAX_SOPS_CIPHERTEXT_BYTES: u64 = 1024 * 1024;

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
/// Store a human-tier key from a non-terminal standard input stream.
///
/// Concurrent calls serialize on the target directory; the last writer wins,
/// and each completed write is atomic. Rotation replaces the ciphertext inode,
/// so `HumanStore` detects the changed `FileIdentity` and revokes stale grants.
pub(super) fn write_piped_human(path: &Path, name: &SecretName) -> Result<(), CliError> {
    crate::hardening::apply_no_core_dumps().map_err(CliError::Hardening)?;
    let assignment = read_piped_assignment(name)?;
    let directory = path.parent().ok_or(CliError::InstallEditedSecret)?;
    let directory = File::open(directory).map_err(|_| CliError::InstallEditedSecret)?;
    let _lock = Flock::lock(directory, FlockArg::LockExclusive)
        .map_err(|_| CliError::InstallEditedSecret)?;
    let rotated = path.exists();
    encrypt_bytes(&assignment, path)?;
    let action = if rotated { "rotated" } else { "created" };
    writeln!(std::io::stdout().lock(), "{action} {}", path.display()).map_err(CliError::Stdout)
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
fn read_piped_assignment(name: &SecretName) -> Result<SecretBytes, CliError> {
    let stdin = std::io::stdin();

    let mut value = Vec::new();
    let read_result = stdin.lock().read_to_end(&mut value);
    if let Err(error) = read_result {
        value.zeroize();
        return Err(CliError::PipedHumanRead(error));
    }
    if value.last() == Some(&b'\n') {
        let _ = value.pop();
        if value.last() == Some(&b'\r') {
            let _ = value.pop();
        }
    }
    if value.is_empty() {
        value.zeroize();
        return Err(CliError::EmptyPipedHumanSecret(name.clone()));
    }
    if value.contains(&b'\n') || value.contains(&b'\r') {
        value.zeroize();
        return Err(CliError::InvalidPipedHumanSecret(name.clone()));
    }

    let mut assignment = Vec::new();
    assignment.extend_from_slice(name.as_str().as_bytes());
    assignment.push(b'=');
    assignment.extend_from_slice(&value);
    assignment.push(b'\n');
    value.zeroize();
    let assignment = SecretBytes::from_vec(assignment);
    if parse_single_assignment(assignment.as_slice(), name).is_err() {
        return Err(CliError::InvalidPipedHumanSecret(name.clone()));
    }
    Ok(assignment)
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
    let mut child = sops_encrypt_command(directory, target)
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

fn sops_encrypt_command(directory: &Path, target: &Path) -> Command {
    let mut command = Command::new("sops");
    command
        .current_dir(directory)
        .arg("encrypt")
        .arg("--filename-override")
        .arg(target)
        .args(["--input-type", "dotenv", "--output-type", "dotenv"]);
    command
}

/// Why draining the sops child's stdout failed, so the caller can say which.
enum DrainFailure {
    /// Reading the pipe failed outright.
    Read,
    /// The child produced more than `MAX_SOPS_CIPHERTEXT_BYTES`.
    TooLarge,
}

fn drain_sops_stdout(mut stdout: ChildStdout, process_id: Pid) -> Result<Vec<u8>, DrainFailure> {
    let mut output = Vec::new();
    let read_result = stdout
        .by_ref()
        .take(MAX_SOPS_CIPHERTEXT_BYTES + 1)
        .read_to_end(&mut output);
    let output_too_large =
        u64::try_from(output.len()).map_or(true, |length| length > MAX_SOPS_CIPHERTEXT_BYTES);
    if read_result.is_err() || output_too_large {
        output.zeroize();
        let _ = kill(process_id, Signal::SIGKILL);
        return Err(if read_result.is_err() {
            DrainFailure::Read
        } else {
            DrainFailure::TooLarge
        });
    }
    Ok(output)
}

fn encrypt_bytes(plaintext: &SecretBytes, target: &Path) -> Result<(), CliError> {
    let directory = target.parent().ok_or(CliError::InstallEditedSecret)?;
    let mut child = sops_encrypt_command(directory, target)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| CliError::EncryptEditedSecret(target.to_path_buf()))?;
    let process_id = i32::try_from(child.id())
        .map(Pid::from_raw)
        .map_err(|_| CliError::EncryptEditedSecret(target.to_path_buf()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| CliError::EncryptEditedSecret(target.to_path_buf()))?;
    let stdout_reader = std::thread::spawn(move || drain_sops_stdout(stdout, process_id));
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| CliError::EncryptEditedSecret(target.to_path_buf()))?;
    let stderr_reader =
        std::thread::spawn(move || std::io::copy(&mut stderr, &mut std::io::sink()));
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| CliError::EncryptEditedSecret(target.to_path_buf()))?;
    let write_result = stdin.write_all(plaintext.as_slice());
    drop(stdin);
    let status = child.wait();
    let stdout_result = stdout_reader.join();
    let stderr_result = stderr_reader.join();
    let mut output = match stdout_result {
        Ok(Ok(output)) => output,
        Ok(Err(DrainFailure::TooLarge)) => {
            return Err(CliError::SopsCiphertextTooLarge {
                limit: MAX_SOPS_CIPHERTEXT_BYTES,
            });
        }
        Ok(Err(DrainFailure::Read)) | Err(_) => {
            return Err(CliError::EncryptEditedSecret(target.to_path_buf()));
        }
    };
    if write_result.is_err()
        || !matches!(status, Ok(status) if status.success())
        || !matches!(stderr_result, Ok(Ok(_)))
    {
        output.zeroize();
        return Err(CliError::EncryptEditedSecret(target.to_path_buf()));
    }

    let mut ciphertext = Builder::new()
        .prefix(".secretsd-ciphertext-")
        .tempfile_in(directory)
        .map_err(|_| CliError::InstallEditedSecret)?;
    let write_result = ciphertext.as_file_mut().write_all(&output);
    output.zeroize();
    write_result.map_err(|_| CliError::InstallEditedSecret)?;
    ciphertext
        .persist(target)
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
