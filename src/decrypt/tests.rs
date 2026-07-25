use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use super::*;
use crate::proto::ErrCode;
use crate::secret::SecretName;
use crate::store::HumanStore;

fn direct_pcsc() -> PcscReachability {
    PcscReachability::new(None, None)
}

fn fixture_bin(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn store_with_key(key: &str) -> (tempfile::TempDir, HumanStore) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(format!("{key}.env")), b"ciphertext").unwrap();
    let store = HumanStore::new(dir.path().to_path_buf());
    (dir, store)
}

#[test]
fn returns_value_when_sops_succeeds() {
    let (_dir, store) = store_with_key("DEEL_API_KEY");
    let decryptor = Decryptor::new(
        fixture_bin("fake-sops-ok"),
        Duration::from_secs(5),
        direct_pcsc(),
    );
    let key = SecretName::parse("DEEL_API_KEY").unwrap();
    let value = decryptor.decrypt(&store, &key).unwrap();
    assert_eq!(value.as_slice(), b"value-for-DEEL_API_KEY");
}

#[test]
fn decrypts_the_inode_validated_before_its_path_is_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("DEEL_API_KEY.env");
    let replacement_path = dir.path().join("replacement.env");
    let sops_path = dir.path().join("swap-and-read-sops");
    std::fs::write(&key_path, b"DEEL_API_KEY=validated\n").unwrap();
    std::fs::write(&replacement_path, b"DEEL_API_KEY=replacement\n").unwrap();
    std::fs::write(
        &sops_path,
        format!(
            "#!/bin/bash\nrm -- '{}'\nln -s '{}' '{}'\npath=\"${{!#}}\"\ncat \"$path\"\n",
            key_path.display(),
            replacement_path.display(),
            key_path.display(),
        ),
    )
    .unwrap();
    std::fs::set_permissions(&sops_path, std::fs::Permissions::from_mode(0o700)).unwrap();

    let store = HumanStore::new(dir.path().to_path_buf());
    let decryptor = Decryptor::new(sops_path, Duration::from_secs(5), direct_pcsc());
    let key = SecretName::parse("DEEL_API_KEY").unwrap();

    let value = decryptor.decrypt(&store, &key).unwrap();

    assert_eq!(value.as_slice(), b"validated");
}

#[test]
#[cfg_attr(miri, ignore)]
fn duplicate_fd_avoids_standard_descriptors_when_stdin_is_closed() {
    if std::env::var_os("SECRETSD_TEST_CLOSE_STDIN").is_some() {
        let directory = tempfile::tempdir().unwrap();
        let ciphertext = directory.path().join("ciphertext.env");
        std::fs::write(&ciphertext, b"ciphertext").unwrap();
        let validated = std::fs::File::open(ciphertext).unwrap();
        nix::unistd::close(0).unwrap();

        let inherited = duplicate_ciphertext_fd(validated.as_raw_fd()).unwrap();

        assert!(inherited.as_raw_fd() >= 3);
        return;
    }

    let status = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "decrypt::tests::duplicate_fd_avoids_standard_descriptors_when_stdin_is_closed",
            "--nocapture",
        ])
        .env("SECRETSD_TEST_CLOSE_STDIN", "1")
        .stdin(Stdio::null())
        .status()
        .unwrap();

    assert!(status.success());
}

#[test]
fn returns_internal_error_when_sops_fails() {
    let (_dir, store) = store_with_key("K");
    let decryptor = Decryptor::new(
        fixture_bin("fake-sops-fail"),
        Duration::from_secs(5),
        direct_pcsc(),
    );
    let key = SecretName::parse("K").unwrap();
    assert_eq!(
        decryptor.decrypt(&store, &key).err(),
        Some(ErrCode::Internal)
    );
}

#[test]
fn times_out_and_kills_the_process_group() {
    let (_dir, store) = store_with_key("K");
    let decryptor = Decryptor::new(
        fixture_bin("fake-sops-hang"),
        Duration::from_millis(300),
        direct_pcsc(),
    );
    let key = SecretName::parse("K").unwrap();
    let started = std::time::Instant::now();
    assert_eq!(
        decryptor.decrypt(&store, &key).err(),
        Some(ErrCode::Timeout)
    );
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn is_reachable_without_a_pcsc_socket() {
    let decryptor = Decryptor::new(PathBuf::from("sops"), Duration::from_secs(1), direct_pcsc());
    assert!(decryptor.reachable());
}

#[test]
fn is_unreachable_when_configured_pcsc_socket_is_absent() {
    let decryptor = Decryptor::new(
        PathBuf::from("sops"),
        Duration::from_secs(1),
        PcscReachability::new(Some(PathBuf::from("/nonexistent/pcscd.comm")), None),
    );
    assert!(!decryptor.reachable());
}

#[test]
fn is_reachable_when_configured_pcsc_socket_exists() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("pcscd.comm");
    std::fs::write(&socket, b"").unwrap();
    let decryptor = Decryptor::new(
        PathBuf::from("sops"),
        Duration::from_secs(1),
        PcscReachability::new(Some(socket), None),
    );
    assert!(decryptor.reachable());
}

#[test]
fn is_unreachable_when_present_pcsc_socket_has_a_failing_injected_probe() {
    // Given a socket path and a probe command that represents a dead far end.
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("pcscd.comm");
    let _listener = UnixListener::bind(&socket).unwrap();
    let probe = YubikeyProbe::new(
        PathBuf::from("/bin/false"),
        Vec::new(),
        Duration::from_secs(1),
    );
    let reachability = PcscReachability::new(Some(socket), Some(probe));
    let decryptor = Decryptor::new(PathBuf::from("sops"), Duration::from_secs(1), reachability);

    // When the pre-flight runs.
    let reachable = decryptor.reachable();

    // Then it rejects the stale listener instead of starting the decrypt.
    assert!(!reachable);
}

#[test]
fn is_reachable_when_present_pcsc_socket_has_a_successful_injected_probe() {
    // Given a socket path and a probe command that represents a live far end.
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("pcscd.comm");
    let _listener = UnixListener::bind(&socket).unwrap();
    let probe = YubikeyProbe::new(
        PathBuf::from("/bin/true"),
        Vec::new(),
        Duration::from_secs(1),
    );
    let reachability = PcscReachability::new(Some(socket), Some(probe));
    let decryptor = Decryptor::new(PathBuf::from("sops"), Duration::from_secs(1), reachability);

    // When the pre-flight runs.
    let reachable = decryptor.reachable();

    // Then it permits the decrypt to proceed.
    assert!(reachable);
}

#[test]
fn is_unreachable_promptly_when_the_injected_probe_hangs() {
    // Given a socket path and a probe that never completes.
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("pcscd.comm");
    let _listener = UnixListener::bind(&socket).unwrap();
    let probe = YubikeyProbe::new(
        PathBuf::from("/bin/sleep"),
        vec!["30".to_owned()],
        Duration::from_millis(10),
    );
    let reachability = PcscReachability::new(Some(socket), Some(probe));
    let decryptor = Decryptor::new(PathBuf::from("sops"), Duration::from_secs(1), reachability);

    // When the pre-flight runs.
    let started = std::time::Instant::now();
    let reachable = decryptor.reachable();

    // Then it returns before the decrypt timeout could be reached.
    assert!(!reachable);
    assert!(started.elapsed() < Duration::from_secs(1));
}

/// Captures emitted log lines so a test can assert on what was recorded.
#[derive(Clone)]
struct CapturedLogs(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for CapturedLogs {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for CapturedLogs {
    type Writer = Self;

    fn make_writer(&'writer self) -> Self::Writer {
        self.clone()
    }
}

#[test]
fn classifies_a_sops_failure_without_logging_child_stderr() {
    // The fixture writes "sops: could not decrypt" to stderr. That text stands in
    // for anything sops might quote -- including material it just decrypted -- so
    // its absence from the journal is the invariant under test.
    let (_dir, store) = store_with_key("K");
    let decryptor = Decryptor::new(
        fixture_bin("fake-sops-fail"),
        Duration::from_secs(5),
        direct_pcsc(),
    );
    let key = SecretName::parse("K").unwrap();
    let logs = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(CapturedLogs(std::sync::Arc::clone(&logs)))
        .finish();
    let outcome = tracing::subscriber::with_default(subscriber, || decryptor.decrypt(&store, &key));

    assert_eq!(outcome.err(), Some(ErrCode::Internal));
    let output = String::from_utf8(logs.lock().unwrap().clone()).unwrap();
    assert!(
        output.contains("sops_failure=") && output.contains("sops_stderr_bytes="),
        "expected a classified failure, got: {output}"
    );
    assert!(
        !output.contains("could not decrypt"),
        "child stderr reached the log: {output}"
    );
}

#[test]
fn classifies_known_sops_signatures_and_falls_back_to_unclassified() {
    // The first case is the real message seen when a YubiKey touch never lands;
    // it contains both yubikey signatures, so ordering must pick the specific one.
    assert_eq!(
        classify_sops_stderr(
            b"age: yubikey plugin: Failed to decrypt YubiKey stanza. Did you touch it?"
        ),
        "yubikey-stanza-undecryptable"
    );
    assert_eq!(
        classify_sops_stderr(b"Failed to get the data key required to decrypt the SOPS file."),
        "data-key-unavailable"
    );
    assert_eq!(
        classify_sops_stderr(b"open /nope: no such file or directory"),
        "input-unreadable"
    );
    assert_eq!(
        classify_sops_stderr(b"sops metadata not found"),
        "missing-sops-metadata"
    );
    assert_eq!(classify_sops_stderr(b"a novel failure"), "unclassified");
    assert_eq!(classify_sops_stderr(b""), "unclassified");
}
