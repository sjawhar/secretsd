//! Process-global hardening checks, isolated by `cargo-nextest`.

use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::Duration;

use secretsd::hardening::{self, MemlockPolicy};

fn write_source_config(directory: &tempfile::TempDir) -> std::io::Result<std::path::PathBuf> {
    let path = directory.path().join("config.toml");
    std::fs::write(
        &path,
        format!("[source.test]\npath = \"{}\"\n", directory.path().display()),
    )?;
    Ok(path)
}

fn start_daemon_with_memlock_limit(
    limit: &str,
    policy: Option<&str>,
) -> std::io::Result<(tempfile::TempDir, Child)> {
    let directory = tempfile::tempdir()?;
    let config_path = write_source_config(&directory)?;
    let binary = env!("CARGO_BIN_EXE_secrets");
    let mut command = Command::new("bash");
    command
        .args([
            "-c",
            "ulimit -l \"$1\" && exec \"$2\" \"$3\"",
            "bash",
            limit,
            binary,
            "serve",
        ])
        .env("SECRETSD_SOCKET", directory.path().join("broker.sock"))
        .env("SECRETSD_CONFIG", config_path)
        .env("HOME", directory.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(policy) = policy {
        command.env("SECRETSD_MEMLOCK", policy);
    }
    let daemon = command.spawn()?;
    Ok((directory, daemon))
}

fn wait_for_socket(directory: &tempfile::TempDir, mut daemon: Child) -> std::io::Result<Child> {
    for _ in 0..100 {
        if directory.path().join("broker.sock").exists() {
            return Ok(daemon);
        }
        if let Some(status) = daemon.try_wait()? {
            let output = daemon.wait_with_output()?;
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(std::io::Error::other(format!(
                "daemon exited with {status}: {stderr}"
            )));
        }
        thread::sleep(Duration::from_millis(20));
    }

    daemon.kill()?;
    let output = daemon.wait_with_output()?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(std::io::Error::other(format!(
        "daemon did not create a socket: {stderr}"
    )))
}

fn stop_daemon(mut daemon: Child) -> std::io::Result<Output> {
    if daemon.try_wait()?.is_none() {
        daemon.kill()?;
    }
    daemon.wait_with_output()
}

#[test]
fn disables_core_dumps_and_ptrace_dumpability() {
    hardening::apply(MemlockPolicy::Optional).expect("hardening applies");

    assert!(
        !nix::sys::prctl::get_dumpable().expect("get dumpable"),
        "process must not be dumpable"
    );

    let (soft, hard) = nix::sys::resource::getrlimit(nix::sys::resource::Resource::RLIMIT_CORE)
        .expect("getrlimit");
    assert_eq!(soft, 0, "core dump soft limit must be zero");
    assert_eq!(hard, 0, "core dump hard limit must be zero");
}

#[test]
fn required_memlock_fails_closed_when_locking_is_unavailable() {
    match hardening::apply(MemlockPolicy::Require) {
        Ok(()) => {}
        Err(hardening::HardeningError::InsufficientMemlock { soft, hard }) => {
            assert!(
                soft != nix::sys::resource::RLIM_INFINITY
                    || hard != nix::sys::resource::RLIM_INFINITY,
                "finite limits must fail closed"
            );
        }
        Err(hardening::HardeningError::Memlock(errno)) => {
            assert!(
                matches!(errno, nix::Error::EPERM | nix::Error::ENOMEM),
                "unexpected memlock errno: {errno:?}"
            );
        }
        Err(other) => panic!("unexpected hardening failure: {other}"),
    }
}

#[test]
fn low_memlock_limit_exits_with_actionable_diagnostic_instead_of_sigabrt() {
    // Given a daemon process restricted to an 8 KiB memlock limit.
    let directory = tempfile::tempdir().expect("create temporary directory");
    let config_path = write_source_config(&directory).expect("write source config");
    let binary = env!("CARGO_BIN_EXE_secrets");

    // When it starts before any threads are created.
    let output = Command::new("sh")
        .args([
            "-c",
            "ulimit -l 8; exec timeout 5s \"$1\" \"$2\"",
            "sh",
            binary,
            "serve",
        ])
        .env("SECRETSD_SOCKET", directory.path().join("broker.sock"))
        .env("SECRETSD_CONFIG", config_path)
        .env("HOME", directory.path())
        .output()
        .expect("start low-memlock daemon");

    // Then it reports a recoverable configuration error rather than aborting.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "stderr: {stderr}");
    assert!(stderr.contains("RLIMIT_MEMLOCK"), "stderr: {stderr}");
    assert!(stderr.contains("LimitMEMLOCK=infinity"), "stderr: {stderr}");
    assert!(!stderr.contains("panicked"), "stderr: {stderr}");
}

#[test]
fn validates_a_generous_finite_memlock_limit() {
    // Given the regression's 12 GB finite memlock limit.
    let twelve_gigabytes = 12_079_136_768;

    // When strict startup validates that finite limit.
    let result = hardening::validate_memlock_limits(twelve_gigabytes, twelve_gigabytes);

    // Then it accepts the limit instead of rejecting a generous finite value.
    assert!(result.is_ok());
}

#[test]
fn validates_an_unlimited_memlock_limit() {
    // Given an unlimited memlock limit.
    let infinity = nix::sys::resource::RLIM_INFINITY;

    // When strict startup validates that limit.
    let result = hardening::validate_memlock_limits(infinity, infinity);

    // Then it accepts the ideal production configuration.
    assert!(result.is_ok());
}

#[test]
fn optional_memlock_warns_and_starts_with_a_tiny_limit() -> Result<(), Box<dyn std::error::Error>> {
    // Given a daemon restricted to an 8 KiB memlock limit and the dev-only policy.
    let (directory, daemon) = start_daemon_with_memlock_limit("8", Some("optional"))?;

    // When it starts before any worker threads are created.
    let daemon = wait_for_socket(&directory, daemon)?;

    // Then it starts with an explicit warning about the reduced protection.
    let output = stop_daemon(daemon)?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("plaintext pages may be swappable"),
        "stderr: {stderr}"
    );
    Ok(())
}
