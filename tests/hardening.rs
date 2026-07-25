//! Process-global hardening checks, isolated by `cargo-nextest`.

use std::process::Command;

use secretsd::hardening::{self, MemlockPolicy};

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
    let binary = env!("CARGO_BIN_EXE_secretsd");

    // When it starts before any threads are created.
    let output = Command::new("sh")
        .args(["-c", "ulimit -l 8; exec timeout 5s \"$1\"", "sh", binary])
        .env("SECRETSD_SOCKET", directory.path().join("broker.sock"))
        .env("SECRETSD_HUMAN_DIR", directory.path().join("human"))
        .output()
        .expect("start low-memlock daemon");

    // Then it reports a recoverable configuration error rather than aborting.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "stderr: {stderr}");
    assert!(stderr.contains("RLIMIT_MEMLOCK"), "stderr: {stderr}");
    assert!(stderr.contains("LimitMEMLOCK=infinity"), "stderr: {stderr}");
    assert!(!stderr.contains("panicked"), "stderr: {stderr}");
}
