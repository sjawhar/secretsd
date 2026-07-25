//! Process-global hardening checks, isolated by `cargo-nextest`.

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
fn memlock_is_attempted_and_reports_its_outcome() {
    match hardening::apply(MemlockPolicy::Require) {
        Ok(()) => {}
        Err(hardening::HardeningError::Memlock(errno)) => {
            assert!(
                matches!(errno, nix::Error::EPERM | nix::Error::ENOMEM),
                "unexpected memlock errno: {errno:?}"
            );
        }
        Err(other) => panic!("unexpected hardening failure: {other}"),
    }
}
