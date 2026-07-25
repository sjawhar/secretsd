//! Process-level hardening applied before the daemon holds any plaintext.

use std::fmt;

use nix::sys::mman::{MlockAllFlags, mlockall};
use nix::sys::prctl::set_dumpable;
use nix::sys::resource::{Resource, setrlimit};

/// Whether locking memory is mandatory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MemlockPolicy {
    /// Fail startup if pages cannot be locked in production.
    Require,
    /// Tolerate a memlock failure in CI containers without `LimitMEMLOCK`.
    Optional,
}

/// A hardening step that did not take effect.
#[derive(Debug)]
#[non_exhaustive]
pub enum HardeningError {
    /// `mlockall` failed while the policy required it.
    Memlock(nix::Error),
    /// `PR_SET_DUMPABLE` failed.
    Dumpable(nix::Error),
    /// Setting `RLIMIT_CORE` to zero failed.
    CoreLimit(nix::Error),
}

impl fmt::Display for HardeningError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Memlock(error) => write!(formatter, "mlockall failed: {error}"),
            Self::Dumpable(error) => write!(formatter, "set_dumpable failed: {error}"),
            Self::CoreLimit(error) => write!(formatter, "RLIMIT_CORE could not be zeroed: {error}"),
        }
    }
}

impl std::error::Error for HardeningError {}

/// Apply every hardening step.
///
/// Dumpability and core limits are set before memlock because they must hold
/// even when optional memlock is unavailable in a test environment.
pub fn apply(policy: MemlockPolicy) -> Result<(), HardeningError> {
    set_dumpable(false).map_err(HardeningError::Dumpable)?;
    setrlimit(Resource::RLIMIT_CORE, 0, 0).map_err(HardeningError::CoreLimit)?;

    match (
        mlockall(MlockAllFlags::MCL_CURRENT | MlockAllFlags::MCL_FUTURE),
        policy,
    ) {
        (Ok(()), _) => Ok(()),
        (Err(error), MemlockPolicy::Require) => Err(HardeningError::Memlock(error)),
        (Err(error), MemlockPolicy::Optional) => {
            tracing::warn!(%error, "memlock unavailable; plaintext pages may be swappable");
            Ok(())
        }
    }
}
