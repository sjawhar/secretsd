//! Process-level hardening applied before any plaintext is held.
//!
//! This covers the daemon before it holds decrypted secrets, and the client
//! before it reads a non-interactive human-secret write from stdin.

use std::fmt;

use nix::sys::mman::{MlockAllFlags, mlockall};
use nix::sys::prctl::set_dumpable;
use nix::sys::resource::{RLIM_INFINITY, Resource, getrlimit, rlim_t, setrlimit};

/// Minimum finite `RLIMIT_MEMLOCK` accepted for the daemon.
///
/// The daemon creates eleven post-check workers: one approval worker, eight
/// main-lane workers, one fast-lane worker, and one control-lane worker. At
/// Rust's 2 MiB default stack size, their stacks need 22 MiB; 512 MiB leaves
/// 490 MiB for the main stack, bounded connection queues, and later heap
/// allocations. `MCL_FUTURE` still means no finite limit can guarantee every
/// future allocation remains lockable, but this floor makes exhaustion
/// implausible for the bounded daemon.
pub const MIN_MEMLOCK_BYTES: rlim_t = 512 * 1024 * 1024;

/// Whether locking memory is mandatory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MemlockPolicy {
    /// Fail startup if pages cannot be locked in production.
    Require,
    /// Tolerate a memlock failure in development and test environments.
    Optional,
}

/// A hardening step that did not take effect.
#[derive(Debug)]
#[non_exhaustive]
pub enum HardeningError {
    /// Reading `RLIMIT_MEMLOCK` failed.
    MemlockLimit(nix::Error),
    /// `RLIMIT_MEMLOCK` cannot protect all future daemon allocations.
    InsufficientMemlock {
        /// Current soft limit in bytes.
        soft: rlim_t,
        /// Current hard limit in bytes.
        hard: rlim_t,
    },
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
            Self::MemlockLimit(error) => {
                write!(formatter, "getrlimit(RLIMIT_MEMLOCK) failed: {error}")
            }
            Self::InsufficientMemlock { soft, hard } => write!(
                formatter,
                "RLIMIT_MEMLOCK is insufficient for mlockall(MCL_CURRENT|MCL_FUTURE) (soft={soft} bytes, hard={hard} bytes); configure LimitMEMLOCK=infinity or at least {MIN_MEMLOCK_BYTES} bytes, or use SECRETSD_MEMLOCK=optional only for local development"
            ),
            Self::Memlock(error) => write!(formatter, "mlockall failed: {error}"),
            Self::Dumpable(error) => write!(formatter, "set_dumpable failed: {error}"),
            Self::CoreLimit(error) => write!(formatter, "RLIMIT_CORE could not be zeroed: {error}"),
        }
    }
}

impl std::error::Error for HardeningError {}

/// Verify that the supplied memlock limits are adequate for the daemon.
///
/// Unlimited memory locking remains ideal. A finite limit at or above
/// [`MIN_MEMLOCK_BYTES`] is accepted, while acknowledging that `MCL_FUTURE`
/// cannot guarantee every future allocation remains lockable under a finite
/// limit.
pub const fn validate_memlock_limits(soft: rlim_t, hard: rlim_t) -> Result<(), HardeningError> {
    if (soft == RLIM_INFINITY || soft >= MIN_MEMLOCK_BYTES)
        && (hard == RLIM_INFINITY || hard >= MIN_MEMLOCK_BYTES)
    {
        Ok(())
    } else {
        Err(HardeningError::InsufficientMemlock { soft, hard })
    }
}

/// Verify that the current process has adequate memory-locking limits.
pub fn validate_memlock_limit() -> Result<(), HardeningError> {
    let (soft, hard) = getrlimit(Resource::RLIMIT_MEMLOCK).map_err(HardeningError::MemlockLimit)?;
    validate_memlock_limits(soft, hard)
}

/// Disable core dumps before this process can hold plaintext.
///
/// The core limit is inherited by child processes, protecting commands spawned
/// with plaintext on their standard input.
pub fn apply_no_core_dumps() -> Result<(), HardeningError> {
    set_dumpable(false).map_err(HardeningError::Dumpable)?;
    setrlimit(Resource::RLIMIT_CORE, 0, 0).map_err(HardeningError::CoreLimit)?;
    Ok(())
}

/// Apply every hardening step.
///
/// Dumpability and core limits are set before memlock because they must hold
/// even when optional memlock is unavailable in a test environment.
pub fn apply(policy: MemlockPolicy) -> Result<(), HardeningError> {
    apply_no_core_dumps()?;
    match validate_memlock_limit() {
        Ok(()) => {}
        Err(error) => {
            return match policy {
                MemlockPolicy::Require => Err(error),
                MemlockPolicy::Optional => {
                    tracing::warn!(%error, "memlock unavailable; plaintext pages may be swappable");
                    Ok(())
                }
            };
        }
    }

    match mlockall(MlockAllFlags::MCL_CURRENT | MlockAllFlags::MCL_FUTURE) {
        Ok(()) => Ok(()),
        Err(error) => match policy {
            MemlockPolicy::Require => Err(HardeningError::Memlock(error)),
            MemlockPolicy::Optional => {
                tracing::warn!(%error, "memlock unavailable; plaintext pages may be swappable");
                Ok(())
            }
        },
    }
}
