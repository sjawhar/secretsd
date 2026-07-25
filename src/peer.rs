//! Kernel-derived identity for the peer of a socket connection.
//!
//! A session token proves *which* session a request belongs to, but on a
//! single-uid machine possession of the token file is not proof that the caller
//! belongs to that session: any process sharing the uid can read it. Pairing the
//! token with the caller's position in the process tree closes that gap for
//! callers outside the session's tree.
//!
//! Ancestry is only trustworthy if the pid it starts from cannot be recycled
//! between the moment the kernel reports it and the moment `/proc` is walked.
//! `SO_PEERPIDFD` returns a descriptor pinned to the peer process, which makes
//! that pid stable for as long as the descriptor is held, so this module uses it
//! rather than the pid from `SO_PEERCRED`.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::Arc;

use nix::libc;

use crate::proto::ErrCode;

/// `SO_PEERPIDFD`, added in Linux 6.5 and not surfaced by nix 0.29.
const SO_PEERPIDFD: libc::c_int = 77;

/// Upper bound on a `/proc` parent walk, so a cycle or a pathological tree
/// cannot spin the daemon.
const MAX_ANCESTRY_DEPTH: usize = 64;

/// A pidfd pinned to the process on the other end of a connection.
///
/// Cloning shares the descriptor: every clone observes the same process, and the
/// pid stays reserved until the last clone is dropped.
#[derive(Debug, Clone)]
pub struct PeerIdentity {
    pidfd: Arc<OwnedFd>,
}

impl PeerIdentity {
    /// Pin the peer of `stream`.
    ///
    /// # Errors
    /// Returns [`ErrCode::Internal`] when the kernel does not supply a peer
    /// pidfd, so a caller that cannot be identified is refused rather than
    /// treated as trusted.
    pub fn from_stream(stream: &UnixStream) -> Result<Self, ErrCode> {
        let mut raw: libc::c_int = -1;
        let mut length: libc::socklen_t = size_of::<libc::c_int>()
            .try_into()
            .map_err(|_| ErrCode::Internal)?;
        // SAFETY: `raw` and `length` are live for the duration of the call and
        // sized as `getsockopt` expects for an integer option, and the socket
        // descriptor is kept open by the borrow of `stream`.
        let outcome = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                SO_PEERPIDFD,
                (&raw mut raw).cast(),
                &raw mut length,
            )
        };
        if outcome != 0 || raw < 0 {
            return Err(ErrCode::Internal);
        }
        // SAFETY: a successful `SO_PEERPIDFD` installed a fresh descriptor that
        // nothing else owns, so the close obligation is ours alone.
        let pidfd = unsafe { OwnedFd::from_raw_fd(raw) };
        Ok(Self {
            pidfd: Arc::new(pidfd),
        })
    }

    /// The pinned pid, or `None` once that process has exited.
    ///
    /// A pidfd whose process is gone reports `Pid: -1`, which is how a dead
    /// session root is distinguished from a live one.
    #[must_use]
    pub fn pid(&self) -> Option<i32> {
        let path = format!("/proc/self/fdinfo/{}", self.pidfd.as_raw_fd());
        let info = std::fs::read_to_string(path).ok()?;
        let value = field(&info, "Pid:")?;
        (value > 0).then_some(value)
    }

    /// Whether the pinned process is still running.
    #[must_use]
    pub fn is_alive(&self) -> bool {
        self.pid().is_some()
    }

    /// Whether this peer is `root` itself or one of its descendants.
    ///
    /// Both ends are resolved from pinned descriptors, so neither pid can have
    /// been recycled onto an unrelated process.
    #[must_use]
    pub fn descends_from(&self, root: &Self) -> bool {
        match (self.pid(), root.pid()) {
            (Some(caller), Some(ancestor)) => descends_from(caller, ancestor),
            _ => false,
        }
    }
}

/// Walk `caller`'s parents looking for `ancestor`.
fn descends_from(caller: i32, ancestor: i32) -> bool {
    let mut current = caller;
    for _ in 0..MAX_ANCESTRY_DEPTH {
        if current == ancestor {
            return true;
        }
        // pid 1 has no parent worth following, and 0 means the walk ran out.
        if current <= 1 {
            return false;
        }
        match parent_of(current) {
            Some(parent) => current = parent,
            None => return false,
        }
    }
    false
}

/// The parent pid recorded for `pid`, or `None` if it cannot be read.
fn parent_of(pid: i32) -> Option<i32> {
    let info = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    field(&info, "PPid:")
}

/// Parse a `key:\tvalue` line out of a `/proc` status-style file.
fn field(contents: &str, key: &str) -> Option<i32> {
    contents
        .lines()
        .find_map(|line| line.strip_prefix(key))?
        .trim()
        .parse()
        .ok()
}

#[cfg(test)]
impl PeerIdentity {
    /// Pin the current process, for tests that need a concrete identity.
    ///
    /// Both ends of a socket pair live in this process, so the pinned pid is our
    /// own and `descends_from` against it holds.
    pub(crate) fn current_for_test() -> Self {
        // Pinned once per test binary: a fresh pidfd per call would shift file
        // descriptor numbers under tests that assert on specific descriptors.
        static SHARED: std::sync::OnceLock<PeerIdentity> = std::sync::OnceLock::new();
        SHARED
            .get_or_init(|| {
                let (ours, theirs) = UnixStream::pair().expect("socket pair");
                let identity = Self::from_stream(&ours).expect("peer pidfd");
                drop(theirs);
                identity
            })
            .clone()
    }
}

#[cfg(test)]
mod tests;
