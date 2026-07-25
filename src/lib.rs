//! Session-scoped secrets broker.
//!
//! See `docs/design.md` for the threat model and the reasoning behind the
//! security properties this crate is required to hold.

use std::path::PathBuf;
use std::time::Duration;

use crate::decrypt::{Decryptor, PcscReachability, YubikeyProbe};
use crate::hardening::MemlockPolicy;

/// Shared Unix-socket protocol client used by the `secrets` CLI.
pub mod client;
/// Sops subprocess handling for one human-tier secret.
pub mod decrypt;
pub mod grants;
/// Process hardening that must complete before plaintext is held.
pub mod hardening;
pub mod peer;
pub mod proto;
/// Pending approval requests and the single-flight hardware queue.
pub mod requests;
/// Secret names and zeroizing plaintext bytes.
pub mod secret;
/// Socket server, worker, and request dispatch.
pub mod server;
/// Human-tier ciphertext directory access.
pub mod store;

/// Daemon configuration. Sourced from the daemon's own environment only —
/// never from a client request, because clients are untrusted.
#[derive(Debug, Clone)]
#[allow(
    clippy::exhaustive_structs,
    reason = "integration harnesses construct every configuration field explicitly"
)]
pub struct Config {
    /// Unix socket to serve on when not socket-activated.
    pub socket_path: PathBuf,
    /// Directory of per-key sops files.
    pub human_dir: PathBuf,
    /// Path to the sops binary.
    pub sops_bin: PathBuf,
    /// PC/SC socket whose absence means the `YubiKey` is unreachable.
    pub pcsc_socket: Option<PathBuf>,
    /// argv for an optional bounded PC/SC far-end liveness probe.
    pub yubikey_probe_argv: Vec<String>,
    /// Backstop lifetime for a grant.
    pub max_grant: Duration,
    /// Gap enforced between decrypts; must exceed the PIV touch cache.
    pub cooldown: Duration,
    /// How long a request waits for approval.
    pub request_ttl: Duration,
    /// Pending requests allowed per scope.
    pub max_pending_per_scope: usize,
}

impl Config {
    /// Build configuration from environment variables, requiring a human secret directory.
    pub fn from_env() -> Self {
        let var = |name: &str| std::env::var(name).ok().filter(|value| !value.is_empty());
        let runtime = var("XDG_RUNTIME_DIR").unwrap_or_else(|| "/tmp".to_owned());
        let argv = |name: &str| {
            var(name)
                .map(|value| {
                    value
                        .split_whitespace()
                        .map(ToOwned::to_owned)
                        .collect::<Vec<String>>()
                })
                .unwrap_or_default()
        };
        let secs = |name: &str, fallback: u64| {
            var(name)
                .and_then(|value| value.parse().ok())
                .map_or_else(|| Duration::from_secs(fallback), Duration::from_secs)
        };
        Self {
            socket_path: var("SECRETSD_SOCKET").map_or_else(
                || PathBuf::from(format!("{runtime}/secretsd.sock")),
                PathBuf::from,
            ),
            human_dir: var("SECRETSD_HUMAN_DIR").map_or_else(PathBuf::new, PathBuf::from),
            sops_bin: var("SECRETSD_SOPS_BIN").map_or_else(|| PathBuf::from("sops"), PathBuf::from),
            pcsc_socket: var("PCSCLITE_CSOCK_NAME").map(PathBuf::from),
            yubikey_probe_argv: argv("SECRETSD_YUBIKEY_PROBE_CMD"),
            max_grant: secs("SECRETSD_MAX_GRANT_SECS", 43200),
            cooldown: secs("SECRETSD_COOLDOWN_SECS", 16),
            request_ttl: secs("SECRETSD_REQUEST_TTL_SECS", 90),
            max_pending_per_scope: var("SECRETSD_MAX_PENDING")
                .and_then(|value| value.parse().ok())
                .unwrap_or(3),
        }
    }

    /// Build a decryptor from daemon-only configuration.
    pub(crate) fn decryptor(&self) -> Decryptor {
        Decryptor::new(
            self.sops_bin.clone(),
            self.request_ttl,
            PcscReachability::new(
                self.pcsc_socket.clone(),
                YubikeyProbe::from_argv(&self.yubikey_probe_argv),
            ),
        )
    }

    /// Reject settings that could allow one touch to authorize two decrypts.
    pub fn validate(&self) -> std::io::Result<()> {
        if self.human_dir.as_os_str().is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "SECRETSD_HUMAN_DIR must be set",
            ));
        }
        if self.cooldown <= Duration::from_secs(15) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "SECRETSD_COOLDOWN_SECS must exceed the 15s PIV touch cache",
            ));
        }
        Ok(())
    }
}

/// Serve until the process is stopped.
pub fn run(config: Config) -> std::io::Result<()> {
    config.validate()?;
    server::serve(config)
}

/// Start the hardened daemon until the process is stopped.
pub fn serve_main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();

    let policy = match memlock_policy() {
        Ok(policy) => policy,
        Err(error) => {
            tracing::error!(%error, "refusing to start without process hardening");
            return std::process::ExitCode::FAILURE;
        }
    };

    if let Err(error) = hardening::apply(policy) {
        tracing::error!(%error, "refusing to start without process hardening");
        return std::process::ExitCode::FAILURE;
    }

    match run(Config::from_env()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "secretsd exited");
            std::process::ExitCode::FAILURE
        }
    }
}

fn memlock_policy() -> Result<MemlockPolicy, &'static str> {
    match std::env::var("SECRETSD_MEMLOCK") {
        Ok(value) => match value.as_str() {
            "require" => Ok(MemlockPolicy::Require),
            "optional" => Ok(MemlockPolicy::Optional),
            _ => Err("SECRETSD_MEMLOCK must be require (default) or optional"),
        },
        Err(std::env::VarError::NotPresent) => Ok(MemlockPolicy::Require),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err("SECRETSD_MEMLOCK must be require (default) or optional")
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::sync::{Mutex, MutexGuard};

    use super::*;

    static HUMAN_DIR_ENV_LOCK: Mutex<()> = Mutex::new(());

    struct HumanDirEnvironment {
        previous: Option<OsString>,
        _lock: MutexGuard<'static, ()>,
    }

    impl HumanDirEnvironment {
        fn unset() -> Self {
            let lock = HUMAN_DIR_ENV_LOCK.lock().unwrap();
            let previous = std::env::var_os("SECRETSD_HUMAN_DIR");
            // SAFETY: this test holds the process-wide environment lock and no daemon thread runs.
            unsafe { std::env::remove_var("SECRETSD_HUMAN_DIR") };
            Self {
                previous,
                _lock: lock,
            }
        }

        fn set(value: &std::path::Path) -> Self {
            let lock = HUMAN_DIR_ENV_LOCK.lock().unwrap();
            let previous = std::env::var_os("SECRETSD_HUMAN_DIR");
            // SAFETY: this test holds the process-wide environment lock and no daemon thread runs.
            unsafe { std::env::set_var("SECRETSD_HUMAN_DIR", value) };
            Self {
                previous,
                _lock: lock,
            }
        }
    }

    impl Drop for HumanDirEnvironment {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(value) => {
                    // SAFETY: this guard retains the process-wide environment lock until restoration.
                    unsafe { std::env::set_var("SECRETSD_HUMAN_DIR", value) };
                }
                None => {
                    // SAFETY: this guard retains the process-wide environment lock until restoration.
                    unsafe { std::env::remove_var("SECRETSD_HUMAN_DIR") };
                }
            }
        }
    }

    #[test]
    fn rejects_a_cooldown_at_or_below_the_piv_touch_cache() {
        let config = Config {
            socket_path: PathBuf::from("/tmp/secretsd-test.sock"),
            human_dir: PathBuf::from("/tmp/secretsd-human"),
            sops_bin: PathBuf::from("sops"),
            pcsc_socket: None,
            yubikey_probe_argv: Vec::new(),
            max_grant: Duration::from_secs(1),
            cooldown: Duration::from_secs(15),
            request_ttl: Duration::from_secs(1),
            max_pending_per_scope: 1,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn startup_configuration_fails_when_human_dir_is_unset() {
        // Given no deployment-provided human secret directory.
        let _environment = HumanDirEnvironment::unset();

        // When the daemon configuration is validated.
        let result = Config::from_env().validate();

        // Then startup fails and identifies the required variable.
        let error = result.unwrap_err();
        assert!(error.to_string().contains("SECRETSD_HUMAN_DIR"));
    }

    #[test]
    fn startup_configuration_accepts_a_configured_human_dir() {
        // Given an explicit deployment-provided human secret directory.
        let directory = tempfile::tempdir().unwrap();
        let _environment = HumanDirEnvironment::set(directory.path());

        // When the daemon configuration is validated.
        let config = Config::from_env();

        // Then startup keeps that directory and accepts its configuration.
        assert_eq!(config.human_dir, directory.path());
        assert!(config.validate().is_ok());
    }
}
