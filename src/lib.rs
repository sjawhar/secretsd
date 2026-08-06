//! Session-scoped secrets broker.
//!
//! See `docs/design.md` for the threat model and the reasoning behind the
//! security properties this crate is required to hold.

use std::io::ErrorKind;
use std::path::PathBuf;
use std::time::Duration;

use crate::config::Sources;
use crate::decrypt::{Decryptor, PcscReachability, YubikeyProbe};
use crate::hardening::MemlockPolicy;
use crate::store::HumanSource;

#[doc(hidden)]
pub mod audit;
/// Shared Unix-socket protocol client used by the `secrets` CLI.
pub mod client;
/// Shared source-root configuration carrying directory paths, never secret values.
pub mod config;
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

/// Declared touch policy of the hardware key backing the human tier.
///
/// This is an operator assertion, not a probed fact: the daemon cannot ask a
/// ciphertext which slot will decrypt it. `Cached` is the fail-closed default;
/// declare `Always` only when every human-tier recipient key demands a touch
/// per decrypt, because that is what makes a sub-cache cooldown safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(
    clippy::exhaustive_enums,
    reason = "the two hardware touch policies secretsd supports are an explicit configuration contract"
)]
pub enum TouchPolicy {
    /// Touches open a ~15s window (the `YubiKey` PIV default cache).
    Cached,
    /// Every decrypt requires its own physical touch.
    Always,
}

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
    /// Configured directories of per-key sops files.
    pub human_sources: Vec<HumanSource>,
    /// Path to the sops binary.
    pub sops_bin: PathBuf,
    /// PC/SC socket whose absence means the `YubiKey` is unreachable.
    pub pcsc_socket: Option<PathBuf>,
    /// argv for an optional bounded PC/SC far-end liveness probe.
    pub yubikey_probe_argv: Vec<String>,
    /// Time budget for one probe run. Through a pcscd tunnel a healthy probe
    /// can take over 3s, so the 2s direct-pcscd default needs raising there.
    pub yubikey_probe_timeout: Duration,
    /// Declared hardware touch policy; controls the cooldown floor.
    pub touch_policy: TouchPolicy,
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
    /// Build daemon configuration from its environment and source-root file.
    pub fn from_env() -> std::io::Result<Self> {
        let var = |name: &str| std::env::var(name).ok().filter(|value| !value.is_empty());
        let human_sources = Sources::load()
            .map_err(|error| std::io::Error::new(ErrorKind::InvalidInput, error.to_string()))?
            .roots
            .into_iter()
            .map(|root| {
                let dir = root.human_dir();
                HumanSource {
                    label: root.name,
                    dir,
                }
            })
            .collect();
        let runtime = var("XDG_RUNTIME_DIR");
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
        Ok(Self {
            // Resolved by the same rule as the client (SocketPath::resolve), so a
            // daemon started without XDG_RUNTIME_DIR listens where clients look
            // (/run/user/<uid>), never at a divergent /tmp path.
            socket_path: client::SocketPath::resolve(
                var("SECRETSD_SOCKET").as_deref(),
                runtime.as_deref(),
                nix::unistd::getuid().as_raw(),
            )
            .as_path()
            .to_path_buf(),
            human_sources,
            sops_bin: var("SECRETSD_SOPS_BIN").map_or_else(|| PathBuf::from("sops"), PathBuf::from),
            pcsc_socket: var("PCSCLITE_CSOCK_NAME").map(PathBuf::from),
            yubikey_probe_argv: argv("SECRETSD_YUBIKEY_PROBE_CMD"),
            yubikey_probe_timeout: secs("SECRETSD_YUBIKEY_PROBE_TIMEOUT_SECS", 2),
            touch_policy: match var("SECRETSD_TOUCH_POLICY").as_deref() {
                None | Some("cached") => TouchPolicy::Cached,
                Some("always") => TouchPolicy::Always,
                Some(_) => {
                    return Err(std::io::Error::new(
                        ErrorKind::InvalidInput,
                        "SECRETSD_TOUCH_POLICY must be cached (default) or always",
                    ));
                }
            },
            max_grant: secs("SECRETSD_MAX_GRANT_SECS", 43200),
            cooldown: secs("SECRETSD_COOLDOWN_SECS", 16),
            request_ttl: secs("SECRETSD_REQUEST_TTL_SECS", 90),
            max_pending_per_scope: var("SECRETSD_MAX_PENDING")
                .and_then(|value| value.parse().ok())
                .unwrap_or(3),
        })
    }

    /// Build a decryptor from daemon-only configuration.
    pub(crate) fn decryptor(&self) -> Decryptor {
        Decryptor::new(
            self.sops_bin.clone(),
            self.request_ttl,
            PcscReachability::new(
                self.pcsc_socket.clone(),
                YubikeyProbe::from_argv(&self.yubikey_probe_argv, self.yubikey_probe_timeout),
            ),
        )
    }

    /// Reject settings that could allow one touch to authorize two decrypts.
    pub fn validate(&self) -> std::io::Result<()> {
        if self.touch_policy == TouchPolicy::Cached && self.cooldown <= Duration::from_secs(15) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "SECRETSD_COOLDOWN_SECS must exceed the 15s PIV touch cache; a shorter \
                 cooldown is safe only with SECRETSD_TOUCH_POLICY=always hardware",
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

    match Config::from_env().and_then(run) {
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
    use super::*;

    #[test]
    fn rejects_a_cooldown_at_or_below_the_piv_touch_cache() {
        let config = Config {
            socket_path: PathBuf::from("/tmp/secretsd-test.sock"),
            human_sources: Vec::new(),
            sops_bin: PathBuf::from("sops"),
            pcsc_socket: None,
            yubikey_probe_argv: Vec::new(),
            yubikey_probe_timeout: Duration::from_secs(2),
            touch_policy: TouchPolicy::Cached,
            max_grant: Duration::from_secs(1),
            cooldown: Duration::from_secs(15),
            request_ttl: Duration::from_secs(1),
            max_pending_per_scope: 1,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn startup_configuration_accepts_an_empty_human_source_set() {
        // Given a daemon configuration whose configured roots currently have no human directories.
        let config = Config {
            socket_path: PathBuf::from("/tmp/secretsd-test.sock"),
            human_sources: Vec::new(),
            sops_bin: PathBuf::from("sops"),
            pcsc_socket: None,
            yubikey_probe_argv: Vec::new(),
            yubikey_probe_timeout: Duration::from_secs(2),
            touch_policy: TouchPolicy::Cached,
            max_grant: Duration::from_secs(1),
            cooldown: Duration::from_secs(16),
            request_ttl: Duration::from_secs(1),
            max_pending_per_scope: 1,
        };

        // When startup validates the configuration.
        let result = config.validate();

        // Then absence of human-tier files is not a configuration failure.
        assert!(result.is_ok());
    }

    #[test]
    fn accepts_a_short_cooldown_when_the_touch_policy_is_always() {
        // Given hardware declared as touch-policy Always, where no touch cache exists.
        let config = Config {
            socket_path: PathBuf::from("/tmp/secretsd-test.sock"),
            human_sources: Vec::new(),
            sops_bin: PathBuf::from("sops"),
            pcsc_socket: None,
            yubikey_probe_argv: Vec::new(),
            yubikey_probe_timeout: Duration::from_secs(2),
            touch_policy: TouchPolicy::Always,
            max_grant: Duration::from_secs(1),
            cooldown: Duration::from_secs(2),
            request_ttl: Duration::from_secs(1),
            max_pending_per_scope: 1,
        };

        // When startup validates the configuration.
        let result = config.validate();

        // Then the touch-cache cooldown floor does not apply.
        assert!(result.is_ok());
    }

    #[test]
    fn rejects_a_short_cooldown_when_the_touch_policy_is_cached() {
        // Given hardware left at the default Cached declaration and a sub-cache cooldown.
        let config = Config {
            socket_path: PathBuf::from("/tmp/secretsd-test.sock"),
            human_sources: Vec::new(),
            sops_bin: PathBuf::from("sops"),
            pcsc_socket: None,
            yubikey_probe_argv: Vec::new(),
            yubikey_probe_timeout: Duration::from_secs(2),
            touch_policy: TouchPolicy::Cached,
            max_grant: Duration::from_secs(1),
            cooldown: Duration::from_secs(2),
            request_ttl: Duration::from_secs(1),
            max_pending_per_scope: 1,
        };

        // When startup validates the configuration.
        let result = config.validate();

        // Then a cooldown inside the touch cache is refused.
        assert!(result.is_err());
    }
}
