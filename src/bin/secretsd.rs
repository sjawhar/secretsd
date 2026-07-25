//! Daemon entry point.

use secretsd::hardening::{self, MemlockPolicy};
use secretsd::{Config, run};

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

fn main() -> std::process::ExitCode {
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
