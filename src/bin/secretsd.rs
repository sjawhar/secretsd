//! Daemon entry point.

use secretsd::hardening::{self, MemlockPolicy};
use secretsd::{Config, run};

fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();

    if let Err(error) =
        hardening::validate_memlock_limit().and_then(|()| hardening::apply(MemlockPolicy::Require))
    {
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
