//! Deferred command-line entry point for the shared `secrets` client.

fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();

    match secretsd::client::cli::run(std::env::args_os()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "secrets command failed");
            std::process::ExitCode::FAILURE
        }
    }
}
