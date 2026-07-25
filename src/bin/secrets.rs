//! Drop-in command-line entry point for the shared `secrets` client.

use std::io::Write;

fn main() -> std::process::ExitCode {
    match secretsd::client::cli::run(std::env::args_os()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => match writeln!(std::io::stderr(), "secrets: {error}") {
            Ok(()) | Err(_) => std::process::ExitCode::FAILURE,
        },
    }
}
