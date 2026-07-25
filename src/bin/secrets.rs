//! Drop-in command-line entry point for the shared `secrets` client.

use std::ffi::{OsStr, OsString};
use std::fmt::Display;
use std::io::Write;

fn main() -> std::process::ExitCode {
    let arguments = std::env::args_os().collect::<Vec<OsString>>();
    match arguments.get(1).map(OsString::as_os_str) {
        Some(command) if command == OsStr::new("serve") => match arguments.get(2) {
            Some(_) => report_failure("serve does not accept arguments"),
            None => secretsd::serve_main(),
        },
        _ => match secretsd::client::cli::run(arguments) {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(error) => report_failure(error),
        },
    }
}

fn report_failure(error: impl Display) -> std::process::ExitCode {
    match writeln!(std::io::stderr(), "secrets: {error}") {
        Ok(()) | Err(_) => std::process::ExitCode::FAILURE,
    }
}
