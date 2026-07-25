use std::ffi::{OsStr, OsString};
use std::io::Write;

use super::{CliError, ClientError, caller_tty};
use crate::secret::SecretName;

#[derive(Clone, Copy)]
pub(super) enum GetOutput {
    /// Ask the broker to grant the key, then report status. Blocks for the
    /// human's approval, so this is how a session pre-authorizes itself.
    Request,
    /// Report what is known without asking for anything, so no touch is needed.
    Status,
    /// Print the secret itself.
    Value,
}

pub(super) fn get_arguments(arguments: &[OsString]) -> Result<(&OsString, GetOutput), CliError> {
    let value = OsStr::new("--value");
    let no_request = OsStr::new("--no-request");
    let is_flag = |argument: &OsString| argument == value || argument == no_request;
    let mode = |flag: &OsString| {
        if flag == value {
            GetOutput::Value
        } else {
            GetOutput::Status
        }
    };
    match arguments {
        [_, name] if !is_flag(name) => Ok((name, GetOutput::Request)),
        [_, name, flag] | [_, flag, name] if is_flag(flag) && !is_flag(name) => {
            Ok((name, mode(flag)))
        }
        _ => Err(CliError::Usage),
    }
}

pub(super) fn write_status(name: &SecretName, status: TierStatus) -> Result<(), CliError> {
    let mut stdout = std::io::stdout().lock();
    match status {
        TierStatus::Agent => writeln!(stdout, "{}  agent tier", name.as_str()),
        TierStatus::Human { grant_active } => {
            let grant = if grant_active { "active" } else { "inactive" };
            writeln!(stdout, "{}  human tier  grant: {grant}", name.as_str())
        }
    }
    .map_err(CliError::Stdout)?;

    writeln!(
        std::io::stderr().lock(),
        "Use --value to print the secret, secrets KEY -- command to inject it into a child process, or --no-request to check status without asking for approval."
    )
    .map_err(CliError::Stderr)
}

#[derive(Clone, Copy)]
pub(super) enum TierStatus {
    Agent,
    Human { grant_active: bool },
}

pub(super) fn active_grant(name: &SecretName, grants: &[u8]) -> Result<bool, CliError> {
    let listing = std::str::from_utf8(grants)
        .map_err(|_| CliError::from_client(ClientError::InvalidResponse))?;
    let caller_scope = if std::env::var_os("SECRETSD_SESSION_TOKEN_FILE").is_some() {
        CallerScope::Session
    } else {
        caller_tty().map_or(CallerScope::None, CallerScope::Tty)
    };
    Ok(listing.lines().any(|line| {
        let mut fields = line.split('\t');
        let (Some(key), Some(grant_scope), Some(_age), None) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return false;
        };
        if key != name.as_str() {
            return false;
        }
        match &caller_scope {
            CallerScope::Session => grant_scope == "session",
            CallerScope::Tty(tty) => grant_scope.strip_prefix("tty ") == Some(tty),
            CallerScope::None => false,
        }
    }))
}

enum CallerScope {
    Session,
    Tty(String),
    None,
}
