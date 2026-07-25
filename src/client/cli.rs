//! Drop-in command-line compatibility for the `secrets` executable.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::Write;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

use super::{AgentStore, HumanNames};
use crate::secret::{SecretBytes, SecretName};

/// A CLI failure that never renders plaintext secret bytes.
#[derive(Debug)]
#[non_exhaustive]
pub enum CliError {
    /// The command line did not match the compatible CLI surface.
    Usage,
    /// A key name does not satisfy `[A-Za-z_][A-Za-z0-9_]*`.
    InvalidSecretName,
    /// A requested agent-tier key was absent.
    MissingSecret(SecretName),
    /// A key exists in both storage tiers and access is denied.
    AmbiguousKey(SecretName),
    /// Starting `sops` failed.
    SopsStart(std::io::Error),
    /// `sops` exited unsuccessfully.
    SopsFailed,
    /// Decrypted dotenv bytes were malformed or unsafe.
    InvalidDotenv,
    /// Reading the human-tier directory failed.
    HumanDirectory(std::io::Error),
    /// A human-tier filename was not a valid key name.
    InvalidHumanFile,
    /// The requested operation needs Task 4's broker transport.
    HumanTierNotImplemented,
    /// Replacing the process for an edit or injection command failed.
    Exec(std::io::Error),
    /// Writing an agent-tier value to standard output failed.
    Stdout(std::io::Error),
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage => formatter.write_str(
                "usage: secrets get KEY | secrets list | secrets KEY1 [KEY2 ...] -- command [args...]",
            ),
            Self::InvalidSecretName => formatter.write_str("invalid secret key"),
            Self::MissingSecret(name) => write!(formatter, "secret '{}' not found", name.as_str()),
            Self::AmbiguousKey(name) => write!(
                formatter,
                "key '{}' exists in both agent and human tiers; refusing ambiguous access",
                name.as_str()
            ),
            Self::SopsStart(error) => write!(formatter, "could not start sops: {error}"),
            Self::SopsFailed => formatter.write_str("sops could not decrypt the agent-tier secrets"),
            Self::InvalidDotenv => formatter.write_str("sops returned invalid dotenv data"),
            Self::HumanDirectory(error) => write!(formatter, "could not list human-tier keys: {error}"),
            Self::InvalidHumanFile => formatter.write_str("human-tier directory contains an invalid key filename"),
            Self::HumanTierNotImplemented => formatter.write_str(
                "human-tier transport is not yet implemented; ask the human to use the existing shim",
            ),
            Self::Exec(error) => write!(formatter, "could not execute command: {error}"),
            Self::Stdout(error) => write!(formatter, "could not write secret value: {error}"),
        }
    }
}

impl std::error::Error for CliError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SopsStart(error)
            | Self::HumanDirectory(error)
            | Self::Exec(error)
            | Self::Stdout(error) => Some(error),
            Self::Usage
            | Self::InvalidSecretName
            | Self::MissingSecret(_)
            | Self::AmbiguousKey(_)
            | Self::SopsFailed
            | Self::InvalidDotenv
            | Self::InvalidHumanFile
            | Self::HumanTierNotImplemented => None,
        }
    }
}

/// Run a compatible `secrets` command.
pub fn run(arguments: impl IntoIterator<Item = OsString>) -> Result<(), CliError> {
    let mut arguments = arguments.into_iter();
    let _program = arguments.next();
    let arguments: Vec<OsString> = arguments.collect();
    let command = arguments.first().ok_or(CliError::Usage)?;
    let context = Context::from_environment()?;
    match command.as_os_str() {
        value if value == OsStr::new("get") => context.get(argument_at(&arguments, 1)?),
        value if value == OsStr::new("list") => context.list(),
        value if value == OsStr::new("edit") => Context::edit(context.agent_file()),
        value if value == OsStr::new("edit-local") => Context::edit(context.local_file()),
        value if value == OsStr::new("edit-human") => {
            let name = parse_name(argument_at(&arguments, 1)?)?;
            Context::edit(context.human_file(&name))
        }
        value
            if value == OsStr::new("grants")
                || value == OsStr::new("deny")
                || value == OsStr::new("lock") =>
        {
            Err(CliError::HumanTierNotImplemented)
        }
        _ => context.inject(&arguments),
    }
}

struct Context {
    dotfiles_dir: PathBuf,
    agent: AgentStore,
    human: HumanNames,
}

impl Context {
    fn from_environment() -> Result<Self, CliError> {
        let dotfiles_dir = std::env::var_os("DOTFILES_DIR")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".dotfiles")))
            .ok_or(CliError::Usage)?;
        let human = HumanNames::load(&dotfiles_dir.join("secrets.human.d"))?;
        Ok(Self {
            agent: AgentStore::new(&dotfiles_dir, OsString::from("sops")),
            dotfiles_dir,
            human,
        })
    }

    fn get(&self, raw_name: &OsString) -> Result<(), CliError> {
        let name = parse_name(raw_name)?;
        let value = self.value(&name)?;
        let mut stdout = std::io::stdout().lock();
        stdout
            .write_all(value.as_slice())
            .map_err(CliError::Stdout)?;
        stdout.write_all(b"\n").map_err(CliError::Stdout)
    }

    fn list(&self) -> Result<(), CliError> {
        let agent = self.agent.all()?;
        self.reject_duplicates(&agent)?;
        let mut stdout = std::io::stdout().lock();
        for name in agent.keys() {
            writeln!(stdout, "{}", name.as_str()).map_err(CliError::Stdout)?;
        }
        for name in self.human.iter() {
            writeln!(stdout, "{}  (human tier)", name.as_str()).map_err(CliError::Stdout)?;
        }
        Ok(())
    }

    fn inject(&self, arguments: &[OsString]) -> Result<(), CliError> {
        let Some(separator) = arguments.iter().position(|argument| argument == "--") else {
            return Err(CliError::Usage);
        };
        let Some(command_index) = separator.checked_add(1) else {
            return Err(CliError::Usage);
        };
        if separator == 0 || command_index == arguments.len() {
            return Err(CliError::Usage);
        }
        let names = arguments.get(..separator).ok_or(CliError::Usage)?;
        let mut environment = Vec::new();
        for raw_name in names {
            let name = parse_name(raw_name)?;
            let value = self.value(&name)?;
            environment.push((
                OsString::from(name.as_str()),
                OsString::from_vec(value.as_slice().to_vec()),
            ));
        }
        let command_name = arguments.get(command_index).ok_or(CliError::Usage)?;
        let argument_index = command_index.checked_add(1).ok_or(CliError::Usage)?;
        let command_arguments = arguments.get(argument_index..).ok_or(CliError::Usage)?;
        let mut command = Command::new(command_name);
        command.args(command_arguments).envs(environment);
        Err(CliError::Exec(command.exec()))
    }

    fn value(&self, name: &SecretName) -> Result<SecretBytes, CliError> {
        let agent = self.agent.all()?;
        if self.human.contains(name) {
            self.reject_duplicates(&agent)?;
            return Err(CliError::HumanTierNotImplemented);
        }
        agent
            .get(name)
            .cloned()
            .ok_or_else(|| CliError::MissingSecret(name.clone()))
    }

    fn reject_duplicates(&self, agent: &BTreeMap<SecretName, SecretBytes>) -> Result<(), CliError> {
        for name in self.human.iter() {
            if agent.contains_key(name) {
                return Err(CliError::AmbiguousKey(name.clone()));
            }
        }
        Ok(())
    }

    fn agent_file(&self) -> PathBuf {
        self.dotfiles_dir.join("secrets.env")
    }

    fn local_file(&self) -> PathBuf {
        self.dotfiles_dir.join("secrets.local.env")
    }

    fn human_file(&self, name: &SecretName) -> PathBuf {
        self.dotfiles_dir
            .join("secrets.human.d")
            .join(name.file_name())
    }

    fn edit(path: PathBuf) -> Result<(), CliError> {
        Err(CliError::Exec(Command::new("sops").arg(path).exec()))
    }
}

fn argument_at(arguments: &[OsString], index: usize) -> Result<&OsString, CliError> {
    arguments.get(index).ok_or(CliError::Usage)
}

fn parse_name(raw: &OsString) -> Result<SecretName, CliError> {
    raw.to_str()
        .ok_or(CliError::InvalidSecretName)
        .and_then(|name| SecretName::parse(name).map_err(|_| CliError::InvalidSecretName))
}
