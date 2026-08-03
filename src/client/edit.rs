//! Multi-source edit command parsing and path selection.

use std::ffi::{OsStr, OsString};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

use super::cli::parse_name;
use super::{CliError, HumanLocation, HumanNames};
use crate::config::{ConfigError, SourceRoot, Sources};
use crate::secret::SecretName;

/// Edit an agent-tier file in the selected source root.
pub(super) fn agent(
    sources: &Sources,
    arguments: &[OsString],
    local: bool,
) -> Result<(), CliError> {
    let flags = edit_arguments(arguments, 1, false)?;
    let [local_path, shared_path] = select_root(sources, flags.source)?.agent_files();
    let path = if local { local_path } else { shared_path };
    edit(path)
}

/// Edit an existing human-tier key or create its selected file path.
pub(super) fn human(
    sources: &Sources,
    human: &HumanNames,
    arguments: &[OsString],
) -> Result<(), CliError> {
    let name = parse_name(argument_at(arguments, 1)?)?;
    let flags = edit_arguments(arguments, 2, true)?;
    let path = match human.location(&name) {
        Some(location) => existing_human_path(
            sources,
            &ExistingHumanEdit {
                name: &name,
                location,
                flags,
            },
        )?,
        None => new_human_path(sources, &name, flags)?,
    };
    edit(path)
}

#[derive(Clone, Copy)]
struct EditArguments<'a> {
    source: Option<&'a OsString>,
    local: bool,
}

struct ExistingHumanEdit<'a> {
    name: &'a SecretName,
    location: &'a HumanLocation,
    flags: EditArguments<'a>,
}

fn edit_arguments(
    arguments: &[OsString],
    flag_start: usize,
    accepts_local: bool,
) -> Result<EditArguments<'_>, CliError> {
    let source_flag = OsStr::new("--source");
    let local_flag = OsStr::new("--local");
    let flags = arguments.get(flag_start..).ok_or(CliError::Usage)?;
    let mut source = None;
    let mut local = false;
    let mut flags = flags.iter();
    while let Some(flag) = flags.next() {
        if flag == source_flag {
            let value = flags.next().ok_or(CliError::Usage)?;
            if source.replace(value).is_some()
                || value.to_str().is_some_and(|value| value.starts_with("--"))
            {
                return Err(CliError::Usage);
            }
        } else if accepts_local && flag == local_flag {
            if local {
                return Err(CliError::Usage);
            }
            local = true;
        } else {
            return Err(CliError::Usage);
        }
    }
    Ok(EditArguments { source, local })
}

fn existing_human_path(
    sources: &Sources,
    edit: &ExistingHumanEdit<'_>,
) -> Result<PathBuf, CliError> {
    let actual_source = edit
        .location
        .label
        .strip_suffix(".local")
        .unwrap_or(edit.location.label.as_str());
    if let Some(source) = edit.flags.source {
        let selected = select_named_root(sources, source)?;
        if selected.name != actual_source {
            return Err(CliError::EditConflict {
                name: edit.name.clone(),
                actual: edit.location.label.clone(),
            });
        }
    }
    let actual_local = edit.location.label.as_str() != actual_source;
    if edit.flags.local && !actual_local {
        return Err(CliError::EditConflict {
            name: edit.name.clone(),
            actual: edit.location.label.clone(),
        });
    }
    Ok(edit.location.path.clone())
}

fn new_human_path(
    sources: &Sources,
    name: &SecretName,
    flags: EditArguments<'_>,
) -> Result<PathBuf, CliError> {
    let root = select_root(sources, flags.source)?;
    let directory = root.human_dir();
    std::fs::create_dir_all(&directory).map_err(CliError::HumanDirectory)?;
    let file_name = if flags.local {
        name.local_file_name()
    } else {
        name.file_name()
    };
    Ok(directory.join(file_name))
}

fn select_root<'a>(
    sources: &'a Sources,
    source: Option<&OsString>,
) -> Result<&'a SourceRoot, CliError> {
    source.map_or_else(
        || match sources.roots.as_slice() {
            [root] => Ok(root),
            [] => Err(CliError::Config(ConfigError::NoRoots)),
            _ => Err(CliError::EditSourceRequired(source_names(sources))),
        },
        |source| select_named_root(sources, source),
    )
}

fn select_named_root<'a>(
    sources: &'a Sources,
    raw_source: &OsString,
) -> Result<&'a SourceRoot, CliError> {
    let source = raw_source.to_str().ok_or(CliError::Usage)?;
    sources
        .roots
        .iter()
        .find(|root| root.name == source)
        .ok_or_else(|| CliError::UnknownEditSource {
            source: source.to_owned(),
            available: source_names(sources),
        })
}

fn source_names(sources: &Sources) -> String {
    sources
        .roots
        .iter()
        .map(|root| root.name.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

fn argument_at(arguments: &[OsString], index: usize) -> Result<&OsString, CliError> {
    arguments.get(index).ok_or(CliError::Usage)
}

fn edit(path: PathBuf) -> Result<(), CliError> {
    Err(CliError::Exec(Command::new("sops").arg(path).exec()))
}
