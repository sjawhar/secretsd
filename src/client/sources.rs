//! Read-only diagnostics for configured secrets roots.

use std::fs;
use std::io::Write;
use std::path::Path;

use super::{AgentStore, CliError};
use crate::config::{SourceRoot, Sources};
use crate::secret::{HumanFileName, parse_human_file_name};

/// Print the configured source roots and their encrypted key-file counts.
pub(super) fn run() -> Result<(), CliError> {
    let config_path = Sources::config_path().map_err(CliError::Config)?;
    let sources = Sources::load().map_err(CliError::Config)?;
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "config: {}", config_path.display()).map_err(CliError::Stdout)?;
    for root in &sources.roots {
        write_source(&mut stdout, root)?;
    }
    Ok(())
}

fn write_source(stdout: &mut impl Write, root: &SourceRoot) -> Result<(), CliError> {
    writeln!(stdout, "source {}: {}", root.name, root.path.display()).map_err(CliError::Stdout)?;
    let [local, shared] = root.agent_files();
    write_agent_count(stdout, "secrets.env", &shared)?;
    write_agent_count(stdout, "secrets.local.env", &local)?;
    write_human_count(stdout, &root.human_dir())
}

fn write_agent_count(stdout: &mut impl Write, label: &str, path: &Path) -> Result<(), CliError> {
    if !path.is_file() {
        return writeln!(stdout, "  {label}: absent").map_err(CliError::Stdout);
    }
    match AgentStore::names_in(path) {
        Ok(names) => {
            let count = names
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len();
            writeln!(stdout, "  {label}: {count} {}", key_label(count)).map_err(CliError::Stdout)
        }
        Err(error) => writeln!(stdout, "  {label}: unreadable ({error})").map_err(CliError::Stdout),
    }
}

fn write_human_count(stdout: &mut impl Write, path: &Path) -> Result<(), CliError> {
    if !path.is_dir() {
        return writeln!(stdout, "  secrets.human.d: absent").map_err(CliError::Stdout);
    }
    let counts = human_counts(path)?;
    let local = counts
        .keys
        .values()
        .filter(|files| files.local && !files.committed)
        .count();
    writeln!(
        stdout,
        "  secrets.human.d: {} {} ({local} local)",
        counts.keys.len(),
        key_label(counts.keys.len()),
    )
    .map_err(CliError::Stdout)?;
    for (name, files) in &counts.keys {
        if files.committed && files.local {
            writeln!(
                stdout,
                "  warning: key {} has both committed and local files",
                name.as_str()
            )
            .map_err(CliError::Stdout)?;
        }
    }
    for invalid in counts.invalid {
        writeln!(stdout, "  warning: invalid human file name {invalid}")
            .map_err(CliError::Stdout)?;
    }
    Ok(())
}

#[derive(Default)]
struct KeyFiles {
    committed: bool,
    local: bool,
}

struct HumanCounts {
    keys: std::collections::BTreeMap<crate::secret::SecretName, KeyFiles>,
    invalid: Vec<String>,
}

fn human_counts(path: &Path) -> Result<HumanCounts, CliError> {
    let mut entries = fs::read_dir(path)
        .map_err(CliError::HumanDirectory)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(CliError::HumanDirectory)?;
    entries.sort_by_key(fs::DirEntry::file_name);
    let mut counts = HumanCounts {
        keys: std::collections::BTreeMap::new(),
        invalid: Vec::new(),
    };
    for entry in entries {
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            counts
                .invalid
                .push(file_name.to_string_lossy().into_owned());
            continue;
        };
        match parse_human_file_name(file_name) {
            HumanFileName::Ignored => {}
            HumanFileName::Invalid => counts.invalid.push(file_name.to_owned()),
            HumanFileName::Key { name, local } => {
                let files = counts.keys.entry(name).or_default();
                if local {
                    files.local = true;
                } else {
                    files.committed = true;
                }
            }
        }
    }
    Ok(counts)
}

const fn key_label(count: usize) -> &'static str {
    if count == 1 { "key" } else { "keys" }
}
