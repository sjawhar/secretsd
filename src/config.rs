//! Source-root configuration carrying directory paths, never secret values.

use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use std::path::{Component, Path, PathBuf};

use serde::Deserialize;

/// A named secrets root and its absolute directory path.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(
    clippy::exhaustive_structs,
    reason = "source roots are an explicit shared configuration data contract"
)]
pub struct SourceRoot {
    /// Lowercase source-root name from the configuration table.
    pub name: String,
    /// Absolute source-root directory path.
    pub path: PathBuf,
}

impl SourceRoot {
    /// Return the agent-tier files in precedence order.
    pub fn agent_files(&self) -> [PathBuf; 2] {
        [
            self.path.join("secrets.local.env"),
            self.path.join("secrets.env"),
        ]
    }

    /// Return the human-tier secrets directory.
    pub fn human_dir(&self) -> PathBuf {
        self.path.join("secrets.human.d")
    }
}

/// Ordered, non-empty collection of configured secrets roots; parsing rejects empty source tables.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(
    clippy::exhaustive_structs,
    reason = "source roots are an explicit shared configuration data contract"
)]
pub struct Sources {
    /// Source roots in configuration declaration order.
    pub roots: Vec<SourceRoot>,
}

impl Sources {
    /// Return the path to the source-root configuration file.
    ///
    /// # Errors
    ///
    /// Returns `ConfigError::NoHome` when resolving the home-directory fallback requires an absent or relative HOME.
    pub fn config_path() -> Result<PathBuf, ConfigError> {
        if let Some(path) = environment_path("SECRETSD_CONFIG") {
            return Ok(path);
        }
        if let Some(path) = environment_path("XDG_CONFIG_HOME") {
            return Ok(path.join("secretsd/config.toml"));
        }

        Ok(home_path()?.join(".config/secretsd/config.toml"))
    }

    /// Load and validate configured source-root directories.
    ///
    /// # Errors
    ///
    /// Returns an error when the configuration cannot be read or parsed, or a configured root is not a directory.
    pub fn load() -> Result<Self, ConfigError> {
        let home = home_path()?;
        let config_path = Self::config_path()?;
        let text = std::fs::read_to_string(&config_path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                ConfigError::Missing(config_path.clone())
            } else {
                ConfigError::Read(config_path.clone(), error)
            }
        })?;
        let sources = Self::parse(&text, &home)?;

        for root in &sources.roots {
            if !root.path.is_dir() {
                return Err(ConfigError::RootNotDirectory {
                    name: root.name.clone(),
                    path: root.path.clone(),
                    config: config_path,
                });
            }
        }

        Ok(sources)
    }

    /// Parse source-root TOML without reading the environment or filesystem.
    ///
    /// # Errors
    ///
    /// Returns an error when the TOML shape, root name, or root path is invalid.
    pub fn parse(text: &str, home: &Path) -> Result<Self, ConfigError> {
        if !home.is_absolute() {
            return Err(ConfigError::NoHome);
        }
        let mut document = text
            .parse::<toml::Table>()
            .map_err(|error| ConfigError::Toml(error.to_string()))?;
        if document.len() != 1 {
            return Err(ConfigError::Toml(
                "config must contain exactly one top-level source table".to_owned(),
            ));
        }
        let source = document.remove("source").ok_or_else(|| {
            ConfigError::Toml("config must contain a top-level source table".to_owned())
        })?;
        let toml::Value::Table(source) = source else {
            return Err(ConfigError::Toml(
                "top-level source must be a table".to_owned(),
            ));
        };
        if source.is_empty() {
            return Err(ConfigError::NoRoots);
        }

        let mut roots = Vec::with_capacity(source.len());
        let mut paths = BTreeMap::new();
        for (name, value) in source {
            if !is_root_name(&name) {
                return Err(ConfigError::BadRootName(name));
            }
            let raw = value
                .try_into::<RawSource>()
                .map_err(|error| ConfigError::Toml(error.to_string()))?;
            let path = resolve_path(raw.path, home)?;
            if let Some(first) = paths.insert(path.clone(), name.clone()) {
                return Err(ConfigError::DuplicatePath(first, name));
            }
            roots.push(SourceRoot { name, path });
        }

        Ok(Self { roots })
    }
}

/// Errors returned while resolving source-root configuration.
#[derive(Debug)]
#[allow(
    clippy::exhaustive_enums,
    reason = "configuration failures are an explicit shared configuration data contract"
)]
pub enum ConfigError {
    /// The expected configuration file was absent.
    Missing(PathBuf),
    /// Reading the configuration file failed.
    Read(PathBuf, std::io::Error),
    /// The configuration was not valid source-root TOML.
    Toml(String),
    /// A source-root name was outside the accepted grammar.
    BadRootName(String),
    /// A source-root path was not absolute or a supported home path.
    RelativePath(String),
    /// Two source roots resolve to the same path, in first-seen order.
    DuplicatePath(String, String),
    /// The source table did not declare a root.
    NoRoots,
    /// A configured source root does not name an existing directory.
    RootNotDirectory {
        /// Root name as declared in the config.
        name: String,
        /// The path that is not a directory.
        path: PathBuf,
        /// The config file that declared the root.
        config: PathBuf,
    },
    /// HOME was absent, empty, or not an absolute directory path.
    NoHome,
}

impl Display for ConfigError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing(path) => write!(
                formatter,
                "no secretsd config at {}; create it with a [source.<name>] table per secrets root, e.g.\n[source.dotfiles]\npath = \"~/dotfiles\"",
                path.display()
            ),
            Self::Read(path, error) => {
                write!(
                    formatter,
                    "failed to read secretsd config at {}: {error}",
                    path.display()
                )
            }
            Self::Toml(error) => write!(formatter, "invalid secretsd config: {error}"),
            Self::BadRootName(name) => write!(
                formatter,
                "invalid secretsd source root name {name}; expected [a-z][a-z0-9-]*"
            ),
            Self::RelativePath(path) => write!(
                formatter,
                "source root path {path} must be absolute and free of .. segments"
            ),
            Self::DuplicatePath(first, duplicate) => write!(
                formatter,
                "source roots {first} and {duplicate} resolve to the same path"
            ),
            Self::NoRoots => formatter
                .write_str("secretsd config must define at least one [source.<name>] table"),
            Self::RootNotDirectory { name, path, config } => write!(
                formatter,
                "source root {name} is not an existing directory: {}; clone or create it, or remove [source.{name}] from {}",
                path.display(),
                config.display()
            ),
            Self::NoHome => formatter.write_str("HOME must be set to an absolute path"),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read(_, error) => Some(error),
            Self::Missing(_)
            | Self::Toml(_)
            | Self::BadRootName(_)
            | Self::RelativePath(_)
            | Self::DuplicatePath(_, _)
            | Self::NoRoots
            | Self::RootNotDirectory { .. }
            | Self::NoHome => None,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSource {
    path: String,
}

fn environment_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn home_path() -> Result<PathBuf, ConfigError> {
    let home = environment_path("HOME").ok_or(ConfigError::NoHome)?;
    if home.is_absolute() {
        Ok(home)
    } else {
        Err(ConfigError::NoHome)
    }
}

fn is_root_name(name: &str) -> bool {
    let mut characters = name.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    first.is_ascii_lowercase()
        && characters.all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        })
}

fn resolve_path(raw: String, home: &Path) -> Result<PathBuf, ConfigError> {
    let path = if raw == "~" {
        home.to_path_buf()
    } else if let Some(path) = raw.strip_prefix("~/") {
        home.join(path.trim_start_matches('/'))
    } else {
        PathBuf::from(&raw)
    };

    if path.is_absolute()
        && !path
            .components()
            .any(|component| component == Component::ParentDir)
    {
        Ok(path)
    } else {
        Err(ConfigError::RelativePath(raw))
    }
}

#[cfg(test)]
mod tests;
