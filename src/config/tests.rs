use std::ffi::{OsStr, OsString};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use super::{ConfigError, SourceRoot, Sources};
use crate::{Config, TouchPolicy};

static CONFIG_ENVIRONMENT_LOCK: Mutex<()> = Mutex::new(());

struct ConfigEnvironment {
    config: Option<OsString>,
    home: Option<OsString>,
    xdg_config_home: Option<OsString>,
    yubikey_probe_timeout: Option<OsString>,
    touch_policy: Option<OsString>,
    _lock: MutexGuard<'static, ()>,
}

impl ConfigEnvironment {
    fn clear() -> Self {
        let lock = CONFIG_ENVIRONMENT_LOCK.lock().unwrap();
        let config = std::env::var_os("SECRETSD_CONFIG");
        let home = std::env::var_os("HOME");
        let xdg_config_home = std::env::var_os("XDG_CONFIG_HOME");
        let yubikey_probe_timeout = std::env::var_os("SECRETSD_YUBIKEY_PROBE_TIMEOUT_SECS");
        let touch_policy = std::env::var_os("SECRETSD_TOUCH_POLICY");

        // SAFETY: this test holds the process-wide environment lock and no daemon thread runs.
        unsafe { std::env::remove_var("SECRETSD_CONFIG") };
        // SAFETY: this test holds the process-wide environment lock and no daemon thread runs.
        unsafe { std::env::remove_var("HOME") };
        // SAFETY: this test holds the process-wide environment lock and no daemon thread runs.
        unsafe { std::env::remove_var("XDG_CONFIG_HOME") };
        // SAFETY: this test holds the process-wide environment lock and no daemon thread runs.
        unsafe { std::env::remove_var("SECRETSD_YUBIKEY_PROBE_TIMEOUT_SECS") };
        // SAFETY: this test holds the process-wide environment lock and no daemon thread runs.
        unsafe { std::env::remove_var("SECRETSD_TOUCH_POLICY") };

        Self {
            config,
            home,
            xdg_config_home,
            yubikey_probe_timeout,
            touch_policy,
            _lock: lock,
        }
    }

    fn set(name: &str, value: impl AsRef<OsStr>) {
        // SAFETY: this test retains the process-wide environment lock until restoration.
        unsafe { std::env::set_var(name, value) };
    }
}

impl Drop for ConfigEnvironment {
    fn drop(&mut self) {
        for (name, value) in [
            ("SECRETSD_CONFIG", self.config.take()),
            ("HOME", self.home.take()),
            ("XDG_CONFIG_HOME", self.xdg_config_home.take()),
            (
                "SECRETSD_YUBIKEY_PROBE_TIMEOUT_SECS",
                self.yubikey_probe_timeout.take(),
            ),
            ("SECRETSD_TOUCH_POLICY", self.touch_policy.take()),
        ] {
            match value {
                Some(value) => {
                    // SAFETY: this guard retains the process-wide environment lock until restoration.
                    unsafe { std::env::set_var(name, value) };
                }
                None => {
                    // SAFETY: this guard retains the process-wide environment lock until restoration.
                    unsafe { std::env::remove_var(name) };
                }
            }
        }
    }
}

fn parse(text: &str) -> Result<Sources, ConfigError> {
    Sources::parse(text, Path::new("/home/u"))
}

#[test]
fn parses_roots_in_declaration_order() {
    // Given two source roots, with the first path relative to the configured home directory.
    let text = "[source.zebra]\npath = \"~/zebra\"\n[source.alpha]\npath = \"/srv/alpha\"\n";

    // When the source configuration is parsed.
    let sources = parse(text).unwrap();

    // Then declaration order and expanded paths are preserved.
    let described: Vec<(&str, &Path)> = sources
        .roots
        .iter()
        .map(|root| (root.name.as_str(), root.path.as_path()))
        .collect();
    assert_eq!(
        described,
        vec![
            ("zebra", Path::new("/home/u/zebra")),
            ("alpha", Path::new("/srv/alpha")),
        ]
    );
}

#[test]
fn parses_a_home_directory_path() {
    // Given a root whose path is exactly the home-directory marker.
    let text = "[source.dotfiles]\npath = \"~\"\n";

    // When the source configuration is parsed.
    let sources = parse(text).unwrap();

    // Then the marker expands to the supplied home directory.
    assert_eq!(
        sources.roots.first().map(|root| root.path.as_path()),
        Some(Path::new("/home/u"))
    );
}

#[test]
fn rejects_relative_paths() {
    // Given a root with a non-home relative path.
    let text = "[source.dotfiles]\npath = \"dotfiles\"\n";

    // When the source configuration is parsed.
    let result = parse(text);

    // Then parsing reports the unsafe relative path.
    assert!(matches!(result, Err(ConfigError::RelativePath(path)) if path == "dotfiles"));
}

#[test]
fn rejects_unsupported_user_home_paths() {
    // Given a root with another user's home-directory marker.
    let text = "[source.dotfiles]\npath = \"~other/dotfiles\"\n";

    // When the source configuration is parsed.
    let result = parse(text);

    // Then parsing treats it as an unsupported relative path.
    assert!(matches!(result, Err(ConfigError::RelativePath(path)) if path == "~other/dotfiles"));
}

#[test]
fn rejects_empty_and_relative_home_directories() {
    // Given home-directory values that cannot produce absolute source-root paths.
    let text = "[source.dotfiles]\npath = \"~/dotfiles\"\n";

    // When each home-directory value is used for parsing.
    let results = [Path::new(""), Path::new("relhome")].map(|home| Sources::parse(text, home));

    // Then parsing refuses both values before expanding source paths.
    assert!(matches!(results[0], Err(ConfigError::NoHome)));
    assert!(matches!(results[1], Err(ConfigError::NoHome)));
}

#[test]
fn rejects_bad_root_names() {
    // Given source names outside the lowercase-hyphenated grammar.
    let texts = [
        "[source.Dotfiles]\npath = \"/srv/dotfiles\"\n",
        "[source.1x]\npath = \"/srv/one\"\n",
    ];

    // When each source configuration is parsed.
    let results = texts.map(parse);

    // Then each name is rejected as invalid.
    assert!(matches!(
        &results[0],
        Err(ConfigError::BadRootName(name)) if name == "Dotfiles"
    ));
    assert!(matches!(
        &results[1],
        Err(ConfigError::BadRootName(name)) if name == "1x"
    ));
}

#[test]
fn rejects_unknown_source_fields() {
    // Given a source table with an unexpected field.
    let text = "[source.dotfiles]\npath = \"/srv/dotfiles\"\nextra = 1\n";

    // When the source configuration is parsed.
    let result = parse(text);

    // Then deserialization rejects the unknown field.
    assert!(matches!(result, Err(ConfigError::Toml(message)) if message.contains("unknown field")));
}

#[test]
fn rejects_unknown_top_level_tables() {
    // Given a document with an unrelated top-level table.
    let text = "[source.dotfiles]\npath = \"/srv/dotfiles\"\n[other]\nk = 1\n";

    // When the source configuration is parsed.
    let result = parse(text);

    // Then parsing refuses the unsupported configuration shape.
    assert!(
        matches!(result, Err(ConfigError::Toml(message)) if message.contains("exactly one top-level source table"))
    );
}

#[test]
fn rejects_a_document_without_source_roots() {
    // Given a document with an empty source table.
    let text = "[source]\n";

    // When the source configuration is parsed.
    let result = parse(text);

    // Then parsing reports that no roots were configured.
    assert!(matches!(result, Err(ConfigError::NoRoots)));
}

#[test]
fn rejects_duplicate_resolved_paths() {
    // Given two root names resolving to one directory.
    let text =
        "[source.dotfiles]\npath = \"~/dotfiles\"\n[source.private]\npath = \"/home/u/dotfiles\"\n";

    // When the source configuration is parsed.
    let result = parse(text);

    // Then parsing reports the first and duplicate root names in declaration order.
    assert!(matches!(
        result,
        Err(ConfigError::DuplicatePath(first, duplicate))
            if first == "dotfiles" && duplicate == "private"
    ));
}

#[test]
fn rejects_duplicate_source_tables() {
    // Given duplicate TOML tables for a source name.
    let text = "[source.dotfiles]\npath = \"/srv/one\"\n[source.dotfiles]\npath = \"/srv/two\"\n";

    // When the source configuration is parsed.
    let result = parse(text);

    // Then the TOML parser rejects the duplicate table.
    assert!(matches!(result, Err(ConfigError::Toml(message)) if message.contains("duplicate")));
}

#[test]
fn rejects_parent_directory_segments() {
    // Given absolute and home-expanded source paths containing parent-directory segments.
    let texts = [
        "[source.dotfiles]\npath = \"/srv/x/../a\"\n",
        "[source.dotfiles]\npath = \"~/../escape\"\n",
    ];

    // When each configuration is parsed.
    let results = texts.map(parse);

    // Then neither path can escape its configured lexical root.
    assert!(matches!(&results[0], Err(ConfigError::RelativePath(path)) if path == "/srv/x/../a"));
    assert!(matches!(&results[1], Err(ConfigError::RelativePath(path)) if path == "~/../escape"));
}

#[test]
fn derives_the_agent_and_human_paths() {
    // Given a parsed source root.
    let root = SourceRoot {
        name: "dotfiles".to_owned(),
        path: PathBuf::from("/srv/dotfiles"),
    };

    // When its derived paths are requested.
    let agent_files = root.agent_files();
    let human_dir = root.human_dir();

    // Then the agent tier checks the local file before the shared file and the human tier uses its directory.
    assert_eq!(
        agent_files,
        [
            PathBuf::from("/srv/dotfiles/secrets.local.env"),
            PathBuf::from("/srv/dotfiles/secrets.env"),
        ]
    );
    assert_eq!(human_dir, PathBuf::from("/srv/dotfiles/secrets.human.d"));
}

#[test]
#[cfg_attr(miri, ignore)]
fn config_path_prefers_the_explicit_override() {
    // Given every config-path environment variable is set.
    // When the configuration path is resolved.
    let path = {
        let _environment = ConfigEnvironment::clear();
        ConfigEnvironment::set("HOME", Path::new("/home/u"));
        ConfigEnvironment::set("XDG_CONFIG_HOME", Path::new("/xdg"));
        ConfigEnvironment::set("SECRETSD_CONFIG", Path::new("/custom/config.toml"));
        Sources::config_path().unwrap()
    };

    // Then the explicit override wins.
    assert_eq!(path, Path::new("/custom/config.toml"));
}

#[test]
#[cfg_attr(miri, ignore)]
fn config_path_falls_back_to_xdg_config_home() {
    // Given no explicit path and an XDG configuration directory.
    // When the configuration path is resolved.
    let path = {
        let _environment = ConfigEnvironment::clear();
        ConfigEnvironment::set("HOME", Path::new("/home/u"));
        ConfigEnvironment::set("XDG_CONFIG_HOME", Path::new("/xdg"));
        Sources::config_path().unwrap()
    };

    // Then it is placed under the XDG configuration directory.
    assert_eq!(path, Path::new("/xdg/secretsd/config.toml"));
}

#[test]
#[cfg_attr(miri, ignore)]
fn config_path_falls_back_to_home_config_directory_and_rejects_relative_home() {
    // Given neither an explicit path nor an XDG configuration directory, and absolute or relative HOME values.
    // When the configuration path is resolved for each home-directory value.
    let [absolute, relative] = [Path::new("/home/u"), Path::new("relhome")].map(|home| {
        let _environment = ConfigEnvironment::clear();
        ConfigEnvironment::set("HOME", home);
        Sources::config_path()
    });

    // Then it uses the conventional absolute home configuration directory and refuses a relative fallback.
    assert_eq!(
        absolute.unwrap(),
        Path::new("/home/u/.config/secretsd/config.toml")
    );
    assert!(matches!(relative, Err(ConfigError::NoHome)));
}

#[test]
#[cfg_attr(miri, ignore)]
fn load_reports_missing_configuration_with_creation_guidance() {
    // Given the configuration environment points at a missing file.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("missing.toml");
    // When the configuration is loaded.
    let result = {
        let _environment = ConfigEnvironment::clear();
        ConfigEnvironment::set("HOME", Path::new("/home/u"));
        ConfigEnvironment::set("SECRETSD_CONFIG", &path);
        Sources::load()
    };

    // Then the missing-file error tells the operator how to create a source root.
    let error = result.unwrap_err();
    assert!(matches!(error, ConfigError::Missing(ref missing) if *missing == path));
    assert_eq!(
        error.to_string(),
        format!(
            "no secretsd config at {}; create it with a [source.<name>] table per secrets root, e.g.\n[source.dotfiles]\npath = \"~/dotfiles\"",
            path.display()
        )
    );
}

#[test]
#[cfg_attr(miri, ignore)]
fn from_env_maps_a_missing_source_configuration_to_invalid_input() {
    // Given the daemon configuration environment points at a missing source-root file.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("missing.toml");

    // When the daemon configuration is constructed.
    let error = {
        let _environment = ConfigEnvironment::clear();
        ConfigEnvironment::set("HOME", Path::new("/home/u"));
        ConfigEnvironment::set("SECRETSD_CONFIG", &path);
        Config::from_env().unwrap_err()
    };

    // Then callers receive an invalid-input error with source configuration guidance.
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert!(
        error
            .to_string()
            .contains("create it with a [source.<name>] table per secrets root"),
        "{error}"
    );
}

#[test]
#[cfg_attr(miri, ignore)]
fn load_rejects_an_unset_home_directory() {
    // Given no source configuration override or home directory.
    let result = {
        let _environment = ConfigEnvironment::clear();

        // When sources are loaded.
        Sources::load()
    };

    // Then loading refuses to fabricate a root-relative configuration path.
    assert!(matches!(result, Err(ConfigError::NoHome)));
}

#[test]
#[cfg_attr(miri, ignore)]
fn load_rejects_a_root_that_is_not_a_directory() {
    // Given configuration that names a regular file as a root.
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("not-a-directory");
    std::fs::write(&root, "not a directory").unwrap();
    let config = directory.path().join("config.toml");
    std::fs::write(
        &config,
        format!("[source.dotfiles]\npath = \"{}\"\n", root.display()),
    )
    .unwrap();
    // When the configuration is loaded.
    let result = {
        let _environment = ConfigEnvironment::clear();
        ConfigEnvironment::set("HOME", Path::new("/home/u"));
        ConfigEnvironment::set("SECRETSD_CONFIG", &config);
        Sources::load()
    };

    // Then the named root is rejected because it is not a directory, and the
    // error names the config file that declared it.
    assert!(matches!(
        result,
        Err(ConfigError::RootNotDirectory { name, path, config: declared })
            if name == "dotfiles" && path == root && declared == config
    ));
}

#[test]
#[cfg_attr(miri, ignore)]
fn from_env_reads_the_probe_timeout_from_its_environment() {
    // Given a valid source root and a probe timeout override in the daemon's environment.
    let directory = tempfile::tempdir().unwrap();
    let config_file = directory.path().join("config.toml");
    std::fs::write(
        &config_file,
        format!("[source.test]\npath = \"{}\"\n", directory.path().display()),
    )
    .unwrap();

    // When the daemon configuration is constructed.
    let config = {
        let _environment = ConfigEnvironment::clear();
        ConfigEnvironment::set("HOME", Path::new("/home/u"));
        ConfigEnvironment::set("SECRETSD_CONFIG", &config_file);
        ConfigEnvironment::set("SECRETSD_YUBIKEY_PROBE_TIMEOUT_SECS", "7");
        Config::from_env().unwrap()
    };

    // Then the probe timeout is the configured number of seconds.
    assert_eq!(config.yubikey_probe_timeout, Duration::from_secs(7));
}

#[test]
#[cfg_attr(miri, ignore)]
fn from_env_defaults_the_probe_timeout_to_two_seconds() {
    // Given a valid source root and no probe timeout in the daemon's environment.
    let directory = tempfile::tempdir().unwrap();
    let config_file = directory.path().join("config.toml");
    std::fs::write(
        &config_file,
        format!("[source.test]\npath = \"{}\"\n", directory.path().display()),
    )
    .unwrap();

    // When the daemon configuration is constructed.
    let config = {
        let _environment = ConfigEnvironment::clear();
        ConfigEnvironment::set("HOME", Path::new("/home/u"));
        ConfigEnvironment::set("SECRETSD_CONFIG", &config_file);
        Config::from_env().unwrap()
    };

    // Then the probe timeout keeps the direct-pcscd default.
    assert_eq!(config.yubikey_probe_timeout, Duration::from_secs(2));
}

#[test]
#[cfg_attr(miri, ignore)]
fn from_env_reads_an_always_touch_policy() {
    // Given a valid source root and an Always touch-policy declaration.
    let directory = tempfile::tempdir().unwrap();
    let config_file = directory.path().join("config.toml");
    std::fs::write(
        &config_file,
        format!("[source.test]\npath = \"{}\"\n", directory.path().display()),
    )
    .unwrap();

    // When the daemon configuration is constructed.
    let config = {
        let _environment = ConfigEnvironment::clear();
        ConfigEnvironment::set("HOME", Path::new("/home/u"));
        ConfigEnvironment::set("SECRETSD_CONFIG", &config_file);
        ConfigEnvironment::set("SECRETSD_TOUCH_POLICY", "always");
        Config::from_env().unwrap()
    };

    // Then the declared hardware policy is carried into the configuration.
    assert_eq!(config.touch_policy, TouchPolicy::Always);
}

#[test]
#[cfg_attr(miri, ignore)]
fn from_env_defaults_the_touch_policy_to_cached() {
    // Given a valid source root and no touch-policy declaration.
    let directory = tempfile::tempdir().unwrap();
    let config_file = directory.path().join("config.toml");
    std::fs::write(
        &config_file,
        format!("[source.test]\npath = \"{}\"\n", directory.path().display()),
    )
    .unwrap();

    // When the daemon configuration is constructed.
    let config = {
        let _environment = ConfigEnvironment::clear();
        ConfigEnvironment::set("HOME", Path::new("/home/u"));
        ConfigEnvironment::set("SECRETSD_CONFIG", &config_file);
        Config::from_env().unwrap()
    };

    // Then the stricter Cached assumption holds, keeping the cooldown floor.
    assert_eq!(config.touch_policy, TouchPolicy::Cached);
}

#[test]
#[cfg_attr(miri, ignore)]
fn from_env_rejects_an_unknown_touch_policy() {
    // Given a valid source root and an unsupported touch-policy value.
    let directory = tempfile::tempdir().unwrap();
    let config_file = directory.path().join("config.toml");
    std::fs::write(
        &config_file,
        format!("[source.test]\npath = \"{}\"\n", directory.path().display()),
    )
    .unwrap();

    // When the daemon configuration is constructed.
    let error = {
        let _environment = ConfigEnvironment::clear();
        ConfigEnvironment::set("HOME", Path::new("/home/u"));
        ConfigEnvironment::set("SECRETSD_CONFIG", &config_file);
        ConfigEnvironment::set("SECRETSD_TOUCH_POLICY", "never");
        Config::from_env().unwrap_err()
    };

    // Then startup refuses rather than guessing at the hardware's gate.
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert!(
        error
            .to_string()
            .contains("SECRETSD_TOUCH_POLICY must be cached (default) or always"),
        "{error}"
    );
}
