use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use tempfile::TempDir;

struct Fixture {
    directory: TempDir,
    config_path: PathBuf,
    dotfiles_dir: PathBuf,
    sops_log: PathBuf,
    sops_args_log: PathBuf,
    path: OsString,
}

impl Fixture {
    fn agent(contents: &str) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let dotfiles_dir = directory.path().join("dotfiles");
        let config_path = directory.path().join("config.toml");
        let bin_dir = directory.path().join("bin");
        let sops_log = directory.path().join("sops.log");
        let sops_args_log = directory.path().join("sops-args.log");
        fs::create_dir_all(&dotfiles_dir).unwrap();
        fs::create_dir_all(&bin_dir).unwrap();
        fs::write(
            &config_path,
            format!(
                "[source.dotfiles]\npath = \"{}\"\n",
                dotfiles_dir.display()
            ),
        )
        .unwrap();
        fs::write(dotfiles_dir.join("secrets.env"), contents).unwrap();
        symlink(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-sops-ok"),
            bin_dir.join("sops"),
        )
        .unwrap();

        let inherited_path = std::env::var_os("PATH").unwrap();
        let path = std::env::join_paths(
            std::iter::once(bin_dir).chain(std::env::split_paths(&inherited_path)),
        )
        .unwrap();

        Self {
            directory,
            config_path,
            dotfiles_dir,
            sops_log,
            sops_args_log,
            path,
        }
    }

    fn human(name: &str) -> Self {
        let fixture = Self::agent("");
        fixture.write_human_name(name);
        fixture
    }

    fn write_local(&self, contents: &str) {
        fs::write(self.dotfiles_dir.join("secrets.local.env"), contents).unwrap();
    }

    fn write_human_name(&self, name: &str) {
        self.write_human_name_in("dotfiles", &format!("{name}.env"));
    }

    fn add_root(&self, name: &str) {
        let root_dir = self.root_dir(name);
        fs::create_dir_all(&root_dir).unwrap();
        let mut config = fs::OpenOptions::new()
            .append(true)
            .open(&self.config_path)
            .unwrap();
        writeln!(
            config,
            "\n[source.{name}]\npath = \"{}\"",
            root_dir.display()
        )
        .unwrap();
    }

    fn write_human_name_in(&self, root: &str, file_name: &str) {
        let human_dir = self.root_dir(root).join("secrets.human.d");
        fs::create_dir_all(&human_dir).unwrap();
        fs::write(human_dir.join(file_name), b"ciphertext").unwrap();
    }

    fn write_agent_in(&self, root: &str, file_name: &str, contents: &str) {
        fs::write(self.root_dir(root).join(file_name), contents).unwrap();
    }

    fn write_token(&self, token: &str) -> PathBuf {
        let path = self.dotfiles_dir.join("session.token");
        fs::write(&path, token).unwrap();
        path
    }

    fn run_minimal<I, S>(&self, arguments: I) -> Output
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        Command::new(env!("CARGO_BIN_EXE_secrets"))
            .args(arguments)
            .env_clear()
            .env("PATH", &self.path)
            .env("SECRETSD_CONFIG", &self.config_path)
            .env("HOME", self.directory.path())
            .env("FAKE_SOPS_LOG", &self.sops_log)
            .env("FAKE_SOPS_ARGS_LOG", &self.sops_args_log)
            .env("FAKE_SOPS_PASSTHROUGH", "1")
            .output()
            .unwrap()
    }

    fn run_broker<I, S>(
        &self,
        arguments: I,
        socket: &Path,
        token_file: Option<&Path>,
        ignored_token_environment: Option<&str>,
    ) -> Output
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        let mut command = Command::new(env!("CARGO_BIN_EXE_secrets"));
        command
            .args(arguments)
            .env_clear()
            .env("PATH", &self.path)
            .env("SECRETSD_CONFIG", &self.config_path)
            .env("HOME", self.directory.path())
            .env("SECRETSD_SOCK", socket)
            .env("FAKE_SOPS_LOG", &self.sops_log)
            .env("FAKE_SOPS_ARGS_LOG", &self.sops_args_log)
            .env("FAKE_SOPS_PASSTHROUGH", "1");
        if let Some(token_file) = token_file {
            command.env("SECRETSD_SESSION_TOKEN_FILE", token_file);
        }
        if let Some(token) = ignored_token_environment {
            command.env("SECRETSD_SESSION_TOKEN", token);
        }
        command.output().unwrap()
    }

    fn sops_log(&self) -> String {
        fs::read_to_string(&self.sops_log).unwrap_or_default()
    }

    fn sops_arguments(&self) -> Vec<u8> {
        fs::read(&self.sops_args_log).unwrap_or_default()
    }

    fn sops_calls(&self) -> usize {
        self.sops_log().lines().count()
    }

    fn dotfiles_dir(&self) -> &Path {
        &self.dotfiles_dir
    }

    fn root_dir(&self, root: &str) -> PathBuf {
        if root == "dotfiles" {
            self.dotfiles_dir.clone()
        } else {
            self.directory.path().join(root)
        }
    }
}
