use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use secretsd::Config;

struct Harness {
    _dir: tempfile::TempDir,
    socket: PathBuf,
    sops_log: PathBuf,
    sops_args_log: PathBuf,
    hang_marker: PathBuf,
    _fake_sops_env_lock: MutexGuard<'static, ()>,
}

fn fake_sops_env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(Mutex::default)
}

impl Harness {
    fn start(keys: &[&str]) -> Self {
        Self::start_with_sops(keys, "fake-sops-ok")
    }

    fn start_with_sops(keys: &[&str], sops: &str) -> Self {
        let fake_sops_env_lock = fake_sops_env_lock().lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let sops_log = dir.path().join("fake-sops-invocations.log");
        let sops_args_log = dir.path().join("fake-sops-arguments.log");
        // SAFETY: nextest executes every integration test in a separate process. This
        // test owns the harness environment lock and has not started daemon threads yet.
        unsafe { std::env::set_var("FAKE_SOPS_LOG", &sops_log) };
        // SAFETY: nextest executes every integration test in a separate process. This
        // test owns the harness environment lock and has not started daemon threads yet.
        unsafe { std::env::set_var("FAKE_SOPS_ARGS_LOG", &sops_args_log) };
        // The hanging fixture is killed by the test that uses it, so it can never
        // clean up after itself. Keeping its marker inside this TempDir means the
        // file dies with the harness on every path, including a panic, instead of
        // accumulating one `/tmp` entry per run -- and it is no longer at a shared,
        // predictable path another user could create first to steer the pid the
        // test kills.
        let hang_marker = dir.path().join("fake-sops-hang.pid");
        // SAFETY: nextest executes every integration test in a separate process. This
        // test owns the harness environment lock and has not started daemon threads yet.
        unsafe { std::env::set_var("FAKE_SOPS_HANG_MARKER", &hang_marker) };
        let human = dir.path().join("human.d");
        std::fs::create_dir(&human).unwrap();
        for key in keys {
            std::fs::write(human.join(format!("{key}.env")), b"ciphertext").unwrap();
        }
        let socket = dir.path().join("secretsd.sock");
        let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let config = Config {
            socket_path: socket.clone(),
            human_dir: human,
            sops_bin: fixtures.join(sops),
            pcsc_socket: None,
            yubikey_probe_argv: Vec::new(),
            max_grant: Duration::from_hours(12),
            cooldown: Duration::from_secs(16),
            request_ttl: Duration::from_secs(20),
            max_pending_per_scope: 2,
        };
        std::thread::spawn(move || secretsd::run(config));
        for _ in 0..100 {
            if socket.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Self {
            _dir: dir,
            socket,
            sops_log,
            sops_args_log,
            hang_marker,
            _fake_sops_env_lock: fake_sops_env_lock,
        }
    }

    fn send(&self, line: &str) -> (String, Vec<u8>) {
        let mut stream = UnixStream::connect(&self.socket).unwrap();
        stream.write_all(line.as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();
        let mut reader = BufReader::new(stream);
        let mut header = String::new();
        reader.read_line(&mut header).unwrap();
        let mut payload = Vec::new();
        if let Some(len) = header.trim().strip_prefix("OK\tlen=") {
            let len: usize = len.parse().unwrap();
            payload.resize(len, 0);
            reader.read_exact(&mut payload).unwrap();
        }
        (header, payload)
    }

    const fn socket(&self) -> &PathBuf {
        &self.socket
    }

    const fn hang_marker(&self) -> &PathBuf {
        &self.hang_marker
    }

    fn sops_invocations(&self) -> usize {
        std::fs::read_to_string(&self.sops_log)
            .unwrap_or_default()
            .lines()
            .count()
    }

    fn sops_arguments(&self) -> Vec<String> {
        std::fs::read_to_string(&self.sops_args_log)
            .unwrap_or_default()
            .split('\0')
            .filter(|argument| !argument.is_empty())
            .map(ToOwned::to_owned)
            .collect()
    }
}
