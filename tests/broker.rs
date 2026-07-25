#![allow(
    clippy::unwrap_used,
    clippy::useless_format,
    missing_docs,
    reason = "the task specification provides this integration harness verbatim"
)]

use std::sync::mpsc;

use nix::sys::signal::killpg;
use nix::unistd::Pid;
#[path = "broker/grants.rs"]
mod grants;
include!("broker/support.rs");

fn send_to(socket: &PathBuf, line: &str) -> (String, Vec<u8>) {
    let mut stream = UnixStream::connect(socket).unwrap();
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

const TOKEN_A: &str = "aa";
const TOKEN_B: &str = "bb";

static REQUEST_LOG: OnceLock<Mutex<Vec<u8>>> = OnceLock::new();
static REQUEST_LOG_INIT: OnceLock<()> = OnceLock::new();

#[derive(Clone, Copy)]
struct RequestLogWriter;

impl Write for RequestLogWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        {
            let mut log = REQUEST_LOG
                .get_or_init(|| Mutex::new(Vec::new()))
                .lock()
                .unwrap();
            log.extend_from_slice(buffer);
        }
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn request_log() -> &'static Mutex<Vec<u8>> {
    REQUEST_LOG.get_or_init(|| Mutex::new(Vec::new()))
}

fn install_request_log_capture() {
    REQUEST_LOG_INIT.get_or_init(|| {
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_target(false)
            .with_writer(|| RequestLogWriter)
            .finish();
        tracing::subscriber::set_global_default(subscriber).unwrap();
    });
}

fn token(prefix: &str) -> String {
    prefix.repeat(32)
}

#[test]
fn request_log_attributes_a_grant_without_secret_or_token_bytes() {
    install_request_log_capture();
    request_log().lock().unwrap().clear();
    let token = token(TOKEN_A);
    let harness = Harness::start(&["DEEL_API_KEY"]);
    harness.send(&format!("REGISTER\ttoken={token}\tsession=ses_a\tpid=1"));
    let registration_log = String::from_utf8(request_log().lock().unwrap().clone()).unwrap();
    assert!(
        registration_log.contains("untrusted_registered_session=Some(\"ses_a\")"),
        "REGISTER did not log its session"
    );
    // The frame above claims pid=1. The daemon takes the registering process's
    // identity from the kernel instead, so the log must show this test process
    // and must not echo the value supplied on the wire.
    assert!(
        registration_log.contains(&format!("caller_pid=Some({})", std::process::id())),
        "REGISTER did not log the kernel-derived caller pid"
    );
    assert!(
        !registration_log.contains("caller_pid=Some(1)"),
        "REGISTER trusted the pid supplied on the wire"
    );
    let (header, payload) = harness.send(&format!("GET\tkey=DEEL_API_KEY\ttoken={token}"));

    assert!(header.starts_with("OK\tlen="), "{header}");
    assert_eq!(payload, b"value-for-DEEL_API_KEY");
    let log = String::from_utf8(request_log().lock().unwrap().clone()).unwrap();
    assert!(log.contains("request handled"), "{log}");
    assert!(log.contains("key=DEEL_API_KEY"), "{log}");
    assert!(
        log.contains("untrusted_registered_session=Some(\"ses_a\")"),
        "{log}"
    );
    assert!(log.contains("registered_root_pid=Some("), "{log}");
    // A release served from a live grant is otherwise silent, so the audit
    // must record that bytes moved and how many.
    assert!(log.contains("released_bytes=Some("), "{log}");
    assert!(log.contains("decision="), "{log}");
    assert!(!log.contains("value-for-DEEL_API_KEY"), "{log}");
    assert!(!log.contains(&token), "{log}");
    drop(harness);
}

#[test]
fn hello_reports_protocol_version() {
    let harness = Harness::start(&[]);
    let (header, _) = harness.send("HELLO\tversion=1");
    assert!(header.starts_with("OK"), "{header}");
    drop(harness);
}

#[test]
fn version_mismatch_is_rejected() {
    let harness = Harness::start(&[]);
    let (header, _) = harness.send("HELLO\tversion=999");
    assert!(header.contains("VERSION_MISMATCH"), "{header}");
    drop(harness);
}

#[test]
fn stalled_connections_are_bounded_and_do_not_block_requests() {
    let harness = Harness::start(&[]);
    let baseline_threads = std::fs::read_dir("/proc/self/task").unwrap().count();
    let mut stalled = Vec::new();
    for _ in 0..32 {
        stalled.push(UnixStream::connect(harness.socket()).unwrap());
    }
    std::thread::sleep(Duration::from_millis(100));

    let threads_after_pressure = std::fs::read_dir("/proc/self/task").unwrap().count();
    assert!(
        threads_after_pressure <= baseline_threads + 12,
        "stalled clients created unbounded handler threads: {baseline_threads} -> {threads_after_pressure}"
    );

    let (header, _) = harness.send("HELLO\tversion=1");
    assert!(
        header.starts_with("OK"),
        "request was blocked by stalled clients: {header}"
    );
    drop(stalled);
    drop(harness);
}

#[test]
fn unregister_revokes_grants() {
    let harness = Harness::start(&["DEEL_API_KEY"]);
    harness.send(&format!(
        "REGISTER\ttoken={}\tsession=ses_a\tpid=1",
        token(TOKEN_A)
    ));
    harness.send(&format!("GET\tkey=DEEL_API_KEY\ttoken={}", token(TOKEN_A)));
    harness.send("UNREGISTER\tsession=ses_a");

    let (header, _) = harness.send(&format!("GET\tkey=DEEL_API_KEY\ttoken={}", token(TOKEN_A)));
    assert!(header.contains("UNKNOWN_TOKEN"), "{header}");
    drop(harness);
}

#[test]
fn replacing_a_session_registration_revokes_displaced_grants() {
    let harness = Harness::start(&["DEEL_API_KEY"]);
    harness.send(&format!(
        "REGISTER\ttoken={}\tsession=ses_a\tpid=1",
        token(TOKEN_A)
    ));
    harness.send(&format!("GET\tkey=DEEL_API_KEY\ttoken={}", token(TOKEN_A)));
    harness.send(&format!(
        "REGISTER\ttoken={}\tsession=ses_a\tpid=1",
        token(TOKEN_B)
    ));

    let (header, payload) = harness.send("GRANTS");
    assert!(header.starts_with("OK"), "{header}");
    assert!(
        String::from_utf8_lossy(&payload).contains("no active grants"),
        "replaced token retained an unreachable plaintext grant"
    );
    drop(harness);
}

#[test]
fn lock_wipes_all_grants() {
    let harness = Harness::start(&["DEEL_API_KEY"]);
    harness.send(&format!(
        "REGISTER\ttoken={}\tsession=ses_a\tpid=1",
        token(TOKEN_A)
    ));
    harness.send(&format!("GET\tkey=DEEL_API_KEY\ttoken={}", token(TOKEN_A)));
    harness.send("LOCK");

    let (header, payload) = harness.send("GRANTS");
    assert!(header.starts_with("OK"), "{header}");
    let text = String::from_utf8_lossy(&payload);
    assert!(text.contains("no active grants"), "{text}");
    drop(harness);
}

#[test]
fn grants_listing_never_contains_values() {
    let harness = Harness::start(&["DEEL_API_KEY"]);
    harness.send(&format!(
        "REGISTER\ttoken={}\tsession=ses_a\tpid=1",
        token(TOKEN_A)
    ));
    harness.send(&format!("GET\tkey=DEEL_API_KEY\ttoken={}", token(TOKEN_A)));
    let (_, payload) = harness.send("GRANTS");
    let text = String::from_utf8_lossy(&payload);
    assert!(
        !text.contains("value-for-"),
        "grant listing leaked a secret: {text}"
    );
    drop(harness);
}

#[test]
fn tokenless_request_from_a_learned_agent_tty_is_rejected() {
    let harness = Harness::start(&["DEEL_API_KEY"]);
    harness.send(&format!(
        "REGISTER\ttoken={}\tsession=ses_a\tpid=1",
        token(TOKEN_A)
    ));
    harness.send(&format!(
        "GET\tkey=DEEL_API_KEY\ttoken={}\ttty=/dev/pts/42",
        token(TOKEN_A)
    ));

    let (header, _) = harness.send("GET\tkey=DEEL_API_KEY\ttty=/dev/pts/42");
    assert!(
        header.contains("AGENT_TTY"),
        "env-stripped agent slipped through: {header}"
    );
    drop(harness);
}

#[test]
fn deny_kills_the_hanging_sops_process_group() {
    let marker = PathBuf::from(format!(
        "/tmp/secretsd-fake-sops-hang-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&marker);
    let harness = Harness::start_with_sops(&["DEEL_API_KEY"], "fake-sops-hang");
    harness.send(&format!(
        "REGISTER\ttoken={}\tsession=ses_a\tpid=1",
        token(TOKEN_A)
    ));
    let socket = harness.socket().clone();
    let (response_tx, response_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = response_tx.send(send_to(
            &socket,
            &format!("GET\tkey=DEEL_API_KEY\ttoken={}", token(TOKEN_A)),
        ));
    });
    for _ in 0..100 {
        if marker.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let process_id: i32 = std::fs::read_to_string(&marker)
        .unwrap()
        .trim()
        .parse()
        .unwrap();

    let (header, _) = harness.send("DENY\tid=1");

    assert!(header.starts_with("OK"), "{header}");
    assert!(response_rx.recv_timeout(Duration::from_secs(1)).is_ok());
    for _ in 0..100 {
        if killpg(Pid::from_raw(process_id), None).is_err() {
            drop(harness);
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    drop(harness);
    panic!("denied sops process group remained alive");
}
