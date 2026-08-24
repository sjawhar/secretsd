//! Unix-socket server coordination.

use std::io::{Read, Write};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, mpsc};
use std::thread;
use std::time::Duration;
#[cfg(test)]
use std::time::Instant;

use nix::errno::Errno;
use nix::sys::signal::{Signal, killpg};
use nix::sys::socket::sockopt::{AcceptConn, PeerCredentials, SockType as SocketType};
use nix::sys::socket::{MsgFlags, SockType, UnixAddr, getsockname, getsockopt, recv, send};
use nix::sys::stat::{SFlag, fstat};
use nix::unistd::{Pid, geteuid};
use zeroize::Zeroizing;

use crate::Config;
#[cfg(test)]
use crate::audit::MAX_AUDIT_VALUE_BYTES;
use crate::audit::sanitize_audit_value;
use crate::decrypt::Decryptor;
use crate::grants::{GrantTable, Registry, SessionToken};
use crate::proto::{ErrCode, MAX_FRAME_BYTES, Request, Response, format_response, parse_request};
use crate::receipts::ReceiptTable;
use crate::requests::{Queue, QueueLimits, RequestId};
use crate::store::HumanStore;

mod approval;
mod dispatch;
mod worker;

use dispatch::{Outcome, dispatch, request_key};
use worker::worker;

type Shared = Arc<(Mutex<State>, Condvar)>;

const CONNECTION_WORKERS: usize = 8;
const CONNECTION_QUEUE_DEPTH: usize = 8;
const FAST_CONNECTION_WORKERS: usize = 1;
const FAST_CONNECTION_QUEUE_DEPTH: usize = 8;
const CONTROL_CONNECTION_WORKERS: usize = 1;
const CONTROL_CONNECTION_QUEUE_DEPTH: usize = 8;
#[cfg(test)]
const CONNECTION_CAPACITY: usize = CONNECTION_WORKERS + CONNECTION_QUEUE_DEPTH;
const CONNECTION_READ_TIMEOUT: Duration = Duration::from_millis(250);
const CONNECTION_CAPACITY_RESPONSE: &[u8] = b"ERR\tINTERNAL\tconnection capacity reached\n";

#[derive(Debug)]
struct State {
    /// Identifies this daemon process so a harness can notice a restart.
    instance: String,
    registry: Registry,
    grants: GrantTable,
    receipts: ReceiptTable,
    queue: Queue,
    store: HumanStore,
    decryptor: Decryptor,
    config: Config,
    failures: Vec<(RequestId, ErrCode)>,
    lock_epoch: u64,
    active_decrypt: Option<ActiveDecrypt>,
}

#[derive(Debug)]
struct ActiveDecrypt {
    id: RequestId,
    process_group: i32,
}

impl State {
    fn new(config: Config) -> std::io::Result<Self> {
        let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?
            .trim()
            .to_owned();
        let instance = random_instance_id()?;
        Ok(Self {
            instance,
            registry: Registry::new(boot_id),
            grants: GrantTable::default(),
            receipts: ReceiptTable::default(),
            queue: Queue::new(QueueLimits {
                cooldown: config.cooldown,
                ttl: config.request_ttl,
                max_pending_per_scope: config.max_pending_per_scope,
            }),
            store: HumanStore::new(config.human_sources.clone()),
            decryptor: config.decryptor(),
            config,
            failures: Vec::new(),
            lock_epoch: 0,
            active_decrypt: None,
        })
    }

    fn kill_active(&mut self, id: RequestId) {
        if self
            .active_decrypt
            .as_ref()
            .is_some_and(|active| active.id == id)
            && let Some(active) = self.active_decrypt.take()
        {
            let _ = killpg(Pid::from_raw(active.process_group), Signal::SIGKILL);
        }
    }
}

fn lock_state(mutex: &Mutex<State>) -> MutexGuard<'_, State> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn wait_state<'a>(
    condvar: &Condvar,
    guard: MutexGuard<'a, State>,
    duration: Duration,
) -> MutexGuard<'a, State> {
    condvar
        .wait_timeout(guard, duration)
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .0
}

/// Generate an identifier unique to this daemon process.
///
/// Grants and registrations are memory-only, so a restart silently invalidates
/// every registration a harness is holding. Reporting this value in the
/// handshake lets the harness detect that and re-register before its requests
/// start failing. It is an identity marker, not a credential: it authorizes
/// nothing, and a touch is still required for every new grant.
fn random_instance_id() -> std::io::Result<String> {
    use std::fmt::Write as _;

    let mut bytes = [0_u8; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes
        .iter()
        .fold(String::with_capacity(32), |mut id, byte| {
            let _ = write!(id, "{byte:02x}");
            id
        }))
}

fn socket_activated() -> bool {
    std::env::var("LISTEN_FDS").is_ok_and(|value| value == "1")
        && std::env::var("LISTEN_PID")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .is_some_and(|pid| pid == std::process::id())
}

fn activation_environment_present() -> bool {
    std::env::var_os("LISTEN_FDS").is_some() || std::env::var_os("LISTEN_PID").is_some()
}

const fn peer_uid_is_authorized(peer_uid: u32, daemon_uid: u32) -> bool {
    peer_uid == daemon_uid
}

#[derive(Debug)]
struct AuditContext {
    key: String,
    untrusted_registered_session: Option<String>,
    registered_root_pid: Option<i32>,
}

fn audit_context(request: &Request, shared: &Shared) -> AuditContext {
    let mut audit = AuditContext {
        key: match request {
            Request::Authorize { cap, .. } => {
                sanitize_audit_value(&format!("CAP_{}", cap.to_ascii_uppercase()))
            }
            _ => request_key(request).map_or_else(|| "-".to_owned(), sanitize_audit_value),
        },
        untrusted_registered_session: None,
        registered_root_pid: None,
    };
    let token_hex = match request {
        Request::Get { token_hex, .. }
        | Request::RequestGrant { token_hex, .. }
        | Request::Authorize { token_hex, .. } => token_hex,
        Request::Register { session, .. } => {
            // The pid on the wire is not recorded: `caller_pid` on the log line
            // carries the kernel's view of who actually registered.
            audit.untrusted_registered_session = Some(sanitize_audit_value(session));
            return audit;
        }
        Request::Hello { .. }
        | Request::Unregister { .. }
        | Request::Grants
        | Request::Deny { .. }
        | Request::Lock
        | Request::Redeem { .. } => return audit,
    };
    let Some(token) = token_hex
        .as_deref()
        .and_then(|token_hex| SessionToken::parse_hex(token_hex.as_str()).ok())
    else {
        return audit;
    };
    let (mutex, _) = &**shared;
    let state = lock_state(mutex);
    let Some(registration) = state.registry.registration(&token) else {
        return audit;
    };
    audit.untrusted_registered_session = Some(sanitize_audit_value(&registration.session));
    audit.registered_root_pid = registration.root.pid();
    drop(state);
    audit
}

fn validate_activated_listener(fd: BorrowedFd<'_>) -> std::io::Result<()> {
    let stat = fstat(fd.as_raw_fd()).map_err(std::io::Error::other)?;
    if !SFlag::from_bits_truncate(stat.st_mode).contains(SFlag::S_IFSOCK) {
        return Err(std::io::Error::other("activation fd is not a socket"));
    }
    if getsockopt(&fd, SocketType).map_err(std::io::Error::other)? != SockType::Stream {
        return Err(std::io::Error::other(
            "activation fd is not a stream socket",
        ));
    }
    if !getsockopt(&fd, AcceptConn).map_err(std::io::Error::other)? {
        return Err(std::io::Error::other("activation socket is not listening"));
    }
    let _: UnixAddr = getsockname(fd.as_raw_fd()).map_err(std::io::Error::other)?;
    Ok(())
}

fn listener(config: &Config) -> std::io::Result<UnixListener> {
    if socket_activated() {
        // SAFETY: fd 3 is valid for the duration of this call because activation
        // descriptors are inherited from this process; `validate_activated_listener`
        // verifies its socket type, protocol family, and listening state before adoption.
        let fd = unsafe { BorrowedFd::borrow_raw(3) };
        validate_activated_listener(fd)?;
        // SAFETY: the borrowed fd was validated above and ownership transfers once
        // into the resulting listener, which closes it exactly once on drop.
        return Ok(unsafe { UnixListener::from_raw_fd(3) });
    }
    if activation_environment_present() {
        return Err(std::io::Error::other(
            "invalid socket activation environment",
        ));
    }
    if let Err(error) = std::fs::remove_file(&config.socket_path)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        return Err(error);
    }
    let listener = UnixListener::bind(&config.socket_path)?;
    std::fs::set_permissions(&config.socket_path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

fn read_frame(stream: &mut UnixStream) -> std::io::Result<Zeroizing<Vec<u8>>> {
    let mut read_buffer = Zeroizing::new(vec![0_u8; MAX_FRAME_BYTES + 1]);
    let mut frame = Zeroizing::new(Vec::with_capacity(MAX_FRAME_BYTES + 1));
    loop {
        let remaining = (MAX_FRAME_BYTES + 1).saturating_sub(frame.len());
        if remaining == 0 {
            break;
        }
        let writable = read_buffer
            .get_mut(..remaining)
            .ok_or_else(|| std::io::Error::other("frame buffer bounds invalid"))?;
        let bytes = stream.read(writable)?;
        if bytes == 0 {
            break;
        }
        let chunk = read_buffer
            .get(..bytes)
            .ok_or_else(|| std::io::Error::other("frame read exceeded buffer"))?;
        if let Some(newline) = chunk.iter().position(|byte| *byte == b'\n') {
            let line = chunk
                .get(..=newline)
                .ok_or_else(|| std::io::Error::other("frame newline exceeded buffer"))?;
            frame.extend_from_slice(line);
            break;
        }
        frame.extend_from_slice(chunk);
    }
    Ok(frame)
}

fn handle(mut stream: UnixStream, shared: &Shared) -> std::io::Result<()> {
    stream.set_read_timeout(Some(CONNECTION_READ_TIMEOUT))?;
    let peer = getsockopt(&stream, PeerCredentials).map_err(std::io::Error::other)?;
    if !peer_uid_is_authorized(peer.uid(), geteuid().as_raw()) {
        tracing::warn!(peer_uid = peer.uid(), "connection rejected for foreign uid");
        return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
    }
    let peer_pid = peer.pid();
    // Pin the caller before reading the frame. Ancestry is only meaningful if the
    // pid cannot be recycled between now and the /proc walk, and a caller the
    // kernel will not identify is refused rather than treated as trusted.
    let caller = crate::peer::PeerIdentity::from_stream(&stream).map_err(|_| {
        std::io::Error::other("peer identity unavailable; refusing to authorize the connection")
    })?;
    let request = {
        let frame = read_frame(&mut stream)?;
        frame
            .strip_suffix(b"\n")
            .filter(|line| line.len() <= MAX_FRAME_BYTES)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid frame"))
            .and_then(|line| {
                parse_request(line).map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "bad request")
                })
            })
    };
    #[cfg(test)]
    if let Ok(request) = &request {
        tests::delay_register_handler(request);
    }
    let decision = request.map_or_else(
        |_| dispatch::Decision {
            outcome: Outcome::Failed(ErrCode::BadRequest, "invalid request frame"),
            scope_kind: None,
            source: None,
            request_id: None,
        },
        |request| {
            let audit = audit_context(&request, shared);
            let decision = dispatch(request, shared, &caller);
            let source = decision
                .source
                .as_deref()
                .map_or_else(|| "-".to_owned(), sanitize_audit_value);
            tracing::info!(
                key = %audit.key,
                source = %source,
                peer_pid = ?peer_pid,
                caller_pid = ?caller.pid(),
                scope_kind = ?decision.scope_kind,
                untrusted_registered_session = ?audit.untrusted_registered_session,
                registered_root_pid = ?audit.registered_root_pid,
                request_id = ?decision.request_id,
                decision = decision.outcome.decision(),
                released_bytes = ?decision.outcome.released_bytes(),
                "request handled"
            );
            decision
        },
    );
    match decision.outcome {
        Outcome::Ok => stream.write_all(format_response(&Response::Ok).as_bytes()),
        Outcome::Fields(fields) => {
            stream.write_all(format_response(&Response::OkFields(&fields)).as_bytes())
        }
        Outcome::Payload(payload) => {
            stream.write_all(format_response(&Response::OkBytes(payload.len())).as_bytes())?;
            stream.write_all(&payload)
        }
        Outcome::Bytes(value) => {
            stream.write_all(format_response(&Response::OkBytes(value.len())).as_bytes())?;
            stream.write_all(value.as_slice())
        }
        Outcome::Receipt(receipt) => {
            stream.write_all(b"OK\tstatus=authorized receipt=")?;
            stream.write_all(receipt.as_bytes())?;
            stream.write_all(b"\n")
        }
        Outcome::Failed(code, message) => {
            stream.write_all(format_response(&Response::Failed(code, message)).as_bytes())
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum ConnectionLane {
    Main,
    Fast,
    Control,
}

const fn request_lane(request: &Request) -> ConnectionLane {
    match request {
        Request::Get { .. } | Request::RequestGrant { .. } | Request::Authorize { .. } => {
            ConnectionLane::Main
        }
        Request::Hello { .. }
        | Request::Register { .. }
        | Request::Unregister { .. }
        | Request::Grants
        | Request::Redeem { .. } => ConnectionLane::Fast,
        Request::Deny { .. } | Request::Lock => ConnectionLane::Control,
    }
}

fn ready_request_lane(stream: &UnixStream) -> std::io::Result<Option<ConnectionLane>> {
    let mut buffer = Zeroizing::new([0_u8; MAX_FRAME_BYTES + 1]);
    let bytes = match recv(
        stream.as_raw_fd(),
        &mut buffer[..],
        MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_PEEK,
    ) {
        Ok(length) => buffer
            .get(..length)
            .ok_or_else(|| std::io::Error::other("socket peek exceeded buffer"))?,
        Err(Errno::EAGAIN) => return Ok(None),
        Err(error) => return Err(std::io::Error::other(error)),
    };
    let Some(line) = bytes
        .split_inclusive(|byte| *byte == b'\n')
        .next()
        .and_then(|frame| frame.strip_suffix(b"\n"))
    else {
        return Ok(None);
    };
    if line.len() > MAX_FRAME_BYTES {
        return Ok(None);
    }
    let Ok(request) = parse_request(line) else {
        return Ok(None);
    };
    Ok(Some(request_lane(&request)))
}

fn reject_complete_connection(stream: &UnixStream) -> std::io::Result<()> {
    let mut frame = Zeroizing::new([0_u8; MAX_FRAME_BYTES + 1]);
    match recv(stream.as_raw_fd(), &mut frame[..], MsgFlags::MSG_DONTWAIT) {
        Ok(_) | Err(Errno::EAGAIN) => {}
        Err(error) => return Err(std::io::Error::other(error)),
    }
    let bytes_sent = send(
        stream.as_raw_fd(),
        CONNECTION_CAPACITY_RESPONSE,
        MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL,
    )
    .map_err(std::io::Error::other)?;
    if bytes_sent != CONNECTION_CAPACITY_RESPONSE.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::WriteZero,
            "capacity response was only partially sent",
        ));
    }
    Ok(())
}

fn start_connection_workers(
    receiver: mpsc::Receiver<UnixStream>,
    shared: &Shared,
    worker_count: usize,
) {
    let receiver = Arc::new(Mutex::new(receiver));
    for _ in 0..worker_count {
        let client_shared = Arc::clone(shared);
        let client_receiver = Arc::clone(&receiver);
        let _client = thread::spawn(move || {
            loop {
                let result = client_receiver
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .recv();
                let Ok(stream) = result else { return };
                if let Err(error) = handle(stream, &client_shared) {
                    tracing::warn!(%error, "client connection failed");
                }
            }
        });
    }
}

fn serve_listener(listener: &UnixListener, config: Config) -> std::io::Result<()> {
    let shared = Arc::new((Mutex::new(State::new(config)?), Condvar::new()));
    let worker_shared = Arc::clone(&shared);
    let _worker = thread::spawn(move || worker(&worker_shared));
    let (main_sender, main_receiver) = mpsc::sync_channel(CONNECTION_QUEUE_DEPTH);
    start_connection_workers(main_receiver, &shared, CONNECTION_WORKERS);
    let (fast_sender, fast_receiver) = mpsc::sync_channel(FAST_CONNECTION_QUEUE_DEPTH);
    start_connection_workers(fast_receiver, &shared, FAST_CONNECTION_WORKERS);
    let (control_sender, control_receiver) = mpsc::sync_channel(CONTROL_CONNECTION_QUEUE_DEPTH);
    start_connection_workers(control_receiver, &shared, CONTROL_CONNECTION_WORKERS);
    loop {
        let (stream, _) = listener.accept()?;
        match ready_request_lane(&stream) {
            Ok(lane) => {
                let result = match lane {
                    Some(ConnectionLane::Main) | None => main_sender.try_send(stream),
                    Some(ConnectionLane::Fast) => fast_sender.try_send(stream),
                    Some(ConnectionLane::Control) => control_sender.try_send(stream),
                };
                match result {
                    Ok(()) => {}
                    Err(mpsc::TrySendError::Full(stream)) => {
                        if lane.is_some()
                            && let Err(error) = reject_complete_connection(&stream)
                        {
                            tracing::warn!(%error, "connection capacity rejection failed");
                        }
                        tracing::warn!(?lane, "connection rejected at capacity");
                    }
                    Err(mpsc::TrySendError::Disconnected(_)) => {
                        return Err(std::io::Error::other("connection worker pool stopped"));
                    }
                }
            }
            Err(error) => {
                tracing::warn!(%error, "connection request check failed");
            }
        }
    }
}

/// Serve Unix-socket clients until the listener is closed.
pub fn serve(config: Config) -> std::io::Result<()> {
    let listener = listener(&config)?;
    serve_listener(&listener, config)
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsFd;
    use std::path::Path;

    use super::*;
    use crate::grants::{Registration, SessionToken};
    use crate::store::HumanSource;

    static REGISTER_HANDLER_DELAY: Mutex<Option<Duration>> = Mutex::new(None);

    struct RegisterHandlerDelay;

    #[derive(Clone)]
    struct TestLogWriter(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for TestLogWriter {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().write(buffer)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for TestLogWriter {
        type Writer = Self;

        fn make_writer(&'writer self) -> Self::Writer {
            self.clone()
        }
    }

    impl Drop for RegisterHandlerDelay {
        fn drop(&mut self) {
            *REGISTER_HANDLER_DELAY.lock().unwrap() = None;
        }
    }

    fn delay_register_handlers(delay: Duration) -> RegisterHandlerDelay {
        *REGISTER_HANDLER_DELAY.lock().unwrap() = Some(delay);
        RegisterHandlerDelay
    }

    pub(super) fn delay_register_handler(request: &Request) {
        if matches!(request, Request::Register { .. })
            && let Some(delay) = *REGISTER_HANDLER_DELAY.lock().unwrap()
        {
            thread::sleep(delay);
        }
    }

    fn test_config(directory: &Path) -> Config {
        Config {
            socket_path: directory.join("secretsd.sock"),
            human_sources: vec![HumanSource {
                label: "test".to_owned(),
                dir: directory.join("human"),
            }],
            sops_bin: "/bin/false".into(),
            pcsc_socket: None,
            yubikey_probe_argv: Vec::new(),
            yubikey_probe_timeout: Duration::from_secs(2),
            touch_policy: crate::TouchPolicy::Cached,
            max_grant: Duration::from_secs(1),
            cooldown: Duration::from_secs(16),
            request_ttl: Duration::from_secs(1),
            max_pending_per_scope: 1,
        }
    }

    #[test]
    fn authorize_waits_on_main_workers_while_redeem_uses_fast_workers() {
        let authorize = Request::Authorize {
            cap: "browser".to_owned(),
            token_hex: None,
            tty: None,
        };
        let redeem = Request::Redeem {
            receipt_hex: Zeroizing::new("00".repeat(crate::receipts::RECEIPT_LEN)),
            cap: "browser".to_owned(),
        };

        assert!(matches!(request_lane(&authorize), ConnectionLane::Main));
        assert!(matches!(request_lane(&redeem), ConnectionLane::Fast));
    }

    #[test]
    fn rejects_a_non_socket_activation_fd() {
        let file = tempfile::tempfile().unwrap();

        assert!(validate_activated_listener(file.as_fd()).is_err());
    }

    #[test]
    fn rejects_a_peer_uid_that_is_not_the_daemon_uid() {
        assert!(!peer_uid_is_authorized(1000, 1001));
    }

    #[test]
    fn instance_id_is_lowercase_hex_so_it_cannot_forge_a_handshake_field() {
        // The handshake reports this in a space-separated field. It is the only
        // non-literal value the daemon puts there, so its alphabet is what keeps
        // a client from reading an extra field.
        let id = random_instance_id().unwrap();

        assert_eq!(id.len(), 32, "instance id changed length: {id}");
        assert!(
            id.chars()
                .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character)),
            "instance id is not lowercase hex: {id}"
        );
        assert_ne!(
            random_instance_id().unwrap(),
            id,
            "instance id is not random"
        );
    }

    #[test]
    fn serves_lock_when_slow_connections_exceed_admission_capacity() {
        // Given a listening socket and more newline-less clients than admission permits.
        let directory = tempfile::tempdir().unwrap();
        let config = test_config(directory.path());
        let socket_path = config.socket_path.clone();
        let server_listener = listener(&config).unwrap();
        let _server = thread::spawn(move || serve_listener(&server_listener, config).unwrap());
        let mut slow_connections = (0..=CONNECTION_CAPACITY)
            .map(|_| UnixStream::connect(&socket_path))
            .collect::<std::io::Result<Vec<_>>>()
            .unwrap();
        // When the final slow connection reaches the daemon.
        let rejected = slow_connections.iter_mut().any(|connection| {
            connection
                .set_read_timeout(Some(Duration::from_millis(1)))
                .unwrap();
            let mut byte = [0_u8; 1];
            match connection.read(&mut byte) {
                Ok(0) => true,
                Ok(length) => panic!("slow connection returned {length} bytes"),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                    ) =>
                {
                    false
                }
                Err(error) => panic!("slow connection read failed: {error}"),
            }
        });

        // Then it is closed promptly and a complete LOCK request remains serviceable.
        assert!(rejected);
        let mut control = UnixStream::connect(socket_path).unwrap();
        control
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        control.write_all(b"LOCK\n").unwrap();
        let mut response = String::new();
        control.read_to_string(&mut response).unwrap();
        assert_eq!(response, "OK\n");
    }

    #[test]
    fn serves_lock_when_complete_immediate_connections_flood_the_backlog() {
        // Given a listening socket with complete, expensive immediate requests ahead of LOCK.
        let directory = tempfile::tempdir().unwrap();
        let config = test_config(directory.path());
        let socket_path = config.socket_path.clone();
        let server_listener = listener(&config).unwrap();
        let session_prefix = "f".repeat(3_996);
        let _register_handler_delay = delay_register_handlers(Duration::from_millis(5));
        let mut flood_connections = Vec::new();
        for index in 0..96 {
            let mut connection = UnixStream::connect(&socket_path).unwrap();
            let frame = format!(
                "REGISTER\ttoken={index:064x}\tsession={session_prefix}{index:04x}\tpid=1\n"
            );
            connection.write_all(frame.as_bytes()).unwrap();
            flood_connections.push(connection);
        }
        let mut control = UnixStream::connect(&socket_path).unwrap();
        control.write_all(b"LOCK\n").unwrap();
        let _server = thread::spawn(move || serve_listener(&server_listener, config).unwrap());

        // When the daemon starts draining its backlog.
        control
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let mut response = String::new();
        let result = control.read_to_string(&mut response);

        // Then LOCK is served before complete immediate requests can monopolize acceptance.
        assert!(result.is_ok(), "LOCK was not served promptly: {result:?}");
        assert_eq!(response, "OK\n");
        let mut rejected = flood_connections.pop().unwrap();
        rejected
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let mut rejection = String::new();
        rejected.read_to_string(&mut rejection).unwrap();
        assert_eq!(rejection, "ERR\tINTERNAL\tconnection capacity reached\n");
    }

    #[test]
    fn audit_value_escapes_controls_and_caps_untrusted_metadata() {
        // Given untrusted metadata containing every frame-corrupting control class.
        let input = "safe\rline\nwith\ttab\0and\u{001b}escape";

        // When it is rendered for the audit log.
        let rendered = sanitize_audit_value(input);

        // Then controls are visible escapes, not bytes emitted to journald.
        assert_eq!(rendered, "safe\\rline\\nwith\\ttab\\0and\\u{001B}escape");
        let capped = sanitize_audit_value(&"x".repeat(MAX_AUDIT_VALUE_BYTES + 1));
        assert!(capped.len() <= MAX_AUDIT_VALUE_BYTES);
        assert!(capped.ends_with('…'));
    }

    #[test]
    fn audit_log_records_registered_untrusted_metadata_and_queue_request_id() {
        // Given a registered session and a human-tier key that needs a grant.
        let directory = tempfile::tempdir().unwrap();
        let human_dir = directory.path().join("human");
        std::fs::create_dir(&human_dir).unwrap();
        std::fs::write(human_dir.join("DEEL_API_KEY.env"), b"ciphertext").unwrap();
        let mut config = test_config(directory.path());
        config.human_sources = vec![HumanSource {
            label: "test".to_owned(),
            dir: human_dir,
        }];
        let shared = Arc::new((Mutex::new(State::new(config).unwrap()), Condvar::new()));
        let token_hex = "ab".repeat(32);
        let token = SessionToken::parse_hex(&token_hex).unwrap();
        lock_state(&shared.0)
            .registry
            .register(Registration {
                token,
                session: "opencode-session".to_owned(),
                root: crate::peer::PeerIdentity::current_for_test(),
            })
            .unwrap();
        let worker_shared = Arc::clone(&shared);
        let _worker = thread::spawn(move || worker(&worker_shared));
        let (mut client, server) = UnixStream::pair().unwrap();
        client
            .write_all(format!("REQUEST\tkey=DEEL_API_KEY\ttoken={token_hex}\n").as_bytes())
            .unwrap();
        let logs = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_target(false)
            .with_writer(TestLogWriter(Arc::clone(&logs)))
            .finish();

        // When the daemon handles the request.
        tracing::subscriber::with_default(subscriber, || handle(server, &shared).unwrap());

        // Then the audit event identifies the request without disclosing its token.
        let output = String::from_utf8(logs.lock().unwrap().clone()).unwrap();
        assert!(output.contains("key=DEEL_API_KEY"));
        assert!(output.contains("scope_kind=Some(VerifiedSession)"));
        assert!(output.contains("peer_pid="));
        assert!(output.contains("untrusted_registered_session=Some(\"opencode-session\")"));
        // The registered pid now comes from the kernel, so it is this test
        // process rather than a value supplied over the wire.
        assert!(output.contains(&format!("caller_pid=Some({})", std::process::id())));
        assert!(
            !output.contains("caller_pid=Some(12345)"),
            "the audit trusted a pid supplied over the wire"
        );
        assert!(output.contains("request_id=Some(RequestId(1))"));
        assert!(output.contains("decision="));
        assert!(!output.contains(&token_hex));
    }

    #[test]
    fn audit_context_never_enqueues_a_valid_key() {
        // Given a source containing the requested key and a registered session.
        let directory = tempfile::tempdir().unwrap();
        let human_dir = directory.path().join("human");
        std::fs::create_dir(&human_dir).unwrap();
        std::fs::write(human_dir.join("DEEL_API_KEY.env"), b"ciphertext").unwrap();
        let mut config = test_config(directory.path());
        config.human_sources = vec![HumanSource {
            label: "test".to_owned(),
            dir: human_dir,
        }];
        let shared = Arc::new((Mutex::new(State::new(config).unwrap()), Condvar::new()));
        let token_hex = "ef".repeat(32);
        let token = SessionToken::parse_hex(&token_hex).unwrap();
        lock_state(&shared.0)
            .registry
            .register(Registration {
                token,
                session: "opencode-session".to_owned(),
                root: crate::peer::PeerIdentity::current_for_test(),
            })
            .unwrap();
        let request = Request::Get {
            key: "DEEL_API_KEY".to_owned(),
            token_hex: Some(Zeroizing::new(token_hex)),
            tty: None,
        };

        // When audit metadata is collected for the request.
        let _audit = audit_context(&request, &shared);

        // Then audit metadata collection leaves the approval queue untouched.
        assert!(
            lock_state(&shared.0)
                .queue
                .next_ready(Instant::now())
                .is_none()
        );
    }

    #[test]
    fn audit_log_escapes_control_bytes_from_a_frame_key() {
        // Given a frame with a control-byte key and a verified session token.
        let directory = tempfile::tempdir().unwrap();
        let shared = Arc::new((
            Mutex::new(State::new(test_config(directory.path())).unwrap()),
            Condvar::new(),
        ));
        let token_hex = "cd".repeat(32);
        let token = SessionToken::parse_hex(&token_hex).unwrap();
        lock_state(&shared.0)
            .registry
            .register(Registration {
                token,
                session: "opencode-session".to_owned(),
                root: crate::peer::PeerIdentity::current_for_test(),
            })
            .unwrap();
        let (mut client, server) = UnixStream::pair().unwrap();
        let key = format!("KEY\rINJECT\0{}", "X".repeat(MAX_AUDIT_VALUE_BYTES + 1));
        client
            .write_all(format!("GET\tkey={key}\ttoken={token_hex}\n").as_bytes())
            .unwrap();
        let logs = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_target(false)
            .with_writer(TestLogWriter(Arc::clone(&logs)))
            .finish();

        // When the daemon logs the rejected request.
        tracing::subscriber::with_default(subscriber, || handle(server, &shared).unwrap());

        // Then the audit value exposes escapes instead of emitting control bytes.
        let output = logs.lock().unwrap().clone();
        assert!(String::from_utf8_lossy(&output).contains(r"key=KEY\rINJECT\0"));
        assert!(String::from_utf8_lossy(&output).contains('…'));
        assert!(!output.contains(&b'\r'));
        assert!(!output.contains(&b'\0'));
    }
}
