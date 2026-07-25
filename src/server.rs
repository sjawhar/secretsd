//! Unix-socket server coordination.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, mpsc};
use std::thread;
use std::time::Duration;

use nix::errno::Errno;
use nix::sys::signal::{Signal, killpg};
use nix::sys::socket::sockopt::{AcceptConn, PeerCredentials, SockType as SocketType};
use nix::sys::socket::{MsgFlags, SockType, UnixAddr, getsockname, getsockopt, recv, send};
use nix::sys::stat::{SFlag, fstat};
use nix::unistd::{Pid, geteuid};

use crate::Config;
use crate::decrypt::Decryptor;
use crate::grants::{GrantTable, Registry};
use crate::proto::{ErrCode, MAX_FRAME_BYTES, Request, Response, format_response, parse_request};
use crate::requests::{Queue, QueueLimits, RequestId};
use crate::store::HumanStore;

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
    registry: Registry,
    grants: GrantTable,
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
        Ok(Self {
            registry: Registry::new(boot_id),
            grants: GrantTable::default(),
            queue: Queue::new(QueueLimits {
                cooldown: config.cooldown,
                ttl: config.request_ttl,
                max_pending_per_scope: config.max_pending_per_scope,
            }),
            store: HumanStore::new(config.human_dir.clone()),
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

fn handle(stream: UnixStream, shared: &Shared) -> std::io::Result<()> {
    stream.set_read_timeout(Some(CONNECTION_READ_TIMEOUT))?;
    let peer = getsockopt(&stream, PeerCredentials).map_err(std::io::Error::other)?;
    if !peer_uid_is_authorized(peer.uid(), geteuid().as_raw()) {
        tracing::warn!(peer_uid = peer.uid(), "connection rejected for foreign uid");
        return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
    }
    let peer_pid = Some(peer.pid());
    let mut reader = BufReader::new(stream);
    let mut frame = Vec::new();
    {
        let mut bounded = reader.by_ref().take((MAX_FRAME_BYTES + 1) as u64);
        bounded.read_until(b'\n', &mut frame)?;
    }
    let mut stream = reader.into_inner();
    let request = frame
        .strip_suffix(b"\n")
        .filter(|line| line.len() <= MAX_FRAME_BYTES)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid frame"));
    let request = request.and_then(|line| {
        parse_request(line)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad request"))
    });
    #[cfg(test)]
    if let Ok(request) = &request {
        tests::delay_register_handler(request);
    }
    let decision = request.map_or_else(
            |_| dispatch::Decision {
                outcome: Outcome::Failed(ErrCode::BadRequest, "invalid request frame"),
                scope_kind: None,
            },
            |request| {
                let key = request_key(&request).unwrap_or("-").to_owned();
                let decision = dispatch(request, shared);
                tracing::info!(%key, ?peer_pid, ?decision.scope_kind, decision = decision.outcome.decision(), "request handled");
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
        Request::Get { .. } | Request::RequestGrant { .. } => ConnectionLane::Main,
        Request::Hello { .. }
        | Request::Register { .. }
        | Request::Unregister { .. }
        | Request::Grants => ConnectionLane::Fast,
        Request::Deny { .. } | Request::Lock => ConnectionLane::Control,
    }
}

fn ready_request_lane(stream: &UnixStream) -> std::io::Result<Option<ConnectionLane>> {
    let mut buffer = [0_u8; MAX_FRAME_BYTES + 1];
    let bytes = match recv(
        stream.as_raw_fd(),
        &mut buffer,
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
    let mut frame = [0_u8; MAX_FRAME_BYTES + 1];
    match recv(stream.as_raw_fd(), &mut frame, MsgFlags::MSG_DONTWAIT) {
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

    static REGISTER_HANDLER_DELAY: Mutex<Option<Duration>> = Mutex::new(None);

    struct RegisterHandlerDelay;

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
            human_dir: directory.join("human"),
            sops_bin: "/bin/false".into(),
            pcsc_socket: None,
            yubikey_probe_argv: Vec::new(),
            max_grant: Duration::from_secs(1),
            cooldown: Duration::from_secs(16),
            request_ttl: Duration::from_secs(1),
            max_pending_per_scope: 1,
        }
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
}
