use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use super::{BrokerClient, ClientError};

struct StallingBroker {
    _directory: tempfile::TempDir,
    socket: PathBuf,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl StallingBroker {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("broker.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        listener.set_nonblocking(true).unwrap();
        let worker = thread::spawn(move || {
            let Some(hello) = accept(&listener, &worker_stop) else {
                return;
            };
            let mut hello = BufReader::new(hello);
            let mut request = String::new();
            hello.read_line(&mut request).unwrap();
            hello.get_mut().write_all(b"OK\tversion=2\n").unwrap();
            drop(hello);

            let Some(request) = accept(&listener, &worker_stop) else {
                return;
            };
            let mut request = BufReader::new(request);
            let mut frame = String::new();
            request.read_line(&mut frame).unwrap();
            while !worker_stop.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_millis(1));
            }
        });
        Self {
            _directory: directory,
            socket,
            stop,
            worker: Some(worker),
        }
    }

    fn socket(&self) -> &Path {
        &self.socket
    }
}

impl Drop for StallingBroker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            worker.join().unwrap();
        }
    }
}

fn accept(listener: &UnixListener, stop: &AtomicBool) -> Option<UnixStream> {
    loop {
        match listener.accept() {
            Ok((stream, _)) => return Some(stream),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if stop.load(Ordering::Relaxed) {
                    return None;
                }
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("failed to accept test broker connection: {error}"),
        }
    }
}

#[test]
#[cfg_attr(miri, ignore)]
fn broker_operations_report_the_correct_timeout_when_the_broker_accepts_without_replying() {
    // Given a broker that completes HELLO and stalls each operation connection.
    for (operation, waits_for_approval) in [
        ("GET\tkey=HUMAN", true),
        ("REGISTER\ttoken=token\tsession=session\tpid=1", false),
        ("UNREGISTER\tsession=session", false),
        ("GRANTS", false),
        ("DENY\tid=1", false),
        ("LOCK", false),
    ] {
        let broker = StallingBroker::new();
        let client = BrokerClient::with_test_timeouts(
            broker.socket(),
            Duration::from_millis(100),
            Duration::from_millis(100),
        );

        // When the client issues an operation whose reply never arrives.
        let result = client.call(operation);

        // Then approval waits and control operations report their distinct timeout conditions.
        match (waits_for_approval, result) {
            (true, Err(ClientError::ApprovalTimeout)) => {}
            (false, Err(ClientError::Io(error)))
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) => {}
            (_, unexpected) => panic!("unexpected timeout result: {unexpected:?}"),
        }
    }
}

#[test]
#[cfg_attr(miri, ignore)]
fn request_frames_use_the_approval_timeout() {
    // Given a broker that answers REQUEST after the control timeout has elapsed.
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("broker.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let worker = thread::spawn(move || {
        let (hello, _) = listener.accept().unwrap();
        let mut hello = BufReader::new(hello);
        let mut hello_frame = String::new();
        hello.read_line(&mut hello_frame).unwrap();
        hello.get_mut().write_all(b"OK\tversion=2\n").unwrap();
        drop(hello);

        let (request, _) = listener.accept().unwrap();
        let mut request = BufReader::new(request);
        let mut request_frame = String::new();
        request.read_line(&mut request_frame).unwrap();
        thread::sleep(Duration::from_millis(300));
        request.get_mut().write_all(b"OK\n").unwrap();
    });
    let client = BrokerClient::with_test_timeouts(
        &socket,
        Duration::from_secs(5),
        Duration::from_millis(100),
    );

    // When the client issues a request that waits for approval.
    let result = client.call("REQUEST\tkey=DEEL_API_KEY\ttty=/dev/pts/9");

    // Then it uses the approval timeout rather than the control timeout.
    assert!(
        result.is_ok(),
        "REQUEST should outlive the control timeout: {result:?}"
    );
    worker.join().unwrap();
}

#[test]
#[cfg_attr(miri, ignore)]
fn approval_timeout_is_reported_truthfully() {
    // Given a broker that accepts REQUEST but never replies.
    let broker = StallingBroker::new();
    let client = BrokerClient::with_test_timeouts(
        broker.socket(),
        Duration::from_millis(200),
        Duration::from_millis(100),
    );

    // When the approval wait exceeds the client timeout.
    let error = client
        .call("REQUEST\tkey=DEEL_API_KEY\ttty=/dev/pts/9")
        .unwrap_err();

    // Then it reports the approval wait rather than a transport failure.
    assert!(
        matches!(&error, ClientError::ApprovalTimeout),
        "expected an approval timeout, got {error:?}"
    );
    assert!(error.to_string().contains("timed out waiting for approval"));
}

#[test]
#[cfg_attr(miri, ignore)]
fn control_operations_keep_the_short_timeout() {
    // Given a broker that delays a GRANTS reply beyond the control timeout.
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("broker.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let worker = thread::spawn(move || {
        let (hello, _) = listener.accept().unwrap();
        let mut hello = BufReader::new(hello);
        let mut hello_frame = String::new();
        hello.read_line(&mut hello_frame).unwrap();
        hello.get_mut().write_all(b"OK\tversion=2\n").unwrap();
        drop(hello);

        let (request, _) = listener.accept().unwrap();
        let mut request = BufReader::new(request);
        let mut request_frame = String::new();
        request.read_line(&mut request_frame).unwrap();
        thread::sleep(Duration::from_millis(300));
    });
    let client = BrokerClient::with_test_timeouts(
        &socket,
        Duration::from_secs(5),
        Duration::from_millis(100),
    );

    // When the client issues a control operation.
    let result = client.call("GRANTS");

    // Then it still uses the short control timeout.
    assert!(matches!(
        result,
        Err(ClientError::Io(error))
            if matches!(
                error.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            )
    ));
    worker.join().unwrap();
}
