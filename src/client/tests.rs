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
fn broker_operations_return_timeout_when_the_broker_accepts_without_replying() {
    // Given a broker that completes HELLO and stalls each operation connection.
    for operation in [
        "GET\tkey=HUMAN",
        "REGISTER\ttoken=token\tsession=session\tpid=1",
        "UNREGISTER\tsession=session",
        "GRANTS",
        "DENY\tid=1",
        "LOCK",
    ] {
        let broker = StallingBroker::new();
        let client = BrokerClient::with_test_timeouts(
            broker.socket(),
            Duration::from_millis(100),
            Duration::from_millis(100),
        );

        // When the client issues an operation whose reply never arrives.
        let result = client.call(operation);

        // Then the operation returns the socket read timeout instead of hanging.
        assert!(matches!(
            result,
            Err(ClientError::Io(error))
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                )
        ));
    }
}
