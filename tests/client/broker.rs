use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use tempfile::TempDir;

pub(super) enum Reply {
    Hello,
    Ok,
    Bytes(Vec<u8>),
    Raw(Vec<u8>),
    DelayedRaw(Duration, Vec<u8>),
}

pub(super) struct FakeBroker {
    _directory: TempDir,
    socket: PathBuf,
    frames: Arc<Mutex<Vec<String>>>,
    expected_token_seen: Arc<Mutex<Option<bool>>>,
    stop: Arc<AtomicBool>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl FakeBroker {
    pub(super) fn script(replies: impl IntoIterator<Item = Reply>) -> Self {
        Self::script_with_expected_token(replies, None)
    }

    pub(super) fn script_with_token(
        replies: impl IntoIterator<Item = Reply>,
        token: String,
    ) -> Self {
        Self::script_with_expected_token(replies, Some(token))
    }

    fn script_with_expected_token(
        replies: impl IntoIterator<Item = Reply>,
        expected_token: Option<String>,
    ) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("broker.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let frames = Arc::new(Mutex::new(Vec::new()));
        let expected_token_seen = Arc::new(Mutex::new(None));
        let stop = Arc::new(AtomicBool::new(false));
        let worker_frames = Arc::clone(&frames);
        let worker_token_seen = Arc::clone(&expected_token_seen);
        let worker_stop = Arc::clone(&stop);
        let replies = replies.into_iter().collect::<Vec<_>>();
        listener.set_nonblocking(true).unwrap();
        let worker = thread::spawn(move || {
            for reply in replies {
                let stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            if worker_stop.load(Ordering::Relaxed) {
                                return;
                            }
                            thread::sleep(Duration::from_millis(1));
                        }
                        Err(_) => return,
                    }
                };
                record_frame(
                    stream,
                    &worker_frames,
                    &worker_token_seen,
                    expected_token.as_deref(),
                    reply,
                );
            }
        });
        Self {
            _directory: directory,
            socket,
            frames,
            expected_token_seen,
            stop,
            worker: Mutex::new(Some(worker)),
        }
    }

    pub(super) fn socket(&self) -> &Path {
        &self.socket
    }

    pub(super) fn frames(&self) -> Vec<String> {
        self.join();
        self.frames.lock().unwrap().clone()
    }

    pub(super) fn saw_expected_token(&self) -> bool {
        self.join();
        self.expected_token_seen.lock().unwrap().unwrap_or(false)
    }

    fn join(&self) {
        let worker = self.worker.lock().unwrap().take();
        if let Some(worker) = worker {
            worker.join().unwrap();
        }
    }
}

impl Drop for FakeBroker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.join();
    }
}

fn record_frame(
    stream: UnixStream,
    frames: &Arc<Mutex<Vec<String>>>,
    expected_token_seen: &Arc<Mutex<Option<bool>>>,
    expected_token: Option<&str>,
    reply: Reply,
) {
    let mut reader = BufReader::new(stream);
    let mut frame = String::new();
    reader.read_line(&mut frame).unwrap();
    let frame = frame.strip_suffix('\n').unwrap().to_owned();
    if let Some(expected_token) = expected_token {
        let received_token = frame
            .split('\t')
            .find_map(|field| field.strip_prefix("token="));
        *expected_token_seen.lock().unwrap() = Some(received_token == Some(expected_token));
    }
    frames.lock().unwrap().push(redact_token(&frame));

    let mut stream = reader.into_inner();
    match reply {
        Reply::Hello => stream.write_all(b"OK\tversion=1\n").unwrap(),
        Reply::Ok => stream.write_all(b"OK\n").unwrap(),
        Reply::Bytes(bytes) => {
            let header = format!("OK\tlen={}\n", bytes.len());
            stream.write_all(header.as_bytes()).unwrap();
            stream.write_all(&bytes).unwrap();
        }
        Reply::Raw(bytes) => stream.write_all(&bytes).unwrap(),
        Reply::DelayedRaw(delay, bytes) => {
            thread::sleep(delay);
            stream.write_all(&bytes).unwrap();
        }
    }
}

fn redact_token(frame: &str) -> String {
    frame
        .split('\t')
        .map(|field| {
            if field.starts_with("token=") {
                "token=<redacted>"
            } else {
                field
            }
        })
        .collect::<Vec<_>>()
        .join("\t")
}
