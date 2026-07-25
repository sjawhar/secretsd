#![allow(
    clippy::unwrap_used,
    missing_docs,
    reason = "integration tests use concise setup and assertion helpers"
)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::thread;

use secretsd::client::{BrokerClient, BrokerResponse, ClientError, SocketPath, parse_response};

#[test]
fn exact_payload_accepts_declared_non_nul_bytes() {
    assert_eq!(
        parse_response(b"OK\tlen=3\nabc"),
        Ok(BrokerResponse::Bytes(b"abc".to_vec()))
    );
}

#[test]
fn framed_payload_rejects_short_long_and_nul_bytes() {
    for bytes in [
        b"OK\tlen=4\nabc".as_slice(),
        b"OK\tlen=3\nabcx",
        b"OK\tlen=3\na\0b",
    ] {
        assert!(matches!(
            parse_response(bytes),
            Err(ClientError::InvalidResponse)
        ));
    }
}

#[test]
fn socket_path_is_lazy_and_has_the_documented_fallback() {
    assert_eq!(
        SocketPath::resolve(Some("/tmp/override"), Some("/tmp/runtime"), 42).as_path(),
        "/tmp/override"
    );
    assert_eq!(
        SocketPath::resolve(None, Some("/tmp/runtime"), 42).as_path(),
        "/tmp/runtime/secretsd.sock"
    );
    assert_eq!(
        SocketPath::resolve(None, None, 42).as_path(),
        "/run/user/42/secretsd.sock"
    );
}

#[test]
fn client_rejects_wrong_hello_field_name() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("broker.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let worker = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream);
        let mut hello = String::new();
        reader.read_line(&mut hello).unwrap();
        assert_eq!(hello, "HELLO\tversion=1\n");
        let mut stream = reader.into_inner();
        stream.write_all(b"OK\tv=1\n").unwrap();
    });
    let result = BrokerClient::new(path).hello();
    worker.join().unwrap();
    assert_eq!(result, Err(ClientError::VersionHandshake));
}

#[test]
fn client_handshakes_before_sending_a_request() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("broker.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let worker = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream);
        let mut hello = String::new();
        reader.read_line(&mut hello).unwrap();
        assert_eq!(hello, "HELLO\tversion=1\n");
        let mut stream = reader.into_inner();
        stream.write_all(b"OK\tversion=1\n").unwrap();
        drop(stream);

        let (stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream);
        let mut request = String::new();
        reader.read_line(&mut request).unwrap();
        assert_eq!(request, "GRANTS\n");
        let mut stream = reader.into_inner();
        stream.write_all(b"OK\tlen=3\nabc").unwrap();
    });

    let result = BrokerClient::new(path).call("GRANTS");
    worker.join().unwrap();

    assert_eq!(result, Ok(BrokerResponse::Bytes(b"abc".to_vec())));
}
