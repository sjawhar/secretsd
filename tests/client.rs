#![allow(
    clippy::redundant_pub_crate,
    clippy::unwrap_used,
    missing_docs,
    reason = "integration tests use concise setup and assertion helpers"
)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::thread;

use secretsd::client::{BrokerClient, BrokerResponse, ClientError, SocketPath, parse_response};
use secretsd::proto::PROTOCOL_VERSION;

#[path = "client/broker.rs"]
mod fake_broker;
use fake_broker::{FakeBroker, Reply};
include!("client/fixture.rs");
#[path = "client/broker_transport.rs"]
mod broker_transport;
#[path = "client/edit.rs"]
mod edit;
#[path = "client/edit_human.rs"]
mod edit_human;
#[path = "client/multi_source.rs"]
mod multi_source;
#[path = "client/sources.rs"]
mod sources;

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
        SocketPath::resolve(None, Some(""), 42).as_path(),
        "/run/user/42/secretsd.sock"
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
        assert_eq!(hello, format!("HELLO\tversion={PROTOCOL_VERSION}\n"));
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
        assert_eq!(hello, format!("HELLO\tversion={PROTOCOL_VERSION}\n"));
        let mut stream = reader.into_inner();
        stream
            .write_all(format!("OK\tversion={PROTOCOL_VERSION}\n").as_bytes())
            .unwrap();
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

#[test]
fn agent_get_works_with_a_minimal_noninteractive_environment() {
    let fixture = Fixture::agent("AGENT_ONLY=agent-value\n");

    let output = fixture.run_minimal(["get", "--value", "AGENT_ONLY"]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"agent-value\n");
    assert!(
        fixture
            .sops_arguments()
            .windows(b"--input-type\0dotenv\0--output-type\0dotenv\0".len())
            .any(|window| window == b"--input-type\0dotenv\0--output-type\0dotenv\0")
    );
    assert!(!fixture.sops_log().contains("secretsd.sock"));
}

#[test]
fn agent_get_uses_the_optional_local_overlay_before_the_shared_file() {
    let fixture = Fixture::agent("KEY=shared-value\n");
    fixture.write_local("KEY=local-value\n");

    let output = fixture.run_minimal(["get", "KEY", "--value"]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"local-value\n");
}

#[test]
fn agent_get_succeeds_when_the_optional_local_overlay_is_missing() {
    let fixture = Fixture::agent("AGENT_ONLY=agent-value\n");

    let output = fixture.run_minimal(["get", "AGENT_ONLY", "--value"]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"agent-value\n");
}

#[test]
fn bare_agent_get_reports_status_without_decrypting_or_printing_the_value() {
    let fixture = Fixture::agent("AGENT_ONLY=agent-value\n");

    let output = fixture.run_minimal(["get", "AGENT_ONLY"]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        output.stdout,
        br#"{"key":"AGENT_ONLY","tier":"agent"}
"#
    );
    assert!(
        !output
            .stdout
            .windows(b"agent-value".len())
            .any(|bytes| bytes == b"agent-value")
    );
    assert_eq!(fixture.sops_calls(), 0);
    // Status output is machine-readable and complete on stdout; nothing else is
    // emitted, so callers piping it get JSON and only JSON.
    assert_eq!(output.stderr, b"");
}

#[test]
fn get_rejects_missing_extra_and_unknown_arguments() {
    let fixture = Fixture::agent("AGENT_ONLY=agent-value\n");

    for arguments in [
        ["get"].as_slice(),
        ["get", "AGENT_ONLY", "ANOTHER"].as_slice(),
        ["get", "AGENT_ONLY", "--unknown"].as_slice(),
        ["get", "--value"].as_slice(),
    ] {
        let output = fixture.run_minimal(arguments);

        assert_ne!(output.status.code(), Some(0));
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("usage: secrets get KEY [--value|--no-request]")
        );
    }
    assert_eq!(fixture.sops_calls(), 0);
}

#[test]
fn duplicate_agent_and_human_name_fails_closed_before_output() {
    let fixture = Fixture::agent("DUP=agent-value\n");
    fixture.write_human_name("DUP");

    for arguments in [
        ["get", "DUP"].as_slice(),
        ["list"].as_slice(),
        ["DUP", "--", "true"].as_slice(),
    ] {
        let output = fixture.run_minimal(arguments);

        assert_ne!(output.status.code(), Some(0));
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("exists in both agent and human tiers")
        );
    }
}

#[test]
fn get_rejects_path_traversal_before_constructing_a_path() {
    let fixture = Fixture::agent("AGENT_ONLY=agent-value\n");

    let output = fixture.run_minimal(["get", "../AGENT_ONLY"]);

    assert_ne!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid secret key"));
    assert_eq!(fixture.sops_calls(), 0);
    assert!(!fixture.dotfiles_dir().join("AGENT_ONLY.env").exists());
}

#[test]
fn inject_form_sets_values_only_in_the_child_environment() {
    let fixture = Fixture::agent("A=one\nB=two\n");

    let output = fixture.run_minimal(["A", "B", "--", "sh", "-c", "printf '%s:%s' \"$A\" \"$B\""]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"one:two");
}
