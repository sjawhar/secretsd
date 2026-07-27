use std::time::{Duration, Instant};

use secretsd::client::{
    BrokerClient, BrokerResponse, CliError, ClientError, HumanClient, read_token_file,
};
use secretsd::proto::ErrCode;
use secretsd::secret::SecretName;

use super::{FakeBroker, Fixture, Reply};

#[test]
fn broker_client_reads_an_exact_length_payload_from_a_fake_socket() {
    let broker = FakeBroker::script([Reply::Hello, Reply::Bytes(b"abc".to_vec())]);

    let result = BrokerClient::new(broker.socket()).call("GRANTS");

    assert_eq!(result, Ok(BrokerResponse::Bytes(b"abc".to_vec())));
    assert_eq!(broker.frames(), ["HELLO\tversion=2", "GRANTS"]);
}

#[test]
fn broker_client_rejects_short_trailing_and_nul_payloads_from_a_fake_socket() {
    for reply in [
        Reply::Raw(b"OK\tlen=4\nabc".to_vec()),
        Reply::Raw(b"OK\tlen=3\nabcx".to_vec()),
        Reply::Raw(b"OK\tlen=3\na\0b".to_vec()),
    ] {
        let broker = FakeBroker::script([Reply::Hello, reply]);

        let result = BrokerClient::new(broker.socket()).call("GRANTS");

        assert_eq!(result, Err(ClientError::InvalidResponse));
        assert_eq!(broker.frames(), ["HELLO\tversion=2", "GRANTS"]);
    }
}

#[test]
fn broker_client_waits_for_a_blocking_human_get_response() {
    let broker = FakeBroker::script([
        Reply::Hello,
        Reply::DelayedRaw(Duration::from_secs(3), b"OK\tlen=3\nabc".to_vec()),
    ]);
    let started = Instant::now();

    let result = BrokerClient::new(broker.socket()).call("GET\tkey=HUMAN");

    assert_eq!(result, Ok(BrokerResponse::Bytes(b"abc".to_vec())));
    assert!(started.elapsed() >= Duration::from_secs(3));
}

#[test]
fn human_get_sends_the_callers_tty_once_without_a_software_gate() {
    let broker = FakeBroker::script([Reply::Hello, Reply::Bytes(b"human-value".to_vec())]);
    let key = SecretName::parse("HUMAN").unwrap();
    let client = HumanClient::new(
        BrokerClient::new(broker.socket()),
        None,
        Some("/dev/pts/test".to_owned()),
    );

    let result = client.get(&key);

    assert_eq!(result.unwrap().as_slice(), b"human-value");
    assert_eq!(
        broker.frames(),
        ["HELLO\tversion=2", "GET\tkey=HUMAN\ttty=/dev/pts/test"]
    );
}

#[test]
fn human_get_reads_the_token_from_its_file_not_the_environment() {
    let token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let broker = FakeBroker::script_with_token(
        [Reply::Hello, Reply::Bytes(b"human-value".to_vec())],
        token.to_owned(),
    );
    let fixture = Fixture::human("HUMAN");
    let token_file = fixture.write_token(token);

    let output = fixture.run_broker(
        ["get", "HUMAN", "--value"],
        broker.socket(),
        Some(&token_file),
        Some("environment-token-must-not-be-used"),
    );

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"human-value\n");
    assert!(broker.saw_expected_token());
    assert_eq!(
        broker.frames(),
        ["HELLO\tversion=2", "GET\tkey=HUMAN\ttoken=<redacted>"]
    );
}

#[test]
fn human_get_routes_to_the_broker_when_the_agent_tier_is_absent() {
    let broker = FakeBroker::script([Reply::Hello, Reply::Bytes(b"human-value".to_vec())]);
    let fixture = Fixture::human("HUMAN");
    std::fs::remove_file(fixture.dotfiles_dir().join("secrets.env")).unwrap();

    let output = fixture.run_broker(["get", "HUMAN", "--value"], broker.socket(), None, None);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"human-value\n");
    assert_eq!(fixture.sops_calls(), 0);
    assert_eq!(broker.frames(), ["HELLO\tversion=2", "GET\tkey=HUMAN"]);
}

#[test]
fn get_with_no_request_lists_grants_without_sending_get() {
    let broker = FakeBroker::script([Reply::Hello, Reply::Bytes(b"no active grants\n".to_vec())]);
    let fixture = Fixture::human("HUMAN");

    let output = fixture.run_broker(
        ["get", "HUMAN", "--no-request"],
        broker.socket(),
        None,
        None,
    );

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        output.stdout,
        b"{\"key\":\"HUMAN\",\"tier\":\"human\",\"grant\":false}\n"
    );
    assert_eq!(fixture.sops_calls(), 0);
    assert_eq!(broker.frames(), ["HELLO\tversion=2", "GRANTS"]);
}

#[test]
fn get_with_no_request_reports_an_active_session_grant() {
    let token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let broker = FakeBroker::script([
        Reply::Hello,
        Reply::Bytes(b"KEY\tSCOPE\tAGE\nHUMAN\tsession\t0s\n".to_vec()),
    ]);
    let fixture = Fixture::human("HUMAN");
    let token_file = fixture.write_token(token);

    let output = fixture.run_broker(
        ["get", "HUMAN", "--no-request"],
        broker.socket(),
        Some(&token_file),
        None,
    );

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        output.stdout,
        b"{\"key\":\"HUMAN\",\"tier\":\"human\",\"grant\":true}\n"
    );
    assert_eq!(broker.frames(), ["HELLO\tversion=2", "GRANTS"]);
}

#[test]
fn token_file_rejects_empty_non_utf8_and_whitespace_padded_contents() {
    let directory = tempfile::tempdir().unwrap();
    for (name, bytes) in [
        ("empty", b"".as_slice()),
        ("non-utf8", b"\xff".as_slice()),
        ("leading-space", b" token".as_slice()),
        ("trailing-newline", b"token\n".as_slice()),
    ] {
        let path = directory.path().join(name);
        std::fs::write(&path, bytes).unwrap();

        assert_eq!(read_token_file(path), Err(ClientError::TokenFile));
    }
}

#[test]
fn unknown_token_does_not_render_token_file_contents() {
    let token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let broker = FakeBroker::script_with_token(
        [
            Reply::Hello,
            Reply::Raw(b"ERR\tUNKNOWN_TOKEN\tregistered session missing\n".to_vec()),
        ],
        token.to_owned(),
    );
    let fixture = Fixture::human("HUMAN");
    let token_file = fixture.write_token(token);

    let output = fixture.run_broker(["get", "HUMAN"], broker.socket(), Some(&token_file), None);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_ne!(output.status.code(), Some(0));
    assert!(stderr.contains("broker restarted"));
    assert!(!stderr.contains(token));
}

#[test]
fn every_daemon_error_has_distinct_retry_safe_guidance() {
    for (code, guidance) in [
        (ErrCode::BadRequest, "malformed request"),
        (ErrCode::UnknownOp, "unsupported operation"),
        (ErrCode::VersionMismatch, "different protocol versions"),
        (ErrCode::UnknownToken, "broker restarted"),
        (
            ErrCode::NoScope,
            "non-interactive ssh host 'secrets get KEY'",
        ),
        (ErrCode::AgentTty, "known agent terminal"),
        (ErrCode::NotHumanKey, "missing or was moved"),
        (ErrCode::Denied, "declined"),
        (ErrCode::Timeout, "expired"),
        (ErrCode::YubikeyUnreachable, "hardware path"),
        (ErrCode::TooManyPending, "too many pending"),
        (ErrCode::Internal, "journalctl --user -u secretsd"),
    ] {
        let text = CliError::from_broker(code).to_string();
        assert!(text.starts_with("AGENT NOTICE: ask the human; do not retry-loop."));
        assert!(text.contains(guidance), "{code:?}: {text}");
    }
}

#[test]
fn control_operations_use_the_broker_without_a_token_or_tty() {
    let broker = FakeBroker::script([
        Reply::Hello,
        Reply::Bytes(b"pending=0\n".to_vec()),
        Reply::Hello,
        Reply::Ok,
        Reply::Hello,
        Reply::Ok,
    ]);
    let fixture = Fixture::agent("");

    let grants = fixture.run_broker(["grants"], broker.socket(), None, None);
    let deny = fixture.run_broker(["deny", "7"], broker.socket(), None, None);
    let lock = fixture.run_broker(["lock"], broker.socket(), None, None);

    assert_eq!(grants.stdout, b"pending=0\n");
    assert_eq!(deny.status.code(), Some(0));
    assert_eq!(lock.status.code(), Some(0));
    assert_eq!(
        broker.frames(),
        [
            "HELLO\tversion=2",
            "GRANTS",
            "HELLO\tversion=2",
            "DENY\tid=7",
            "HELLO\tversion=2",
            "LOCK",
        ]
    );
}

#[test]
fn bare_human_get_requests_a_grant_without_receiving_the_value() {
    // A bare `get` pre-authorizes the session: it sends REQUEST, which blocks for
    // the human's approval and triggers the touch, and it never asks for bytes.
    let token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let broker = FakeBroker::script_with_token(
        [Reply::Hello, Reply::Raw(b"OK\tstatus=granted\n".to_vec())],
        token.to_owned(),
    );
    let fixture = Fixture::human("HUMAN");
    let token_file = fixture.write_token(token);

    let output = fixture.run_broker(["get", "HUMAN"], broker.socket(), Some(&token_file), None);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        output.stdout,
        b"{\"key\":\"HUMAN\",\"tier\":\"human\",\"grant\":true}\n"
    );
    assert_eq!(
        broker.frames(),
        ["HELLO\tversion=2", "REQUEST\tkey=HUMAN\ttoken=<redacted>"]
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("human-value"));
}
