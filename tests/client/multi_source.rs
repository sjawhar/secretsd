use secretsd::proto::PROTOCOL_VERSION;

use super::{FakeBroker, Fixture, Reply};

#[test]
fn list_shows_human_source_labels_without_decrypting_human_files() {
    let fixture = Fixture::agent("AGENT_ONLY=agent-value\n");
    fixture.write_human_name("HUMAN");
    fixture.write_human_name_in("dotfiles", "LOCAL_HUMAN.local.env");

    let output = fixture.run_minimal(["list"]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        output.stdout,
        b"AGENT_ONLY\nHUMAN  (human tier: dotfiles)\nLOCAL_HUMAN  (human tier: dotfiles.local)\n"
    );
    assert_eq!(fixture.sops_calls(), 1);
    assert!(fixture.sops_log().contains("secrets.env"));
    assert!(!fixture.sops_log().contains("HUMAN.env"));
}

#[test]
fn duplicate_human_keys_in_two_roots_fail_closed_before_sops_runs() {
    let fixture = Fixture::agent("");
    fixture.add_root("private");
    fixture.write_human_name_in("dotfiles", "DUP.env");
    fixture.write_human_name_in("private", "DUP.local.env");

    let output = fixture.run_minimal(["get", "DUP", "--value"]);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_ne!(output.status.code(), Some(0));
    assert!(stderr.contains("DUP"));
    assert!(stderr.contains("dotfiles"));
    assert!(stderr.contains("private.local"));
    assert_eq!(fixture.sops_calls(), 0);
}

#[test]
fn committed_and_local_human_files_for_one_key_fail_closed() {
    let fixture = Fixture::agent("");
    fixture.write_human_name_in("dotfiles", "DUP.local.env");
    fixture.write_human_name_in("dotfiles", "DUP.env");

    let output = fixture.run_minimal(["list"]);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_ne!(output.status.code(), Some(0));
    assert!(stderr.contains("DUP"));
    assert!(stderr.contains("location (dotfiles, dotfiles.local)"));
    assert_eq!(fixture.sops_calls(), 0);
}

#[test]
fn human_key_in_the_second_root_flows_through_the_broker() {
    let broker = FakeBroker::script([Reply::Hello, Reply::Bytes(b"human-value".to_vec())]);
    let fixture = Fixture::agent("");
    fixture.add_root("private");
    fixture.write_human_name_in("private", "HUMAN.env");
    std::fs::remove_file(fixture.dotfiles_dir().join("secrets.env")).unwrap();

    let output = fixture.run_broker(["get", "HUMAN", "--value"], broker.socket(), None, None);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"human-value\n");
    assert_eq!(fixture.sops_calls(), 0);
    assert_eq!(
        broker.frames(),
        [
            format!("HELLO\tversion={PROTOCOL_VERSION}"),
            "GET\tkey=HUMAN".to_owned(),
        ]
    );
}

#[test]
fn command_reports_source_table_guidance_when_configuration_is_missing() {
    let fixture = Fixture::agent("");
    std::fs::remove_file(&fixture.config_path).unwrap();

    let output = fixture.run_minimal(["list"]);

    assert_ne!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stderr).contains("[source."));
    assert_eq!(fixture.sops_calls(), 0);
}

#[test]
fn agent_get_prefers_the_first_roots_shared_file() {
    let fixture = Fixture::agent("KEY=first-root\n");
    fixture.add_root("private");
    fixture.write_agent_in("private", "secrets.env", "KEY=second-root\n");

    let output = fixture.run_minimal(["get", "KEY", "--value"]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"first-root\n");
}

#[test]
fn agent_get_prefers_the_first_roots_local_file_over_every_shared_file() {
    let fixture = Fixture::agent("KEY=first-root-shared\n");
    fixture.write_local("KEY=first-root-local\n");
    fixture.add_root("private");
    fixture.write_agent_in("private", "secrets.env", "KEY=second-root\n");

    let output = fixture.run_minimal(["get", "KEY", "--value"]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"first-root-local\n");
}

#[test]
fn agent_get_prefers_the_first_roots_shared_file_over_a_later_roots_local_file() {
    let fixture = Fixture::agent("KEY=first-root-shared\n");
    fixture.add_root("private");
    fixture.write_agent_in("private", "secrets.local.env", "KEY=second-root-local\n");

    let output = fixture.run_minimal(["get", "KEY", "--value"]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"first-root-shared\n");
}

#[test]
fn agent_get_fails_closed_when_a_malformed_name_follows_the_requested_key() {
    let fixture = Fixture::agent("GOOD=one\nBAD-NAME=two\n");

    let output = fixture.run_minimal(["get", "GOOD"]);

    assert_ne!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid secret key"));
    assert_eq!(fixture.sops_calls(), 0);
}
