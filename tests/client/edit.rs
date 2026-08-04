use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use secretsd::secret::{SecretName, parse_single_assignment};

use super::Fixture;

const FAKE_SOPS_CIPHERTEXT_MARKER: &[u8] = b"# fake-sops-ciphertext\n";

fn assert_sops_path(fixture: &Fixture, path: &Path) {
    let mut expected = path.as_os_str().as_bytes().to_vec();
    expected.push(b'\0');
    assert!(fixture.sops_arguments().ends_with(&expected));
}

fn assert_filename_override(fixture: &Fixture, path: &Path) {
    let mut expected = b"--filename-override\0".to_vec();
    expected.extend_from_slice(path.as_os_str().as_bytes());
    expected.push(b'\0');
    assert!(
        fixture
            .sops_arguments()
            .windows(expected.len())
            .any(|arguments| arguments == expected),
        "sops did not receive the target as its filename override"
    );
}

fn assert_sops_encrypt_command(fixture: &Fixture) {
    let arguments = fixture.sops_arguments();
    let mut arguments = arguments
        .split(|byte| *byte == b'\0')
        .filter(|argument| !argument.is_empty());
    assert_eq!(arguments.next(), Some(b"encrypt".as_slice()));
}

fn assert_runtime_is_empty(fixture: &Fixture) {
    assert!(
        fs::read_dir(fixture.runtime_dir())
            .unwrap()
            .next()
            .is_none(),
        "an edit plaintext temp file survived"
    );
}

fn assert_ciphertext_contains(ciphertext: &[u8], assignment: &[u8]) {
    assert!(
        ciphertext
            .windows(assignment.len())
            .any(|window| window == assignment),
        "ciphertext did not contain the edited assignment"
    );
}

#[test]
fn edit_human_encrypts_the_successor_created_by_a_rename_save_editor() {
    // Given: a human key creation whose editor writes a replacement inode.
    let fixture = Fixture::agent("");
    let expected = fixture.dotfiles_dir().join("secrets.human.d/NEW_KEY.env");

    // When: the client creates the human secret.
    let output = fixture.run_editor(
        ["edit-human", "NEW_KEY"],
        "NEW_KEY=\n",
        "rename-human",
        Some("NEW_KEY"),
    );

    // Then: it encrypts the replacement's value, never the original empty prefill.
    assert!(output.status.success());
    let ciphertext = fs::read(expected).unwrap();
    assert_ciphertext_contains(&ciphertext, b"NEW_KEY=renamed\n");
    assert!(
        !ciphertext
            .windows(b"NEW_KEY=\n".len())
            .any(|window| window == b"NEW_KEY=\n")
    );
    assert_runtime_is_empty(&fixture);
}

#[test]
fn edit_encrypts_the_successor_created_by_a_rename_save_editor() {
    // Given: an agent-tier creation whose editor writes a replacement inode.
    let fixture = Fixture::agent("");
    fixture.add_root("private");
    let expected = fixture.root_dir("private").join("secrets.env");

    // When: the client creates the shared agent file.
    let output = fixture.run_editor(
        ["edit", "--source", "private"],
        "# shared agent-tier secrets\n",
        "rename-agent",
        None,
    );

    // Then: it encrypts the replacement, not the original prefill comment.
    assert!(output.status.success());
    let ciphertext = fs::read(expected).unwrap();
    assert_ciphertext_contains(&ciphertext, b"AGENT_TEST_KEY=renamed\n");
    assert!(
        !ciphertext
            .windows(b"# shared agent-tier secrets\n".len())
            .any(|window| window == b"# shared agent-tier secrets\n")
    );
    assert_runtime_is_empty(&fixture);
}

#[test]
fn edit_local_encrypts_the_successor_created_by_a_rename_save_editor() {
    // Given: a local agent-tier creation whose editor writes a replacement inode.
    let fixture = Fixture::agent("");
    let expected = fixture.dotfiles_dir().join("secrets.local.env");

    // When: the client creates the local agent file.
    let output = fixture.run_editor(
        ["edit-local"],
        "# local agent-tier secrets\n",
        "rename-agent",
        None,
    );

    // Then: it encrypts the replacement, not the original prefill comment.
    assert!(output.status.success());
    let ciphertext = fs::read(expected).unwrap();
    assert_ciphertext_contains(&ciphertext, b"AGENT_TEST_KEY=renamed\n");
    assert!(
        !ciphertext
            .windows(b"# local agent-tier secrets\n".len())
            .any(|window| window == b"# local agent-tier secrets\n")
    );
    assert_runtime_is_empty(&fixture);
}

#[test]
fn edit_human_tightens_a_wide_rename_save_successor_before_encrypting() {
    // Given: a human key editor that atomically replaces the tempfile at mode 0644.
    let fixture = Fixture::agent("");

    // When: the client creates the human secret.
    let output = fixture.run_editor(
        ["edit-human", "NEW_KEY"],
        "NEW_KEY=\n",
        "rename-human-wide",
        Some("NEW_KEY"),
    );

    // Then: it tightens the successor before sops receives it and cleans it up.
    assert!(output.status.success());
    assert_eq!(fixture.sops_stdin_mode(), "600\n");
    assert_runtime_is_empty(&fixture);
}

#[test]
fn edit_human_creates_a_prefilled_key_with_the_human_target_creation_rule() {
    let fixture = Fixture::agent("");
    let expected = fixture.dotfiles_dir().join("secrets.human.d/NEW_KEY.env");

    let output = fixture.run_editor(
        ["edit-human", "NEW_KEY"],
        "NEW_KEY=\n",
        "valid-human",
        Some("NEW_KEY"),
    );

    assert!(output.status.success());
    let ciphertext = fs::read(&expected).unwrap();
    assert!(ciphertext.starts_with(FAKE_SOPS_CIPHERTEXT_MARKER));
    let name = SecretName::parse("NEW_KEY").unwrap();
    assert!(parse_single_assignment(&ciphertext, &name).is_ok());
    assert_sops_encrypt_command(&fixture);
    assert_filename_override(&fixture, &expected);
    assert_runtime_is_empty(&fixture);
}

#[test]
fn edit_human_discovers_config_from_its_absolute_target_parent() {
    // Given a config-less operator directory and an absolute human-secret target.
    let fixture = Fixture::agent("");
    let expected = fixture.dotfiles_dir().join("secrets.human.d/NEW_KEY.env");
    let operator_directory = tempfile::tempdir().unwrap();
    let mut command = fixture.command(["edit-human", "NEW_KEY"]);
    command
        .current_dir(operator_directory.path())
        .env("EDITOR", &fixture.editor)
        .env("FAKE_EDITOR_EXPECTED", "NEW_KEY=\n")
        .env("FAKE_EDITOR_MODE", "valid-human")
        .env("FAKE_EDITOR_KEY", "NEW_KEY");

    // When the client creates the secret.
    let output = command.output().unwrap();

    // Then sops starts in the target directory, not the operator's CWD.
    assert!(output.status.success());
    assert!(expected.is_absolute());
    assert_eq!(
        fixture.sops_cwd(),
        format!("{}\n", expected.parent().unwrap().display())
    );
}

#[test]
fn edit_human_creates_a_local_file_path_for_a_new_key_in_one_root() {
    let fixture = Fixture::agent("");
    let expected = fixture
        .dotfiles_dir()
        .join("secrets.human.d/NEW_KEY.local.env");

    let output = fixture.run_editor(
        ["edit-human", "NEW_KEY", "--local"],
        "NEW_KEY=\n",
        "valid-human",
        Some("NEW_KEY"),
    );

    assert!(output.status.success());
    assert!(expected.is_file());
    assert_runtime_is_empty(&fixture);
}

#[test]
fn edit_human_creates_nothing_when_the_editor_exits_unsuccessfully() {
    let fixture = Fixture::agent("");
    let target = fixture.dotfiles_dir().join("secrets.human.d/NEW_KEY.env");

    let output = fixture.run_editor(
        ["edit-human", "NEW_KEY"],
        "NEW_KEY=\n",
        "fail",
        Some("NEW_KEY"),
    );

    assert_ne!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stderr).contains("editor exited"));
    assert!(!target.exists());
    assert_runtime_is_empty(&fixture);
}

#[test]
fn edit_human_refuses_a_wrong_assignment_name() {
    let fixture = Fixture::agent("");
    let target = fixture.dotfiles_dir().join("secrets.human.d/NEW_KEY.env");

    let output = fixture.run_editor(
        ["edit-human", "NEW_KEY"],
        "NEW_KEY=\n",
        "wrong-name",
        Some("NEW_KEY"),
    );

    assert_ne!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stderr).contains("exactly one assignment named"));
    assert!(!target.exists());
    assert_runtime_is_empty(&fixture);
}

#[test]
fn edit_human_refuses_an_extra_assignment() {
    let fixture = Fixture::agent("");
    let target = fixture.dotfiles_dir().join("secrets.human.d/NEW_KEY.env");

    let output = fixture.run_editor(
        ["edit-human", "NEW_KEY"],
        "NEW_KEY=\n",
        "extra-assignment",
        Some("NEW_KEY"),
    );

    assert_ne!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stderr).contains("exactly one assignment named"));
    assert!(!target.exists());
    assert_runtime_is_empty(&fixture);
}

#[test]
fn edit_human_refuses_an_empty_value() {
    let fixture = Fixture::agent("");
    let target = fixture.dotfiles_dir().join("secrets.human.d/NEW_KEY.env");

    let output = fixture.run_editor(
        ["edit-human", "NEW_KEY"],
        "NEW_KEY=\n",
        "empty-value",
        Some("NEW_KEY"),
    );

    assert_ne!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stderr).contains("value must not be empty"));
    assert!(!target.exists());
    assert_runtime_is_empty(&fixture);
}

#[test]
fn edit_human_without_flags_uses_an_existing_keys_actual_root_and_file() {
    let fixture = Fixture::agent("");
    fixture.add_root("private");
    fixture.write_human_name_in("private", "EXISTING.env");
    let expected = fixture
        .root_dir("private")
        .join("secrets.human.d/EXISTING.env");

    let output = fixture.run_minimal(["edit-human", "EXISTING"]);

    assert_eq!(output.status.code(), Some(64));
    assert_sops_path(&fixture, &expected);
}

#[test]
fn edit_human_rejects_local_when_an_existing_key_is_committed() {
    let fixture = Fixture::agent("");
    fixture.write_human_name("EXISTING");

    let output = fixture.run_minimal(["edit-human", "EXISTING", "--local"]);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_ne!(output.status.code(), Some(0));
    assert!(stderr.contains("dotfiles"));
    assert!(fixture.sops_log().is_empty());
}

#[test]
fn edit_human_rejects_a_source_other_than_an_existing_keys_actual_root() {
    let fixture = Fixture::agent("");
    fixture.add_root("private");
    fixture.write_human_name("EXISTING");

    let output = fixture.run_minimal(["edit-human", "EXISTING", "--source", "private"]);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_ne!(output.status.code(), Some(0));
    assert!(stderr.contains("dotfiles"));
    assert!(fixture.sops_log().is_empty());
}

#[test]
fn edit_requires_a_source_when_multiple_roots_are_configured() {
    let fixture = Fixture::agent("");
    fixture.add_root("private");

    let output = fixture.run_minimal(["edit"]);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_ne!(output.status.code(), Some(0));
    assert!(stderr.contains("dotfiles"));
    assert!(stderr.contains("private"));
    assert!(fixture.sops_log().is_empty());
}

#[test]
fn edit_uses_the_source_named_by_the_operator() {
    let fixture = Fixture::agent("");
    fixture.add_root("private");
    let expected = fixture.root_dir("private").join("secrets.env");

    let output = fixture.run_editor(
        ["edit", "--source", "private"],
        "# shared agent-tier secrets\n",
        "valid-agent",
        None,
    );

    assert!(output.status.success());
    assert!(expected.is_file());
    assert_runtime_is_empty(&fixture);
}

#[test]
fn edit_local_prefills_a_new_local_agent_file() {
    let fixture = Fixture::agent("");
    let expected = fixture.dotfiles_dir().join("secrets.local.env");

    let output = fixture.run_editor(
        ["edit-local"],
        "# local agent-tier secrets\n",
        "valid-agent",
        None,
    );

    assert!(output.status.success());
    assert!(expected.is_file());
    assert_runtime_is_empty(&fixture);
}

#[test]
fn edit_human_accepts_correct_source_and_local_assertions_for_an_existing_key() {
    let fixture = Fixture::agent("");
    fixture.add_root("private");
    fixture.write_human_name_in("private", "EXISTING.local.env");
    let expected = fixture
        .root_dir("private")
        .join("secrets.human.d/EXISTING.local.env");

    let output = fixture.run_minimal(["edit-human", "EXISTING", "--source", "private", "--local"]);

    assert_eq!(output.status.code(), Some(64));
    assert_sops_path(&fixture, &expected);
}

#[test]
fn edit_commands_reject_unknown_flags_without_starting_sops() {
    let fixture = Fixture::agent("");

    for arguments in [
        ["edit", "--unknown"].as_slice(),
        ["edit", "--source", "--unknown"].as_slice(),
        ["edit-local", "--unknown"].as_slice(),
        ["edit-human", "KEY", "--unknown"].as_slice(),
    ] {
        let output = fixture.run_minimal(arguments);

        assert_ne!(output.status.code(), Some(0));
        assert!(String::from_utf8_lossy(&output.stderr).contains(
            "usage: secrets get KEY [--value|--no-request] | secrets list | secrets sources | secrets edit [--source NAME] | secrets edit-local [--source NAME] | secrets edit-human KEY [--source NAME] [--local]"
        ));
    }
    assert!(fixture.sops_log().is_empty());
}

#[test]
fn edit_lists_valid_source_names_when_the_requested_source_is_unknown() {
    let fixture = Fixture::agent("");
    fixture.add_root("private");

    let output = fixture.run_minimal(["edit-local", "--source", "missing"]);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_ne!(output.status.code(), Some(0));
    assert!(stderr.contains("dotfiles"));
    assert!(stderr.contains("private"));
    assert!(fixture.sops_log().is_empty());
}
