use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use super::Fixture;

fn assert_sops_path(fixture: &Fixture, path: &Path) {
    let mut expected = path.as_os_str().as_bytes().to_vec();
    expected.push(b'\0');
    assert!(fixture.sops_arguments().ends_with(&expected));
}

#[test]
fn edit_human_creates_a_local_file_path_for_a_new_key_in_one_root() {
    let fixture = Fixture::agent("");
    let expected = fixture
        .dotfiles_dir()
        .join("secrets.human.d/NEW_KEY.local.env");

    let output = fixture.run_minimal(["edit-human", "NEW_KEY", "--local"]);

    assert_eq!(output.status.code(), Some(64));
    assert!(expected.parent().is_some_and(Path::is_dir));
    assert_sops_path(&fixture, &expected);
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

    let output = fixture.run_minimal(["edit", "--source", "private"]);

    assert_eq!(output.status.code(), Some(64));
    assert_sops_path(&fixture, &expected);
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
