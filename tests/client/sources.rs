use std::fs;

use super::Fixture;

#[test]
fn sources_reports_each_root_without_decrypting_or_rejecting_duplicate_human_keys() {
    let fixture = Fixture::agent("DOTFILES_SHARED=one\nDOTFILES_OTHER=two\n");
    fixture.write_local("DOTFILES_LOCAL=three\n");
    fixture.write_human_name_in("dotfiles", "HUMAN.env");
    fixture.write_human_name_in("dotfiles", "LOCAL_HUMAN.local.env");
    fixture.write_human_name_in("dotfiles", "DUPLICATE.env");
    fixture.add_root("private");
    fixture.write_agent_in("private", "secrets.env", "PRIVATE_SHARED=four\n");
    fixture.write_human_name_in("private", "DUPLICATE.env");

    let output = fixture.run_minimal(["sources"]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        output.stdout,
        format!(
            "config: {}\nsource dotfiles: {}\n  secrets.env: 2 keys\n  secrets.local.env: 1 key\n  secrets.human.d: 3 keys (1 local)\nsource private: {}\n  secrets.env: 1 key\n  secrets.local.env: absent\n  secrets.human.d: 1 key (0 local)\n",
            fixture.config_path.display(),
            fixture.dotfiles_dir().display(),
            fixture.root_dir("private").display(),
        )
        .as_bytes(),
    );
    assert_eq!(output.stderr, b"");
    assert!(fixture.sops_log().is_empty());
}

#[test]
fn sources_reports_invalid_human_file_names_without_failing() {
    let fixture = Fixture::agent("");
    fixture.write_human_name_in("dotfiles", "BAD-NAME.env");

    let output = fixture.run_minimal(["sources"]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        output.stdout,
        format!(
            "config: {}\nsource dotfiles: {}\n  secrets.env: 0 keys\n  secrets.local.env: absent\n  secrets.human.d: 0 keys (0 local)\n  warning: invalid human file name BAD-NAME.env\n",
            fixture.config_path.display(),
            fixture.dotfiles_dir().display(),
        )
        .as_bytes(),
    );
    assert!(fixture.sops_log().is_empty());
}

#[test]
fn sources_deduplicates_repeated_agent_assignments() {
    let fixture = Fixture::agent("KEY=first\nKEY=second\nOTHER=third\n");

    let output = fixture.run_minimal(["sources"]);

    assert_eq!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stdout).contains("  secrets.env: 2 keys\n"));
    assert!(fixture.sops_log().is_empty());
}

#[test]
fn sources_warns_and_continues_when_an_agent_file_is_malformed() {
    let fixture = Fixture::agent("GOOD=one\n");
    fixture.add_root("private");
    fixture.write_agent_in("private", "secrets.env", "BAD-NAME=two\n");

    let output = fixture.run_minimal(["sources"]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        output.stdout,
        format!(
            "config: {}\nsource dotfiles: {}\n  secrets.env: 1 key\n  secrets.local.env: absent\n  secrets.human.d: absent\nsource private: {}\n  secrets.env: unreadable (invalid secret key)\n  secrets.local.env: absent\n  secrets.human.d: absent\n",
            fixture.config_path.display(),
            fixture.dotfiles_dir().display(),
            fixture.root_dir("private").display(),
        )
        .as_bytes(),
    );
    assert!(fixture.sops_log().is_empty());
}

#[test]
fn sources_rejects_trailing_arguments() {
    let fixture = Fixture::agent("");

    let output = fixture.run_minimal(["sources", "extra"]);

    assert_ne!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stderr).contains("usage: secrets"));
    assert!(fixture.sops_log().is_empty());
}

#[test]
fn sources_counts_distinct_keys_and_warns_on_committed_local_pairs() {
    let fixture = Fixture::agent("");
    fixture.write_human_name("COMMITTED_KEY");
    fixture.write_human_name_in("dotfiles", "COMMITTED_KEY.local.env");
    fixture.write_human_name_in("dotfiles", "MACHINE_KEY.local.env");

    let output = fixture.run_minimal(["sources"]);

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("  secrets.human.d: 2 keys (1 local)\n"));
    assert!(stdout.contains("  warning: key COMMITTED_KEY has both committed and local files\n"));
    assert!(fixture.sops_log().is_empty());
}

#[test]
fn sources_distinguishes_empty_human_directories_from_missing_parts() {
    let fixture = Fixture::agent("");
    fs::create_dir_all(fixture.dotfiles_dir().join("secrets.human.d")).unwrap();

    let empty_directory = fixture.run_minimal(["sources"]);

    assert_eq!(empty_directory.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&empty_directory.stdout)
            .contains("  secrets.human.d: 0 keys (0 local)\n")
    );

    fs::remove_dir(fixture.dotfiles_dir().join("secrets.human.d")).unwrap();
    fs::remove_file(fixture.dotfiles_dir().join("secrets.env")).unwrap();
    let no_parts = fixture.run_minimal(["sources"]);

    assert_eq!(no_parts.status.code(), Some(0));
    assert_eq!(
        no_parts.stdout,
        format!(
            "config: {}\nsource dotfiles: {}\n  secrets.env: absent\n  secrets.local.env: absent\n  secrets.human.d: absent\n",
            fixture.config_path.display(),
            fixture.dotfiles_dir().display(),
        )
        .as_bytes(),
    );
}
