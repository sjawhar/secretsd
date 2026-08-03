use std::io::Read;

use super::*;
use crate::proto::ErrCode;

#[test]
fn unions_disjoint_sources_and_reports_the_resolved_source_label() {
    // Given two human sources with disjoint ciphertext files.
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    std::fs::write(first.path().join("DEEL_API_KEY.env"), b"first").unwrap();
    std::fs::write(second.path().join("FLEET_LICENSE_KEY.env"), b"second").unwrap();
    let store = HumanStore::new(vec![
        source("dotfiles", first.path()),
        source("private", second.path()),
    ]);

    // When names and source labels are resolved.
    let names = store
        .key_names()
        .unwrap()
        .into_iter()
        .map(|name| name.as_str().to_owned())
        .collect::<Vec<_>>();

    // Then the union contains both keys and preserves the winning source label.
    assert_eq!(names, ["DEEL_API_KEY", "FLEET_LICENSE_KEY"]);
    assert_eq!(
        store.locate(&name("DEEL_API_KEY")),
        Ok("dotfiles".to_owned())
    );
    assert_eq!(
        store.locate(&name("FLEET_LICENSE_KEY")),
        Ok("private".to_owned())
    );
}

#[test]
fn refuses_a_key_present_in_multiple_sources() {
    // Given the same key is present in two configured source directories.
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    std::fs::write(first.path().join("DEEL_API_KEY.env"), b"first").unwrap();
    std::fs::write(second.path().join("DEEL_API_KEY.env"), b"second").unwrap();
    let store = HumanStore::new(vec![
        source("dotfiles", first.path()),
        source("private", second.path()),
    ]);

    // When the key is resolved or opened.
    let located = store.locate(&name("DEEL_API_KEY"));
    let opened = store.open(&name("DEEL_API_KEY"));

    // Then neither operation selects an arbitrary ciphertext file.
    assert_eq!(located, Err(ErrCode::AmbiguousKey));
    assert_eq!(opened.err(), Some(ErrCode::AmbiguousKey));
}

#[test]
fn refuses_committed_and_local_variants_of_the_same_key() {
    // Given one source contains both committed and machine-local variants of a key.
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("DEEL_API_KEY.env"), b"committed").unwrap();
    std::fs::write(directory.path().join("DEEL_API_KEY.local.env"), b"local").unwrap();
    let store = HumanStore::new(vec![source("test", directory.path())]);

    // When that key is resolved.
    let result = store.locate(&name("DEEL_API_KEY"));

    // Then the store refuses the ambiguous key.
    assert_eq!(result, Err(ErrCode::AmbiguousKey));
}

#[test]
fn opens_a_local_variant_and_reports_its_source_label() {
    // Given a source containing only a machine-local key file.
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("DEEL_API_KEY.local.env"),
        b"ciphertext",
    )
    .unwrap();
    let store = HumanStore::new(vec![source("test", directory.path())]);

    // When the local key is opened.
    let mut opened = store.open(&name("DEEL_API_KEY")).unwrap();
    let mut content = String::new();
    opened.file.read_to_string(&mut content).unwrap();

    // Then the label identifies the local source and the file is readable.
    assert_eq!(opened.label, "test.local");
    assert_eq!(content, "ciphertext");
}

#[test]
fn refuses_local_symlink_and_directory_candidates() {
    // Given local filenames that resolve to a symlink and a directory.
    let directory = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink("/etc/passwd", directory.path().join("EVIL_LINK.local.env"))
        .unwrap();
    std::fs::create_dir(directory.path().join("A_DIR.local.env")).unwrap();
    let store = HumanStore::new(vec![source("test", directory.path())]);

    // When either local candidate is opened.
    let symlink = store.open(&name("EVIL_LINK"));
    let directory = store.open(&name("A_DIR"));

    // Then the open-at regular-file protections still refuse them.
    assert_eq!(symlink.err(), Some(ErrCode::NotHumanKey));
    assert_eq!(directory.err(), Some(ErrCode::NotHumanKey));
}

#[test]
fn ignores_a_missing_source_directory_when_another_source_serves_the_key() {
    // Given one absent source and one live source containing a key.
    let parent = tempfile::tempdir().unwrap();
    let absent = parent.path().join("missing");
    let present = tempfile::tempdir().unwrap();
    std::fs::write(present.path().join("DEEL_API_KEY.env"), b"ciphertext").unwrap();
    let store = HumanStore::new(vec![
        source("missing", &absent),
        source("present", present.path()),
    ]);

    // When the key is resolved.
    let result = store.locate(&name("DEEL_API_KEY"));

    // Then the live source remains usable.
    assert_eq!(result, Ok("present".to_owned()));
}

#[test]
fn rejects_a_source_with_an_invalid_human_file_name() {
    // Given a source whose directory contains an invalid dotenv file name.
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("DEEL_API_KEY.env"), b"ciphertext").unwrap();
    std::fs::write(directory.path().join("BAD-NAME.env"), b"corrupt").unwrap();
    let store = HumanStore::new(vec![source("test", directory.path())]);

    // When the valid key is resolved.
    let result = store.locate(&name("DEEL_API_KEY"));

    // Then the corrupt directory refuses the whole lookup instead of shrinking its key set.
    assert_eq!(result, Err(ErrCode::Internal));
}
