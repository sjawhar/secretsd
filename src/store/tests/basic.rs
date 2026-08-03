use std::io::Read;

use super::*;
use crate::proto::ErrCode;

fn fixture() -> (tempfile::TempDir, HumanStore) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("DEEL_API_KEY.env"), b"ciphertext").unwrap();
    std::fs::write(dir.path().join("FLEET_LICENSE_KEY.env"), b"ciphertext").unwrap();
    std::fs::write(dir.path().join("notes.txt"), b"ignored").unwrap();
    std::os::unix::fs::symlink("/etc/passwd", dir.path().join("EVIL_LINK.env")).unwrap();
    std::fs::create_dir(dir.path().join("A_DIR.env")).unwrap();
    let store = HumanStore::new(vec![source("test", dir.path())]);
    (dir, store)
}

#[test]
fn lists_key_names_from_file_names_only() {
    let (_dir, store) = fixture();
    let names = store
        .key_names()
        .unwrap()
        .iter()
        .map(|name| name.as_str().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        ["A_DIR", "DEEL_API_KEY", "EVIL_LINK", "FLEET_LICENSE_KEY"]
    );
}

#[test]
fn listing_missing_directory_yields_no_keys() {
    let store = HumanStore::new(vec![source(
        "test",
        Path::new("/nonexistent/secretsd-test"),
    )]);
    assert_eq!(store.key_names().unwrap(), Vec::new());
}

#[test]
fn opens_regular_file() {
    let (_dir, store) = fixture();
    let mut file = store.open(&name("DEEL_API_KEY")).unwrap().file;
    let mut buffer = String::new();
    file.read_to_string(&mut buffer).unwrap();
    assert_eq!(buffer, "ciphertext");
}

#[test]
fn refuses_to_follow_symlink() {
    let (_dir, store) = fixture();
    assert_eq!(
        store.open(&name("EVIL_LINK")).err(),
        Some(ErrCode::NotHumanKey)
    );
}

#[test]
fn refuses_directory() {
    let (_dir, store) = fixture();
    assert_eq!(store.open(&name("A_DIR")).err(), Some(ErrCode::NotHumanKey));
}

#[test]
fn refuses_absent_key() {
    let (_dir, store) = fixture();
    assert_eq!(store.open(&name("NOPE")).err(), Some(ErrCode::NotHumanKey));
}
