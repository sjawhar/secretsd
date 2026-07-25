use std::os::unix::net::{UnixListener, UnixStream};

use super::*;

/// This process's pid as the signed value `/proc` uses.
fn own_pid() -> i32 {
    i32::try_from(std::process::id()).expect("pid fits in i32")
}

/// Connect to a throwaway socket and return both ends' identities.
fn connected_pair() -> (PeerIdentity, tempfile::TempDir) {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("peer.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let client = UnixStream::connect(&socket).unwrap();
    let (accepted, _) = listener.accept().unwrap();
    // Keep the client alive so the pinned process (this test) stays running.
    drop(client);
    (PeerIdentity::from_stream(&accepted).unwrap(), directory)
}

#[test]
#[cfg_attr(miri, ignore)]
fn pins_the_connecting_process() {
    let (peer, _directory) = connected_pair();

    // Both ends are this test process, so the pinned pid must be our own.
    assert_eq!(peer.pid(), Some(own_pid()));
    assert!(peer.is_alive());
}

#[test]
#[cfg_attr(miri, ignore)]
fn a_peer_descends_from_itself() {
    let (peer, _directory) = connected_pair();

    // A session's own process legitimately requests its own secrets.
    assert!(peer.descends_from(&peer));
}

#[test]
fn walks_parents_to_find_an_ancestor() {
    // This process descends from pid 1 on any normal system.
    assert!(descends_from(own_pid(), 1));
}

#[test]
fn a_process_does_not_descend_from_an_unrelated_pid() {
    // pid 0 is never a real ancestor, so the walk must terminate false rather
    // than climbing forever.
    assert!(!descends_from(own_pid(), 0));
}

#[test]
fn an_unreadable_pid_denies_rather_than_assuming_kinship() {
    // A pid that cannot exist has no /proc entry; failing to read it must not be
    // treated as a match.
    assert!(!descends_from(i32::MAX, 1));
    assert_eq!(parent_of(i32::MAX), None);
}

#[test]
fn parses_proc_status_fields() {
    let status = "Name:\tbash\nPid:\t4242\nPPid:\t99\n";

    assert_eq!(field(status, "Pid:"), Some(4242));
    assert_eq!(field(status, "PPid:"), Some(99));
    assert_eq!(field(status, "Absent:"), None);
}
