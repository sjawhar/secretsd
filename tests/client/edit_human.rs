use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::process::{Output, Stdio};
use std::time::{Duration, Instant};
use std::{fs, thread};

use nix::fcntl::{Flock, FlockArg};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;

use super::Fixture;

const FAKE_SOPS_CIPHERTEXT_MARKER: &[u8] = b"# fake-sops-ciphertext\n";

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

fn assert_ciphertext_contains(ciphertext: &[u8], assignment: &[u8]) {
    assert!(
        ciphertext
            .windows(assignment.len())
            .any(|window| window == assignment),
        "ciphertext did not contain the expected assignment"
    );
}

fn runtime_is_empty(fixture: &Fixture) -> bool {
    fs::read_dir(fixture.runtime_dir())
        .unwrap()
        .next()
        .is_none()
}

fn assert_value_is_not_rendered(output: &Output, value: &[u8]) {
    assert!(
        !output
            .stdout
            .windows(value.len())
            .any(|window| window == value),
        "stdout rendered the piped value"
    );
    assert!(
        !output
            .stderr
            .windows(value.len())
            .any(|window| window == value),
        "stderr rendered the piped value"
    );
}

fn assert_no_staged_ciphertext(directory: &Path) {
    assert!(
        fs::read_dir(directory).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .as_bytes()
            .starts_with(b".secretsd-ciphertext-")),
        "a staged ciphertext file survived the failed write"
    );
}

fn core_limit_is_zero(pid: u32) -> bool {
    let Ok(limits) = fs::read_to_string(format!("/proc/{pid}/limits")) else {
        return false;
    };
    let Some(line) = limits
        .lines()
        .find(|line| line.starts_with("Max core file size"))
    else {
        return false;
    };
    let mut values = line
        .strip_prefix("Max core file size")
        .unwrap()
        .split_whitespace();
    values.next() == Some("0") && values.next() == Some("0")
}

#[test]
fn edit_human_creates_a_local_file_for_a_new_key_from_stdin() {
    let fixture = Fixture::agent("");
    let expected = fixture
        .dotfiles_dir()
        .join("secrets.human.d/NEW_KEY.local.env");

    let output = fixture.run_with_stdin(["edit-human", "NEW_KEY"], b"swordfish-0123");

    assert!(output.status.success());
    assert_eq!(
        output.stdout,
        format!("created {}\n", expected.display()).into_bytes()
    );
    let ciphertext = fs::read(&expected).unwrap();
    assert!(ciphertext.starts_with(FAKE_SOPS_CIPHERTEXT_MARKER));
    assert_sops_encrypt_command(&fixture);
    assert_filename_override(&fixture, &expected);
}

#[test]
fn edit_human_rotates_an_existing_keys_actual_file_and_reports_it() {
    let fixture = Fixture::human("EXISTING_KEY");
    let expected = fixture
        .dotfiles_dir()
        .join("secrets.human.d/EXISTING_KEY.env");

    let output = fixture.run_with_stdin(["edit-human", "EXISTING_KEY"], b"rotated-value");

    assert!(output.status.success());
    assert_eq!(
        output.stdout,
        format!("rotated {}\n", expected.display()).into_bytes()
    );
    assert_ciphertext_contains(
        &fs::read(&expected).unwrap(),
        b"EXISTING_KEY=rotated-value\n",
    );
    assert!(
        !fixture
            .dotfiles_dir()
            .join("secrets.human.d/EXISTING_KEY.local.env")
            .exists()
    );
}

#[test]
fn edit_human_rejects_a_source_other_than_an_existing_keys_actual_root() {
    let fixture = Fixture::human("EXISTING_KEY");
    fixture.add_root("private");

    let output = fixture.run_with_stdin(
        ["edit-human", "EXISTING_KEY", "--source", "private"],
        b"unwritten-value",
    );

    assert_ne!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stderr).contains("source dotfiles"));
    assert_eq!(fixture.sops_calls(), 0);
}

#[test]
fn edit_human_requires_a_source_when_multiple_roots_are_configured() {
    let fixture = Fixture::agent("");
    fixture.add_root("private");
    let target = fixture
        .dotfiles_dir()
        .join("secrets.human.d/NEW_KEY.local.env");

    let output = fixture.run_with_stdin(["edit-human", "NEW_KEY"], b"unwritten-value");

    assert_ne!(output.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("multiple secrets sources are configured; pass --source NAME")
    );
    assert!(!target.exists());
    assert_eq!(fixture.sops_calls(), 0);
}

#[test]
fn edit_human_refuses_an_empty_stdin_value_and_creates_nothing() {
    let fixture = Fixture::agent("");
    let target = fixture
        .dotfiles_dir()
        .join("secrets.human.d/NEW_KEY.local.env");

    let output = fixture.run_with_stdin(["edit-human", "NEW_KEY"], b"");

    assert_ne!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stderr).contains("NEW_KEY"));
    assert!(!target.exists());
    assert_eq!(fixture.sops_calls(), 0);
}

#[test]
fn edit_human_refuses_multiline_and_comment_smuggling_values() {
    for value in [b"a\nb".as_slice(), b"a\n#comment", b"a\n\n", b"a\r\nb"] {
        let fixture = Fixture::agent("");
        let target = fixture
            .dotfiles_dir()
            .join("secrets.human.d/NEW_KEY.local.env");

        let output = fixture.run_with_stdin(["edit-human", "NEW_KEY"], value);

        assert_ne!(output.status.code(), Some(0));
        assert!(!target.exists());
        assert_eq!(fixture.sops_calls(), 0);
        assert_value_is_not_rendered(&output, value);
    }
}

#[test]
fn edit_human_strips_exactly_one_trailing_newline() {
    let fixture = Fixture::agent("");
    let target = fixture
        .dotfiles_dir()
        .join("secrets.human.d/NEW_KEY.local.env");

    let output = fixture.run_with_stdin(["edit-human", "NEW_KEY"], b"value\n");

    assert!(output.status.success());
    assert_ciphertext_contains(&fs::read(target).unwrap(), b"NEW_KEY=value\n");
}

#[test]
fn edit_human_strips_exactly_one_trailing_carriage_return_newline() {
    let fixture = Fixture::agent("");
    let target = fixture
        .dotfiles_dir()
        .join("secrets.human.d/NEW_KEY.local.env");

    let output = fixture.run_with_stdin(["edit-human", "NEW_KEY"], b"value\r\n");

    assert!(output.status.success());
    assert_ciphertext_contains(&fs::read(target).unwrap(), b"NEW_KEY=value\n");
}

#[test]
fn edit_human_zeroes_the_core_limit_before_reading_stdin() {
    let fixture = Fixture::agent("");
    let mut child = fixture
        .command(["edit-human", "NEW_KEY"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdin = child.stdin.take().unwrap();

    let hardened = (0..100).any(|_| {
        if core_limit_is_zero(child.id()) {
            true
        } else {
            thread::sleep(Duration::from_millis(10));
            false
        }
    });

    assert!(
        hardened,
        "the child did not zero its core limit before reading stdin"
    );
    assert!(
        child.try_wait().unwrap().is_none(),
        "the child was not blocked on stdin after hardening"
    );
    drop(stdin);
    let _output = child.wait_with_output().unwrap();
}

#[test]
fn edit_human_sops_failure_never_echoes_the_value_and_leaves_target_unchanged() {
    let create_fixture = Fixture::agent("");
    let create_target = create_fixture
        .dotfiles_dir()
        .join("secrets.human.d/NEW_KEY.local.env");
    let create_value = b"create-failure-value";
    create_fixture.use_sops_fixture("fake-sops-stdin-fail");

    let create_output = create_fixture.run_with_stdin(["edit-human", "NEW_KEY"], create_value);

    assert_ne!(create_output.status.code(), Some(0));
    assert_value_is_not_rendered(&create_output, create_value);
    assert_eq!(create_fixture.sops_calls(), 1);
    assert!(!create_target.exists());
    assert_no_staged_ciphertext(create_target.parent().unwrap());

    let rotate_fixture = Fixture::human("EXISTING_KEY");
    let rotate_target = rotate_fixture
        .dotfiles_dir()
        .join("secrets.human.d/EXISTING_KEY.env");
    let original_ciphertext = fs::read(&rotate_target).unwrap();
    let rotate_value = b"rotate-failure-value";
    rotate_fixture.use_sops_fixture("fake-sops-stdin-fail");

    let rotate_output = rotate_fixture.run_with_stdin(["edit-human", "EXISTING_KEY"], rotate_value);

    assert_ne!(rotate_output.status.code(), Some(0));
    assert_value_is_not_rendered(&rotate_output, rotate_value);
    assert_eq!(rotate_fixture.sops_calls(), 1);
    assert_eq!(fs::read(&rotate_target).unwrap(), original_ciphertext);
    assert_no_staged_ciphertext(rotate_target.parent().unwrap());
}

#[test]
fn edit_human_stdout_failure_never_stages_the_piped_value() {
    let fixture = Fixture::agent("");
    fixture.use_sops_fixture("fake-sops-stdout-hang");
    let target = fixture
        .dotfiles_dir()
        .join("secrets.human.d/NEW_KEY.local.env");
    let human_dir = target.parent().unwrap();
    let marker_directory = tempfile::tempdir().unwrap();
    let process_marker = marker_directory.path().join("sops.pid");
    let value = b"stdout-failure-value";
    let mut child = fixture
        .command(["edit-human", "NEW_KEY"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("FAKE_SOPS_STDOUT_HANG_MARKER", &process_marker)
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    std::io::Write::write_all(&mut stdin, value).unwrap();
    drop(stdin);

    let sops_started = (0..100).any(|_| {
        if process_marker.exists() {
            true
        } else {
            thread::sleep(Duration::from_millis(10));
            false
        }
    });
    if !sops_started {
        let _ = child.kill();
        let _ = child.wait();
        panic!("the stdout-hanging sops fixture did not start");
    }

    let staged_plaintext_exists = fs::read_dir(human_dir).unwrap().any(|entry| {
        let entry = entry.unwrap();
        entry
            .file_name()
            .as_bytes()
            .starts_with(b".secretsd-ciphertext-")
            && fs::read(entry.path())
                .unwrap()
                .windows(value.len())
                .any(|window| window == value)
    });
    let client_was_blocked = child.try_wait().unwrap().is_none();
    let process_id: i32 = fs::read_to_string(&process_marker)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let signal_result = kill(Pid::from_raw(process_id), Signal::SIGTERM);
    let output = child.wait_with_output().unwrap();

    signal_result.unwrap();
    assert!(
        client_was_blocked,
        "edit-human did not wait for the stdout-hanging sops fixture"
    );
    assert!(
        !staged_plaintext_exists,
        "a staged ciphertext file contained the piped value while sops was still running"
    );
    assert!(!output.status.success());
    assert_value_is_not_rendered(&output, value);
    assert!(!target.exists());
    assert_eq!(fixture.sops_calls(), 1);
}

#[test]
fn edit_human_drains_sops_output_before_writing_large_stdin() {
    const LARGE_INPUT_BYTES: usize = 2_097_152;

    let fixture = Fixture::agent("");
    fixture.use_sops_fixture("fake-sops-output-before-stdin");
    let target = fixture
        .dotfiles_dir()
        .join("secrets.human.d/NEW_KEY.local.env");
    let marker_directory = tempfile::tempdir().unwrap();
    let process_marker = marker_directory.path().join("sops.pid");
    let mut child = fixture
        .command(["edit-human", "NEW_KEY"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("FAKE_SOPS_OUTPUT_BEFORE_STDIN_MARKER", &process_marker)
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let writer = thread::spawn(move || {
        let value = vec![b'x'; LARGE_INPUT_BYTES];
        std::io::Write::write_all(&mut stdin, &value)
    });

    let sops_started = (0..100).any(|_| {
        if process_marker.exists() {
            true
        } else {
            thread::sleep(Duration::from_millis(10));
            false
        }
    });
    if !sops_started {
        let _ = child.kill();
        let _ = child.wait();
        let _ = writer.join();
        panic!("the output-before-stdin sops fixture did not start");
    }

    let deadline = Instant::now().checked_add(Duration::from_secs(2)).unwrap();
    let completed = loop {
        match child.try_wait().unwrap() {
            Some(_) => break true,
            None if Instant::now() >= deadline => break false,
            None => thread::sleep(Duration::from_millis(10)),
        }
    };
    if !completed {
        let _ = child.kill();
    }
    let output = child.wait_with_output().unwrap();
    let _ = writer.join();

    assert!(
        completed,
        "edit-human deadlocked while sops wrote output before reading stdin"
    );
    assert!(!output.status.success());
    assert!(!target.exists());
    assert_eq!(fixture.sops_calls(), 1);
}

#[test]
fn edit_human_never_echoes_the_value_to_stdout_or_stderr() {
    let fixture = Fixture::agent("");
    let value = b"success-path-value";

    let output = fixture.run_with_stdin(["edit-human", "NEW_KEY"], value);

    assert!(output.status.success());
    assert_value_is_not_rendered(&output, value);
}

#[test]
fn edit_human_leaves_the_runtime_dir_empty() {
    let fixture = Fixture::agent("");
    fixture.use_sops_fixture("fake-sops-hang");
    let marker_directory = tempfile::tempdir().unwrap();
    let process_marker = marker_directory.path().join("sops.pid");
    let stdin_path_marker = marker_directory.path().join("sops.stdin");
    let mut child = fixture
        .command(["edit-human", "NEW_KEY"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("FAKE_SOPS_HANG_MARKER", &process_marker)
        .env("FAKE_SOPS_STDIN_PATH_MARKER", &stdin_path_marker)
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    std::io::Write::write_all(&mut stdin, b"runtime-value").unwrap();
    drop(stdin);

    let sops_started = (0..100).any(|_| {
        if process_marker.exists() && stdin_path_marker.exists() {
            true
        } else {
            thread::sleep(Duration::from_millis(10));
            false
        }
    });
    if !sops_started {
        let _ = child.kill();
        let _ = child.wait();
        if let Ok(process_id) = fs::read_to_string(&process_marker) {
            let _ = process_id
                .trim()
                .parse()
                .map(Pid::from_raw)
                .map(|pid| kill(pid, Signal::SIGKILL));
        }
        panic!("the hanging sops fixture did not start");
    }

    let process_id: i32 = fs::read_to_string(&process_marker)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let runtime_was_empty = runtime_is_empty(&fixture);
    let stdin_was_a_pipe = fs::read_to_string(&stdin_path_marker)
        .unwrap()
        .starts_with("pipe:[");
    let client_was_blocked = child.try_wait().unwrap().is_none();
    let signal_result = kill(Pid::from_raw(process_id), Signal::SIGTERM);
    let output = child.wait_with_output().unwrap();

    signal_result.unwrap();
    assert!(!output.status.success());
    assert!(
        client_was_blocked,
        "edit-human did not wait for sops encryption"
    );
    assert!(
        runtime_was_empty,
        "edit-human created a plaintext runtime file while encryption was in progress"
    );
    assert!(
        stdin_was_a_pipe,
        "edit-human passed sops a regular file instead of its in-memory pipe"
    );
    assert_eq!(fixture.sops_calls(), 1);
}

#[test]
fn edit_human_blocks_on_the_directory_lock() {
    let fixture = Fixture::human("EXISTING_KEY");
    let human_dir = fixture.dotfiles_dir().join("secrets.human.d");
    let target = human_dir.join("NEW_KEY.local.env");
    let lock = Flock::lock(fs::File::open(&human_dir).unwrap(), FlockArg::LockExclusive).unwrap();
    let mut child = fixture
        .command(["edit-human", "NEW_KEY"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    std::io::Write::write_all(&mut stdin, b"locked-value").unwrap();
    drop(stdin);

    thread::sleep(Duration::from_millis(300));
    assert!(
        child.try_wait().unwrap().is_none(),
        "the second writer did not block on the human-secret directory lock"
    );
    drop(lock);
    let output = child.wait_with_output().unwrap();

    assert!(output.status.success());
    assert!(target.is_file());
}

#[test]
fn edit_human_usage_error_names_the_subcommand() {
    let fixture = Fixture::agent("");

    let output = fixture.run_minimal(["edit-human"]);

    assert_ne!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stderr).contains("edit-human"));
}
