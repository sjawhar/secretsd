use super::*;

#[test]
fn ambiguous_key_is_never_decrypted_granted_or_left_pending() {
    // Given two configured sources that both declare the requested key.
    install_request_log_capture();
    request_log().lock().unwrap().clear();
    let sources = [
        ("test", &["DEEL_API_KEY"][..]),
        ("private", &["DEEL_API_KEY"][..]),
    ];
    let harness = Harness::start_with_sources(&sources);
    let token = token(TOKEN_A);
    harness.send(&format!("REGISTER\ttoken={token}\tsession=ses_a\tpid=1"));

    // When the session requests the ambiguous key.
    let (header, _) = harness.send(&format!("GET\tkey=DEEL_API_KEY\ttoken={token}"));
    let (grants_header, grants_payload) = harness.send("GRANTS");

    // Then the protocol rejects it without invoking sops or retaining it in broker state.
    assert!(header.contains("AMBIGUOUS_KEY"), "{header}");
    assert!(header.contains("request refused"), "{header}");
    assert!(!header.contains("approval did not complete"), "{header}");
    assert_eq!(harness.sops_invocations(), 0);
    assert!(grants_header.starts_with("OK"), "{grants_header}");
    assert_eq!(grants_payload, b"no active grants\n");
    let log = String::from_utf8(request_log().lock().unwrap().clone()).unwrap();
    let audit = log
        .lines()
        .find(|line| line.contains("request handled") && line.contains("key=DEEL_API_KEY"))
        .unwrap();
    assert!(
        audit.contains("request_id=None"),
        "ambiguous key was enqueued before dispatch rejected it: {audit}"
    );
    drop(harness);
}

#[test]
fn cached_grant_is_refused_when_its_key_becomes_ambiguous_then_absent() {
    // Given one human key with a cached grant in a multi-source configuration.
    let sources = [("test", &["DEEL_API_KEY"][..]), ("private", &[][..])];
    let harness = Harness::start_with_sources(&sources);
    let token = token(TOKEN_A);
    harness.send(&format!("REGISTER\ttoken={token}\tsession=ses_a\tpid=1"));
    let (initial_header, _) = harness.send(&format!("GET\tkey=DEEL_API_KEY\ttoken={token}"));
    assert!(initial_header.starts_with("OK\tlen="), "{initial_header}");
    assert_eq!(harness.sops_invocations(), 1);

    // When a second source adds the same key.
    let duplicate = harness.human_dir("private").join("DEEL_API_KEY.env");
    std::fs::write(&duplicate, b"ciphertext").unwrap();
    let (ambiguous_header, _) = harness.send(&format!("GET\tkey=DEEL_API_KEY\ttoken={token}"));

    // Then the old grant cannot bypass ambiguity resolution.
    assert!(
        ambiguous_header.contains("AMBIGUOUS_KEY"),
        "{ambiguous_header}"
    );
    assert_eq!(harness.sops_invocations(), 1);

    // When both source files are gone.
    std::fs::remove_file(duplicate).unwrap();
    std::fs::remove_file(harness.human_dir("test").join("DEEL_API_KEY.env")).unwrap();
    let (missing_header, _) = harness.send(&format!("GET\tkey=DEEL_API_KEY\ttoken={token}"));

    // Then the old grant cannot bypass the missing-key resolution either.
    assert!(missing_header.contains("NOT_HUMAN_KEY"), "{missing_header}");
    assert_eq!(harness.sops_invocations(), 1);
    drop(harness);
}

#[test]
fn foreign_caller_refusal_never_enqueues_or_decrypts() {
    // Given a session registered by a short-lived helper process.
    install_request_log_capture();
    request_log().lock().unwrap().clear();
    let harness = Harness::start(&["DEEL_API_KEY"]);
    let token = token(TOKEN_A);
    let registration = send_from_another_process(
        harness.socket(),
        &format!("REGISTER\ttoken={token}\tsession=ses_a\tpid=1"),
    )
    .expect("python3 is required for the foreign-caller authorization regression");
    assert!(registration.starts_with("OK"), "{registration}");

    // When the helper's parent sends a GET using the registered token.
    let (response, _) = harness.send(&format!("GET\tkey=DEEL_API_KEY\ttoken={token}"));
    let (grants_header, grants_payload) = harness.send("GRANTS");

    // Then authorization rejects it before any queue, decrypt, grant, or request-id side effect.
    assert!(response.contains("FOREIGN_CALLER"), "{response}");
    assert_eq!(harness.sops_invocations(), 0);
    assert!(grants_header.starts_with("OK"), "{grants_header}");
    assert_eq!(grants_payload, b"no active grants\n");
    let log = String::from_utf8(request_log().lock().unwrap().clone()).unwrap();
    let audit = log
        .lines()
        .find(|line| {
            line.contains("request handled")
                && line.contains("key=DEEL_API_KEY")
                && line.contains("decision=\"FOREIGN_CALLER\"")
        })
        .unwrap();
    assert!(audit.contains("request_id=None"), "{audit}");
    drop(harness);
}

#[test]
fn local_human_file_grants_with_its_local_source_label_in_the_audit_log() {
    // Given a machine-local human key file in the test source.
    install_request_log_capture();
    request_log().lock().unwrap().clear();
    let harness = Harness::start(&[]);
    std::fs::write(
        harness.human_dir("test").join("DEEL_API_KEY.local.env"),
        b"ciphertext",
    )
    .unwrap();
    let token = token(TOKEN_A);
    harness.send(&format!("REGISTER\ttoken={token}\tsession=ses_a\tpid=1"));

    // When that local key is granted.
    let (header, payload) = harness.send(&format!("GET\tkey=DEEL_API_KEY\ttoken={token}"));
    drop(harness);
    let log = String::from_utf8(request_log().lock().unwrap().clone()).unwrap();

    // Then the value comes from the broker and the worker records the opened local source.
    assert!(header.starts_with("OK\tlen="), "{header}");
    assert_eq!(payload, b"value-for-DEEL_API_KEY");
    let grant_log = log
        .lines()
        .find(|line| line.contains("grant inserted"))
        .unwrap();
    assert!(grant_log.contains("source=test.local"), "{grant_log}");
}

#[test]
fn cached_grant_request_keeps_the_opened_local_source_label_in_the_audit_log() {
    // Given: a local human file has supplied a grant for a registered session.
    install_request_log_capture();
    request_log().lock().unwrap().clear();
    let harness = Harness::start(&[]);
    std::fs::write(
        harness.human_dir("test").join("DEEL_API_KEY.local.env"),
        b"ciphertext",
    )
    .unwrap();
    let token = token(TOKEN_A);
    harness.send(&format!("REGISTER\ttoken={token}\tsession=ses_a\tpid=1"));
    let (header, payload) = harness.send(&format!("GET\tkey=DEEL_API_KEY\ttoken={token}"));
    assert!(header.starts_with("OK\tlen="), "{header}");
    assert_eq!(payload, b"value-for-DEEL_API_KEY");
    request_log().lock().unwrap().clear();

    // When: the same session requests the key again from its cached grant.
    let (header, payload) = harness.send(&format!("GET\tkey=DEEL_API_KEY\ttoken={token}"));
    assert!(header.starts_with("OK\tlen="), "{header}");
    assert_eq!(payload, b"value-for-DEEL_API_KEY");
    assert_eq!(harness.sops_invocations(), 1, "cached grant re-ran sops");
    drop(harness);

    // Then: the second request audit attributes the plaintext to the opened local file.
    let log = String::from_utf8(request_log().lock().unwrap().clone()).unwrap();
    let audit = log
        .lines()
        .find(|line| {
            line.contains("request handled")
                && line.contains("key=DEEL_API_KEY")
                && line.contains("request_id=None")
        })
        .unwrap();
    assert!(audit.contains("source=test.local"), "{audit}");
}

#[test]
fn changed_ciphertext_invalidates_a_cached_grant_and_reapproves() {
    // Given: one human ciphertext file and a session with a live grant from it.
    install_request_log_capture();
    request_log().lock().unwrap().clear();
    // SAFETY: nextest runs this integration test in its own process before the
    // harness starts its daemon thread, so this test owns the fixture setting.
    unsafe { std::env::set_var("FAKE_SOPS_PASSTHROUGH", "1") };
    let harness = Harness::start(&["DEEL_API_KEY"]);
    let ciphertext = harness.human_dir("test").join("DEEL_API_KEY.env");
    std::fs::write(&ciphertext, b"DEEL_API_KEY=first\n").unwrap();
    let token = token(TOKEN_A);
    harness.send(&format!("REGISTER\ttoken={token}\tsession=ses_a\tpid=1"));
    let (first_header, first_value) =
        harness.send(&format!("GET\tkey=DEEL_API_KEY\ttoken={token}"));
    assert!(first_header.starts_with("OK\tlen="), "{first_header}");
    assert_eq!(harness.sops_invocations(), 1);

    // When: an unchanged request uses the cache, then the ciphertext is replaced.
    let (cached_header, cached_value) =
        harness.send(&format!("GET\tkey=DEEL_API_KEY\ttoken={token}"));
    assert!(cached_header.starts_with("OK\tlen="), "{cached_header}");
    assert!(
        cached_value == first_value,
        "unchanged ciphertext did not use cached bytes"
    );
    assert_eq!(
        harness.sops_invocations(),
        1,
        "unchanged ciphertext re-ran sops"
    );
    std::fs::write(&ciphertext, b"DEEL_API_KEY=second-value\n").unwrap();
    let (changed_header, changed_value) =
        harness.send(&format!("GET\tkey=DEEL_API_KEY\ttoken={token}"));

    // Then: the old plaintext was not reused; a fresh decrypt and audit request occurred.
    assert!(changed_header.starts_with("OK\tlen="), "{changed_header}");
    assert!(
        changed_value != first_value,
        "changed ciphertext reused cached bytes"
    );
    assert_eq!(harness.sops_invocations(), 2);
    let log = String::from_utf8(request_log().lock().unwrap().clone()).unwrap();
    let request_ids: Vec<&str> = log
        .lines()
        .filter(|line| line.contains("request handled") && line.contains("key=DEEL_API_KEY"))
        .filter_map(|line| {
            line.split_whitespace()
                .find(|field| field.starts_with("request_id="))
        })
        .collect();
    assert_eq!(request_ids.len(), 3, "{log}");
    let first_request_id = request_ids.first().copied().unwrap();
    let cached_request_id = request_ids.get(1).copied().unwrap();
    let changed_request_id = request_ids.get(2).copied().unwrap();
    assert_ne!(first_request_id, "request_id=None", "{log}");
    assert_eq!(cached_request_id, "request_id=None", "{log}");
    assert_ne!(changed_request_id, "request_id=None", "{log}");
    assert_ne!(first_request_id, changed_request_id, "{log}");
    let invalidation = log
        .lines()
        .find(|line| line.contains("grant invalidated after backing file changed"))
        .unwrap();
    assert!(invalidation.contains("key=DEEL_API_KEY"), "{invalidation}");
    assert!(invalidation.contains("source=test"), "{invalidation}");
    drop(harness);
}

#[test]
fn invalid_human_file_name_refuses_the_source_without_decrypting() {
    // Given a source that contains a valid key and a malformed dotenv filename.
    install_request_log_capture();
    request_log().lock().unwrap().clear();
    let harness = Harness::start(&["DEEL_API_KEY"]);
    std::fs::write(harness.human_dir("test").join("BAD\nNAME.env"), b"corrupt").unwrap();
    let token = token(TOKEN_A);
    harness.send(&format!("REGISTER\ttoken={token}\tsession=ses_a\tpid=1"));

    // When the valid-looking key is requested.
    let (header, _) = harness.send(&format!("GET\tkey=DEEL_API_KEY\ttoken={token}"));

    // Then the corrupt source fails closed instead of serving a shrunken key set.
    assert!(header.contains("INTERNAL"), "{header}");
    assert_eq!(harness.sops_invocations(), 0);
    let log = String::from_utf8(request_log().lock().unwrap().clone()).unwrap();
    let warning = log
        .lines()
        .find(|line| line.contains("invalid human filename"))
        .unwrap();
    assert!(warning.contains("source=test"), "{warning}");
    assert!(warning.contains(r"file_name=BAD\nNAME.env"), "{warning}");
    drop(harness);
}
