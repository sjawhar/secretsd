use super::{Harness, TOKEN_A, TOKEN_B, token};

#[test]
fn registered_session_gets_a_value_and_then_a_cached_grant() {
    let harness = Harness::start(&["DEEL_API_KEY"], true);
    harness.send(&format!(
        "REGISTER\ttoken={}\tsession=ses_a\tpid=1",
        token(TOKEN_A)
    ));

    let (header, payload) =
        harness.send(&format!("GET\tkey=DEEL_API_KEY\ttoken={}", token(TOKEN_A)));
    assert!(header.starts_with("OK\tlen="), "{header}");
    assert_eq!(payload, b"value-for-DEEL_API_KEY");

    let (header, payload) =
        harness.send(&format!("GET\tkey=DEEL_API_KEY\ttoken={}", token(TOKEN_A)));
    assert!(header.starts_with("OK\tlen="), "{header}");
    assert_eq!(payload, b"value-for-DEEL_API_KEY");
    assert_eq!(harness.sops_invocations(), 1, "cached grant re-ran sops");
    drop(harness);
}

#[test]
fn daemon_invokes_sops_with_dotenv_input_type() {
    let harness = Harness::start(&["DEEL_API_KEY"], true);
    harness.send(&format!(
        "REGISTER\ttoken={}\tsession=ses_a\tpid=1",
        token(TOKEN_A)
    ));

    let (header, _) = harness.send(&format!("GET\tkey=DEEL_API_KEY\ttoken={}", token(TOKEN_A)));

    assert!(header.starts_with("OK\tlen="), "{header}");
    assert!(
        harness
            .sops_arguments()
            .windows(2)
            .any(|arguments| matches!(arguments, [input_type, dotenv] if input_type == "--input-type" && dotenv == "dotenv")),
        "sops was not given an explicit dotenv input type"
    );
    drop(harness);
}

#[test]
fn sibling_session_does_not_inherit_a_grant() {
    let harness = Harness::start(&["DEEL_API_KEY"], true);
    harness.send(&format!(
        "REGISTER\ttoken={}\tsession=ses_a\tpid=1",
        token(TOKEN_A)
    ));
    harness.send(&format!(
        "REGISTER\ttoken={}\tsession=ses_b\tpid=1",
        token(TOKEN_B)
    ));
    harness.send(&format!("GET\tkey=DEEL_API_KEY\ttoken={}", token(TOKEN_A)));

    let (header, payload) =
        harness.send(&format!("GET\tkey=DEEL_API_KEY\ttoken={}", token(TOKEN_B)));
    assert!(header.starts_with("OK\tlen="), "{header}");
    assert_eq!(payload, b"value-for-DEEL_API_KEY");
    assert_eq!(
        harness.sops_invocations(),
        2,
        "B reused A's decrypted grant"
    );
    let (header, _) = harness.send("GRANTS");
    assert!(header.starts_with("OK"), "{header}");
    drop(harness);
}

#[test]
fn unknown_token_is_rejected_and_never_downgraded() {
    let harness = Harness::start(&["DEEL_API_KEY"], true);
    let (header, _) = harness.send(&format!("GET\tkey=DEEL_API_KEY\ttoken={}", token("cc")));
    assert!(header.contains("UNKNOWN_TOKEN"), "{header}");
    drop(harness);
}

#[test]
fn request_without_scope_is_rejected() {
    let harness = Harness::start(&["DEEL_API_KEY"], true);
    let (header, _) = harness.send("GET\tkey=DEEL_API_KEY");
    assert!(header.contains("NO_SCOPE"), "{header}");
    drop(harness);
}

#[test]
fn unknown_key_is_not_a_human_key() {
    let harness = Harness::start(&["DEEL_API_KEY"], true);
    harness.send(&format!(
        "REGISTER\ttoken={}\tsession=ses_a\tpid=1",
        token(TOKEN_A)
    ));
    let (header, _) = harness.send(&format!("GET\tkey=NOPE\ttoken={}", token(TOKEN_A)));
    assert!(header.contains("NOT_HUMAN_KEY"), "{header}");
    drop(harness);
}

#[test]
fn no_announcement_channel_means_no_grant() {
    let harness = Harness::start(&["DEEL_API_KEY"], false);
    harness.send(&format!(
        "REGISTER\ttoken={}\tsession=ses_a\tpid=1",
        token(TOKEN_A)
    ));
    let (header, _) = harness.send(&format!("GET\tkey=DEEL_API_KEY\ttoken={}", token(TOKEN_A)));
    assert!(
        header.contains("NOT_ANNOUNCED") || header.contains("TIMEOUT"),
        "unannounced request must not be granted: {header}"
    );
    assert_eq!(
        harness.sops_invocations(),
        0,
        "unannounced request ran sops"
    );
    drop(harness);
}
