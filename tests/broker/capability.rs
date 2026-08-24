#![allow(
    clippy::panic,
    clippy::significant_drop_tightening,
    reason = "the task specification provides this integration harness verbatim"
)]

use super::{Harness, TOKEN_A, install_request_log_capture, request_log, token};

fn receipt_from(header: &str) -> String {
    header
        .trim_end()
        .split(' ')
        .find_map(|field| field.strip_prefix("receipt="))
        .unwrap_or_else(|| panic!("no receipt in {header:?}"))
        .to_owned()
}

#[test]
fn authorize_grants_and_the_receipt_redeems_exactly_once() {
    let harness = Harness::start(&["CAP_BROWSER"]);
    harness.send(&format!(
        "REGISTER\ttoken={}\tsession=ses_a\tpid=1",
        token(TOKEN_A)
    ));

    let (header, _) = harness.send(&format!("AUTHORIZE\tcap=browser\ttoken={}", token(TOKEN_A)));
    assert!(
        header.starts_with("OK\tstatus=authorized receipt="),
        "{header}"
    );
    let receipt = receipt_from(&header);

    let (redeemed, _) = harness.send(&format!("REDEEM\treceipt={receipt}\tcap=browser"));
    assert_eq!(redeemed.trim_end(), "OK\tstatus=redeemed cap=browser");

    let (again, _) = harness.send(&format!("REDEEM\treceipt={receipt}\tcap=browser"));
    assert!(again.contains("DENIED"), "second redeem must fail: {again}");
}

#[test]
fn redeem_refuses_a_mismatched_capability_without_consuming_the_receipt() {
    let harness = Harness::start(&["CAP_BROWSER"]);
    harness.send(&format!(
        "REGISTER\ttoken={}\tsession=ses_a\tpid=1",
        token(TOKEN_A)
    ));
    let (header, _) = harness.send(&format!("AUTHORIZE\tcap=browser\ttoken={}", token(TOKEN_A)));
    let receipt = receipt_from(&header);

    let (mismatched, _) = harness.send(&format!("REDEEM\treceipt={receipt}\tcap=admin"));
    assert!(mismatched.contains("DENIED"));

    let (redeemed, _) = harness.send(&format!("REDEEM\treceipt={receipt}\tcap=browser"));
    assert_eq!(redeemed.trim_end(), "OK\tstatus=redeemed cap=browser");
}

#[test]
fn a_repeat_authorization_runs_a_fresh_ceremony_and_mints() {
    install_request_log_capture();
    match request_log().lock() {
        Ok(mut log) => log.clear(),
        Err(error) => error.into_inner().clear(),
    }
    let harness = Harness::start(&["CAP_BROWSER"]);
    harness.send(&format!(
        "REGISTER\ttoken={}\tsession=ses_a\tpid=1",
        token(TOKEN_A)
    ));
    let (first, _) = harness.send(&format!("AUTHORIZE\tcap=browser\ttoken={}", token(TOKEN_A)));
    let (second, _) = harness.send(&format!("AUTHORIZE\tcap=browser\ttoken={}", token(TOKEN_A)));

    assert!(first.starts_with("OK\tstatus=authorized receipt="));
    assert!(second.starts_with("OK\tstatus=authorized receipt="));
    assert_ne!(receipt_from(&first), receipt_from(&second));
    assert_eq!(harness.sops_invocations(), 2);
    let captured = match request_log().lock() {
        Ok(log) => log.clone(),
        Err(error) => error.into_inner().clone(),
    };
    let log = String::from_utf8(captured).unwrap();
    assert!(!log.contains("grant invalidated after backing file changed"));
}

#[test]
fn two_fresh_capability_authorizations_yield_distinct_receipts() {
    let harness = Harness::start(&["CAP_BROWSER"]);
    harness.send(&format!(
        "REGISTER\ttoken={}\tsession=ses_a\tpid=1",
        token(TOKEN_A)
    ));
    let (first, _) = harness.send(&format!("AUTHORIZE\tcap=browser\ttoken={}", token(TOKEN_A)));
    harness.send("LOCK");
    let (second, _) = harness.send(&format!("AUTHORIZE\tcap=browser\ttoken={}", token(TOKEN_A)));

    assert_ne!(receipt_from(&first), receipt_from(&second));
    assert_eq!(harness.sops_invocations(), 2);
}

#[test]
fn authorization_and_redemption_never_log_credentials() {
    install_request_log_capture();
    match request_log().lock() {
        Ok(mut log) => log.clear(),
        Err(error) => error.into_inner().clear(),
    }
    let session_token = token(TOKEN_A);
    let harness = Harness::start(&["CAP_BROWSER"]);
    harness.send(&format!(
        "REGISTER\ttoken={session_token}\tsession=ses_a\tpid=1"
    ));
    let (header, _) = harness.send(&format!("AUTHORIZE\tcap=browser\ttoken={session_token}"));
    let receipt = receipt_from(&header);
    let (redeemed, _) = harness.send(&format!("REDEEM\treceipt={receipt}\tcap=browser"));

    assert_eq!(redeemed.trim_end(), "OK\tstatus=redeemed cap=browser");
    let (replayed, _) = harness.send(&format!("REDEEM\treceipt={receipt}\tcap=browser"));
    assert!(replayed.contains("DENIED"));
    let captured = match request_log().lock() {
        Ok(log) => log.clone(),
        Err(error) => error.into_inner().clone(),
    };
    let log = String::from_utf8(captured).unwrap();
    assert!(log.contains("key=CAP_BROWSER"));
    assert!(log.contains("cap=browser"));
    assert!(log.contains("redeemed=true"));
    assert!(log.contains("redeemed=false"));
    assert!(!log.contains(&session_token));
    assert!(!log.contains(&receipt));
}

#[test]
fn capability_values_are_unreachable_through_get_and_request() {
    let harness = Harness::start(&["CAP_BROWSER"]);
    harness.send(&format!(
        "REGISTER\ttoken={}\tsession=ses_a\tpid=1",
        token(TOKEN_A)
    ));

    let (get, payload) = harness.send(&format!("GET\tkey=CAP_BROWSER\ttoken={}", token(TOKEN_A)));
    assert!(get.contains("NOT_HUMAN_KEY"), "{get}");
    assert!(payload.is_empty());
    let (request, _) = harness.send(&format!(
        "REQUEST\tkey=CAP_BROWSER\ttoken={}",
        token(TOKEN_A)
    ));
    assert!(request.contains("NOT_HUMAN_KEY"), "{request}");
    assert_eq!(
        harness.sops_invocations(),
        0,
        "the guard must refuse before any decrypt"
    );
}

#[test]
fn authorize_for_an_unprovisioned_capability_names_the_missing_key() {
    let harness = Harness::start(&[]);
    harness.send(&format!(
        "REGISTER\ttoken={}\tsession=ses_a\tpid=1",
        token(TOKEN_A)
    ));
    let (header, _) = harness.send(&format!("AUTHORIZE\tcap=browser\ttoken={}", token(TOKEN_A)));
    assert!(header.contains("NOT_HUMAN_KEY"), "{header}");
}

#[test]
fn a_denied_authorize_mints_no_receipt() {
    let harness = Harness::start_with_sops(&["CAP_BROWSER"], "fake-sops-hang");
    let marker = harness.hang_marker().clone();
    harness.send(&format!(
        "REGISTER\ttoken={}\tsession=ses_a\tpid=1",
        token(TOKEN_A)
    ));
    let socket = harness.socket().clone();
    let authorize = std::thread::spawn(move || {
        let mut stream = std::os::unix::net::UnixStream::connect(&socket).unwrap();
        std::io::Write::write_all(
            &mut stream,
            format!("AUTHORIZE\tcap=browser\ttoken={}\n", token(TOKEN_A)).as_bytes(),
        )
        .unwrap();
        let mut reply = String::new();
        std::io::Read::read_to_string(&mut stream, &mut reply).unwrap();
        reply
    });
    // The hang marker appears when fake-sops-hang starts: the ceremony is now
    // genuinely mid-decrypt. Bounded wait, so a broken daemon fails loudly
    // instead of hanging the test.
    for _ in 0..100 {
        if marker.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    // Request ids are sequential per daemon; the AUTHORIZE above is this
    // harness's first approval request, so it is id 1.
    harness.send("DENY\tid=1");

    let reply = authorize.join().unwrap();
    assert!(reply.contains("DENIED"), "{reply}");
    assert!(
        !reply.contains("receipt="),
        "a denied ceremony must not attest"
    );
}

#[test]
fn lock_kills_receipts_minted_before_it() {
    // Lock must mean locked. Without receipts dying in the lock path, this
    // receipt would stay redeemable for up to 60 seconds after an explicit
    // `secrets lock`, letting forward serve grant browser access post-lock.
    // This is the discriminating regression for the fix: it fails if lock()
    // does not clear the receipt table.
    let harness = Harness::start(&["CAP_BROWSER"]);
    harness.send(&format!(
        "REGISTER\ttoken={}\tsession=ses_a\tpid=1",
        token(TOKEN_A)
    ));
    let (header, _) = harness.send(&format!("AUTHORIZE\tcap=browser\ttoken={}", token(TOKEN_A)));
    let receipt = receipt_from(&header);

    harness.send("LOCK");

    let (after, _) = harness.send(&format!("REDEEM\treceipt={receipt}\tcap=browser"));
    assert!(
        after.contains("DENIED"),
        "a receipt minted before a lock must die with it: {after}"
    );
}

#[test]
fn a_lock_racing_an_in_flight_authorize_leaves_no_redeemable_receipt() {
    // The companion case: the lock lands while the ceremony is still
    // decrypting. The lock epoch — captured before dispatch_access, rechecked
    // under the same state lock as the mint — makes the whole AUTHORIZE
    // atomic with respect to LOCK, so no interleaving mints a receipt that
    // survives the lock.
    let harness = Harness::start_with_sops(&["CAP_BROWSER"], "fake-sops-hang");
    let marker = harness.hang_marker().clone();
    harness.send(&format!(
        "REGISTER\ttoken={}\tsession=ses_a\tpid=1",
        token(TOKEN_A)
    ));
    let socket = harness.socket().clone();
    let authorize = std::thread::spawn(move || {
        let mut stream = std::os::unix::net::UnixStream::connect(&socket).unwrap();
        std::io::Write::write_all(
            &mut stream,
            format!("AUTHORIZE\tcap=browser\ttoken={}\n", token(TOKEN_A)).as_bytes(),
        )
        .unwrap();
        let mut reply = String::new();
        std::io::Read::read_to_string(&mut stream, &mut reply).unwrap();
        reply
    });
    // The hang marker appears when fake-sops-hang starts: the decrypt is now
    // actually in flight, so the LOCK below genuinely races the ceremony.
    // Bounded wait — a broken daemon fails the assertions instead of hanging.
    for _ in 0..100 {
        if marker.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    harness.send("LOCK");

    let reply = authorize.join().unwrap();
    assert!(
        !reply.contains("receipt="),
        "an authorize crossing a lock must not attest: {reply}"
    );
}
