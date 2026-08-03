#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    missing_docs,
    reason = "the integration test delegates its observable end-to-end checks to the standalone harness"
)]

use std::path::Path;
use std::process::Command;

#[test]
fn e2e_real_sops_harness_exercises_the_built_dual_mode_binary_when_prerequisites_exist() {
    // Given the built dual-mode binary plus the permanent standalone harness.
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/e2e-client-harness.sh");
    assert!(
        Path::new(script).is_file(),
        "the standalone real-sops harness must exist"
    );

    // When the harness creates its scratch deployment and drives the human-tier flow.
    let output = Command::new(script)
        .args([
            env!("CARGO_BIN_EXE_secrets"),
            "serve",
            env!("CARGO_BIN_EXE_secrets"),
        ])
        .output()
        .expect("start standalone real-sops harness");

    // Then it succeeds, or cleanly skips on a machine without sops or the disk age key.
    match output.status.code() {
        Some(0 | 77) => {}
        Some(code) => panic!(
            "real-sops daemon/client harness exited {code}: {}",
            String::from_utf8_lossy(&output.stderr)
        ),
        None => panic!("real-sops daemon/client harness terminated by signal"),
    }
}
