use std::fmt;
#[cfg(test)]
use std::sync::{LazyLock, Mutex, mpsc};
use std::time::Instant;

use zeroize::Zeroizing;

use super::approval::{Access, dispatch_access};
use super::{Shared, lock_state};
use crate::grants::{ScopeKind, SessionToken};
use crate::proto::{ErrCode, PROTOCOL_VERSION, Request};
use crate::requests::RequestId;
use crate::secret::SecretBytes;

pub(super) enum Outcome {
    Ok,
    Fields(String),
    Payload(Vec<u8>),
    Bytes(SecretBytes),
    Receipt(Zeroizing<String>),
    Failed(ErrCode, &'static str),
}

impl fmt::Debug for Outcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ok => formatter.write_str("Ok"),
            Self::Fields(fields) => formatter.debug_tuple("Fields").field(fields).finish(),
            Self::Payload(payload) => formatter.debug_tuple("Payload").field(payload).finish(),
            Self::Bytes(value) => formatter.debug_tuple("Bytes").field(value).finish(),
            Self::Receipt(_) => formatter.write_str("Receipt(<redacted>)"),
            Self::Failed(code, message) => formatter
                .debug_tuple("Failed")
                .field(code)
                .field(message)
                .finish(),
        }
    }
}

impl Outcome {
    /// How many secret bytes were handed to the client, if any.
    ///
    /// A release served from a live grant asks nothing of the human and produces
    /// no hardware prompt, so this is the only record that the value moved.
    pub(super) fn released_bytes(&self) -> Option<usize> {
        match self {
            Self::Bytes(value) => Some(value.as_slice().len()),
            Self::Ok | Self::Fields(_) | Self::Payload(_) | Self::Receipt(_) | Self::Failed(..) => {
                None
            }
        }
    }

    pub(super) const fn decision(&self) -> &'static str {
        match self {
            Self::Ok | Self::Fields(_) | Self::Payload(_) | Self::Bytes(_) | Self::Receipt(_) => {
                "ok"
            }
            Self::Failed(code, _) => code.wire(),
        }
    }
}

#[derive(Debug)]
pub(super) struct Decision {
    pub(super) outcome: Outcome,
    pub(super) scope_kind: Option<ScopeKind>,
    pub(super) source: Option<String>,
    pub(super) request_id: Option<RequestId>,
}

fn register(
    shared: &Shared,
    token_hex: &str,
    session: &str,
    root: crate::peer::PeerIdentity,
) -> Decision {
    match SessionToken::parse_hex(token_hex) {
        Ok(token) => {
            let (mutex, condvar) = &**shared;
            let mut state = lock_state(mutex);
            let registered = state.registry.register(crate::grants::Registration {
                token,
                session: session.to_owned(),
                root,
            });
            match registered {
                Ok(displaced) => {
                    state.grants.revoke_tokens(&displaced);
                    drop(state);
                    condvar.notify_all();
                    Decision {
                        outcome: Outcome::Ok,
                        scope_kind: Some(ScopeKind::VerifiedSession),
                        source: None,
                        request_id: None,
                    }
                }
                Err(error) => Decision {
                    outcome: Outcome::Failed(error, "token is already bound to another session"),
                    scope_kind: None,
                    source: None,
                    request_id: None,
                },
            }
        }
        Err(error) => Decision {
            outcome: Outcome::Failed(error, "invalid session token"),
            scope_kind: None,
            source: None,
            request_id: None,
        },
    }
}

fn unregister(shared: &Shared, session: &str) -> Decision {
    let (mutex, condvar) = &**shared;
    let mut state = lock_state(mutex);
    let tokens = state.registry.unregister(session);
    state.grants.revoke_tokens(&tokens);
    drop(state);
    condvar.notify_all();
    Decision {
        outcome: Outcome::Ok,
        scope_kind: None,
        source: None,
        request_id: None,
    }
}

fn grants(shared: &Shared) -> Decision {
    let (mutex, _) = &**shared;
    let state = lock_state(mutex);
    Decision {
        outcome: Outcome::Payload(state.grants.render(Instant::now()).into_bytes()),
        scope_kind: None,
        source: None,
        request_id: None,
    }
}

fn receipt_mint_failure(error: &std::io::Error) -> Outcome {
    match error.kind() {
        std::io::ErrorKind::WouldBlock => {
            Outcome::Failed(ErrCode::TooManyPending, "too many outstanding receipts")
        }
        _ => Outcome::Failed(ErrCode::Internal, "receipt entropy unavailable"),
    }
}

#[cfg(test)]
struct MintPause {
    entered: mpsc::SyncSender<()>,
    resume: mpsc::Receiver<()>,
}

#[cfg(test)]
fn mint_pause() -> &'static Mutex<Option<MintPause>> {
    static PAUSE: LazyLock<Mutex<Option<MintPause>>> = LazyLock::new(|| Mutex::new(None));
    &PAUSE
}

#[cfg(test)]
fn pause_before_receipt_mint() {
    let pause = mint_pause()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    if let Some(pause) = pause {
        let _ = pause.entered.send(());
        let _ = pause.resume.recv();
    }
}

fn finish_authorization(
    shared: &Shared,
    cap: &crate::capability::Capability,
    epoch_before: u64,
    Decision {
        outcome,
        scope_kind,
        source,
        request_id,
    }: Decision,
) -> Decision {
    #[cfg(test)]
    pause_before_receipt_mint();
    let (mutex, _) = &**shared;
    let outcome = match (outcome, request_id) {
        (Outcome::Fields(_), Some(_)) => {
            let mut state = lock_state(mutex);
            if state.lock_epoch == epoch_before {
                state
                    .receipts
                    .mint(cap, Instant::now())
                    .map_or_else(|error| receipt_mint_failure(&error), Outcome::Receipt)
            } else {
                Outcome::Failed(ErrCode::Denied, "locked during authorization")
            }
        }
        (other, _) => other,
    };
    Decision {
        outcome,
        scope_kind,
        source,
        request_id,
    }
}

fn deny(shared: &Shared, id: u64) -> Decision {
    let (mutex, condvar) = &**shared;
    let mut state = lock_state(mutex);
    let outcome = if state.queue.deny(RequestId(id)) {
        state.kill_active(RequestId(id));
        Outcome::Ok
    } else {
        Outcome::Failed(ErrCode::BadRequest, "request is not pending")
    };
    drop(state);
    condvar.notify_all();
    Decision {
        outcome,
        scope_kind: None,
        source: None,
        request_id: None,
    }
}

fn authorize(
    shared: &Shared,
    cap: &str,
    token_hex: Option<Zeroizing<String>>,
    tty: Option<String>,
    caller: &crate::peer::PeerIdentity,
) -> Decision {
    let cap = match crate::capability::Capability::parse(cap) {
        Ok(cap) => cap,
        Err(error) => {
            return Decision {
                outcome: Outcome::Failed(error, "invalid capability name"),
                scope_kind: None,
                source: None,
                request_id: None,
            };
        }
    };
    let access = Access {
        key: cap.key_name(),
        token_hex,
        tty,
    };
    let (mutex, _) = &**shared;
    let epoch_before = lock_state(mutex).lock_epoch;
    let decision = dispatch_access(shared, &access, false, true, caller);
    finish_authorization(shared, &cap, epoch_before, decision)
}

fn redeem(shared: &Shared, receipt_hex: &str, expected_cap: &str) -> Decision {
    let expected_cap = match crate::capability::Capability::parse(expected_cap) {
        Ok(cap) => cap,
        Err(error) => {
            return Decision {
                outcome: Outcome::Failed(error, "invalid capability name"),
                scope_kind: None,
                source: None,
                request_id: None,
            };
        }
    };
    let (mutex, _) = &**shared;
    let redeemed = lock_state(mutex)
        .receipts
        .redeem(receipt_hex, &expected_cap, Instant::now());
    tracing::info!(
        cap = %expected_cap.as_str(),
        redeemed = redeemed.is_some(),
        "capability receipt redemption"
    );
    let outcome = redeemed.map_or(
        Outcome::Failed(ErrCode::Denied, "receipt is not redeemable"),
        |cap| Outcome::Fields(format!("status=redeemed cap={}", cap.as_str())),
    );
    Decision {
        outcome,
        scope_kind: None,
        source: None,
        request_id: None,
    }
}

fn lock(shared: &Shared) -> Decision {
    let (mutex, condvar) = &**shared;
    let mut state = lock_state(mutex);
    state.grants.revoke_all();
    state.receipts.clear();
    state.lock_epoch = state.lock_epoch.saturating_add(1);
    if let Some(active) = state.active_decrypt.take() {
        state.queue.deny(active.id);
        let _ = nix::sys::signal::killpg(
            nix::unistd::Pid::from_raw(active.process_group),
            nix::sys::signal::Signal::SIGKILL,
        );
    }
    drop(state);
    condvar.notify_all();
    Decision {
        outcome: Outcome::Ok,
        scope_kind: None,
        source: None,
        request_id: None,
    }
}

pub(super) fn dispatch(
    request: Request,
    shared: &Shared,
    caller: &crate::peer::PeerIdentity,
) -> Decision {
    match request {
        Request::Hello { version } => Decision {
            outcome: if version == PROTOCOL_VERSION {
                // Reported so a harness can tell "same daemon" from "restarted
                // daemon" and re-register before its requests start failing.
                let (mutex, _) = &**shared;
                let instance = lock_state(mutex).instance.clone();
                Outcome::Fields(format!("version={PROTOCOL_VERSION} instance={instance}"))
            } else {
                Outcome::Failed(ErrCode::VersionMismatch, "unsupported protocol version")
            },
            scope_kind: None,
            source: None,
            request_id: None,
        },
        Request::Register {
            token_hex,
            session,
            pid: _wire_pid,
        } => register(shared, &token_hex, &session, caller.clone()),
        Request::Unregister { session } => unregister(shared, &session),
        Request::Get { key, .. } | Request::RequestGrant { key, .. }
            if key.starts_with(crate::capability::CAPABILITY_KEY_PREFIX) =>
        {
            Decision {
                outcome: Outcome::Failed(
                    ErrCode::NotHumanKey,
                    "capability keys hold no retrievable value",
                ),
                scope_kind: None,
                source: None,
                request_id: None,
            }
        }
        Request::Get {
            key,
            token_hex,
            tty,
        } => {
            let access = Access {
                key,
                token_hex,
                tty,
            };
            dispatch_access(shared, &access, true, false, caller)
        }
        Request::RequestGrant {
            key,
            token_hex,
            tty,
        } => {
            let access = Access {
                key,
                token_hex,
                tty,
            };
            dispatch_access(shared, &access, false, false, caller)
        }
        Request::Grants => grants(shared),
        Request::Deny { id } => deny(shared, id),
        Request::Lock => lock(shared),
        Request::Authorize {
            cap,
            token_hex,
            tty,
        } => authorize(shared, &cap, token_hex, tty, caller),
        Request::Redeem { receipt_hex, cap } => redeem(shared, &receipt_hex, &cap),
    }
}

pub(super) fn request_key(request: &Request) -> Option<&str> {
    match request {
        Request::Get { key, .. } | Request::RequestGrant { key, .. } => Some(key),
        Request::Hello { .. }
        | Request::Register { .. }
        | Request::Unregister { .. }
        | Request::Grants
        | Request::Deny { .. }
        | Request::Lock
        | Request::Authorize { .. }
        | Request::Redeem { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_capacity_is_not_reported_as_an_entropy_failure() {
        let error = std::io::Error::from(std::io::ErrorKind::WouldBlock);

        assert!(matches!(
            receipt_mint_failure(&error),
            Outcome::Failed(ErrCode::TooManyPending, _)
        ));
    }

    #[test]
    fn receipt_entropy_failure_is_internal() {
        let error = std::io::Error::from(std::io::ErrorKind::NotFound);

        assert!(matches!(
            receipt_mint_failure(&error),
            Outcome::Failed(ErrCode::Internal, _)
        ));
    }

    #[test]
    fn receipt_outcome_debug_is_redacted() {
        let receipt = Zeroizing::new("a".repeat(crate::receipts::RECEIPT_LEN * 2));

        assert_eq!(
            format!("{:?}", Outcome::Receipt(receipt)),
            "Receipt(<redacted>)"
        );
    }

    #[test]
    fn lock_between_completed_authorization_and_mint_refuses_the_receipt() {
        use std::os::unix::fs::PermissionsExt;
        use std::path::PathBuf;
        use std::sync::{Arc, Condvar};
        use std::time::Duration;

        use crate::grants::{Registration, SessionToken};
        use crate::store::HumanSource;

        let directory = tempfile::tempdir();
        assert!(directory.is_ok());
        let Some(directory) = directory.ok() else {
            return;
        };
        let human_dir = directory.path().join("human");
        assert!(std::fs::create_dir(&human_dir).is_ok());
        assert!(std::fs::write(human_dir.join("CAP_BROWSER.env"), b"ciphertext").is_ok());
        let sops = directory.path().join("fake-sops");
        assert!(std::fs::write(&sops, "#!/bin/sh\nprintf 'CAP_BROWSER=value\\n'\n").is_ok());
        assert!(std::fs::set_permissions(&sops, std::fs::Permissions::from_mode(0o700)).is_ok());
        let config = crate::Config {
            socket_path: PathBuf::from("/tmp/secretsd-dispatch-test.sock"),
            human_sources: vec![HumanSource {
                label: "test".to_owned(),
                dir: human_dir,
            }],
            sops_bin: sops,
            pcsc_socket: None,
            yubikey_probe_argv: Vec::new(),
            yubikey_probe_timeout: Duration::from_secs(2),
            touch_policy: crate::TouchPolicy::Cached,
            max_grant: Duration::from_secs(1),
            cooldown: Duration::ZERO,
            request_ttl: Duration::from_secs(1),
            max_pending_per_scope: 1,
        };
        let state = super::super::State::new(config);
        assert!(state.is_ok());
        let Some(state) = state.ok() else {
            return;
        };
        let shared = Arc::new((Mutex::new(state), Condvar::new()));
        let caller = crate::peer::PeerIdentity::current_for_test();
        let token_hex = "aa".repeat(32);
        let token = SessionToken::parse_hex(&token_hex);
        assert!(token.is_ok());
        let Some(token) = token.ok() else {
            return;
        };
        let registered = super::super::lock_state(&shared.0)
            .registry
            .register(Registration {
                token,
                session: "session".to_owned(),
                root: caller.clone(),
            });
        assert!(registered.is_ok());
        let cap = crate::capability::Capability::parse("browser");
        assert!(cap.is_ok());
        let Some(cap) = cap.ok() else {
            return;
        };
        let access = Access {
            key: cap.key_name(),
            token_hex: Some(Zeroizing::new(token_hex)),
            tty: None,
        };
        let epoch_before = super::super::lock_state(&shared.0).lock_epoch;
        let worker_shared = Arc::clone(&shared);
        let _worker = std::thread::spawn(move || super::super::worker(&worker_shared));
        let decision = dispatch_access(&shared, &access, false, true, &caller);
        assert!(decision.request_id.is_some());
        assert!(matches!(&decision.outcome, Outcome::Fields(_)));
        let (entered_tx, entered_rx) = mpsc::sync_channel(0);
        let (resume_tx, resume_rx) = mpsc::sync_channel(0);
        let mut pause = mint_pause()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(pause.is_none());
        *pause = Some(MintPause {
            entered: entered_tx,
            resume: resume_rx,
        });
        drop(pause);
        let shared_for_authorize = Arc::clone(&shared);
        let authorizer = std::thread::spawn(move || {
            finish_authorization(&shared_for_authorize, &cap, epoch_before, decision)
        });
        assert!(entered_rx.recv_timeout(Duration::from_secs(1)).is_ok());
        lock(&shared);
        let _ = resume_tx.send(());
        let result = authorizer.join();
        assert!(result.is_ok());
        let Ok(decision) = result else {
            return;
        };
        assert!(matches!(
            decision.outcome,
            Outcome::Failed(ErrCode::Denied, "locked during authorization")
        ));
    }
}
