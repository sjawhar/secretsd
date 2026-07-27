use std::time::Instant;

use super::{Shared, lock_state, wait_state};
use crate::grants::{Scope, ScopeKind, SessionToken};
use crate::proto::{ErrCode, PROTOCOL_VERSION, Request};
use crate::requests::{RequestId, RequestState};
use crate::secret::{SecretBytes, SecretName};

#[derive(Debug)]
struct Access {
    key: String,
    token_hex: Option<String>,
    tty: Option<String>,
}

#[derive(Debug)]
pub(super) enum Outcome {
    Ok,
    Fields(String),
    Payload(Vec<u8>),
    Bytes(SecretBytes),
    Failed(ErrCode, &'static str),
}

impl Outcome {
    /// How many secret bytes were handed to the client, if any.
    ///
    /// A release served from a live grant asks nothing of the human and produces
    /// no hardware prompt, so this is the only record that the value moved.
    pub(super) fn released_bytes(&self) -> Option<usize> {
        match self {
            Self::Bytes(value) => Some(value.as_slice().len()),
            Self::Ok | Self::Fields(_) | Self::Payload(_) | Self::Failed(..) => None,
        }
    }

    pub(super) const fn decision(&self) -> &'static str {
        match self {
            Self::Ok | Self::Fields(_) | Self::Payload(_) | Self::Bytes(_) => "ok",
            Self::Failed(code, _) => code.wire(),
        }
    }
}

#[derive(Debug)]
pub(super) struct Decision {
    pub(super) outcome: Outcome,
    pub(super) scope_kind: Option<ScopeKind>,
}

fn resolve_access(
    shared: &Shared,
    access: &Access,
    caller: &crate::peer::PeerIdentity,
) -> Result<(Scope, SecretName), ErrCode> {
    let key = SecretName::parse(&access.key)?;
    let token = access
        .token_hex
        .as_deref()
        .map(SessionToken::parse_hex)
        .transpose()?;
    let (mutex, _) = &**shared;
    let mut state = lock_state(mutex);
    let scope = state
        .registry
        .resolve(token.as_ref(), access.tty.as_deref(), Some(caller))?;
    drop(state);
    Ok((scope, key))
}

fn await_approval(shared: &Shared, scope: &Scope, key: &SecretName) -> Result<(), ErrCode> {
    let (mutex, condvar) = &**shared;
    let mut state = lock_state(mutex);
    if state.grants.lookup(scope, key).is_some() {
        return Ok(());
    }
    if !state.store.contains(key) {
        return Err(ErrCode::NotHumanKey);
    }
    let now = Instant::now();
    let deadline = now
        .checked_add(state.config.request_ttl)
        .ok_or(ErrCode::Internal)?;
    let id = state.queue.enqueue(scope.clone(), key.clone(), now)?;
    condvar.notify_all();
    loop {
        match state.queue.state_of(id) {
            Some(RequestState::Granted) => return Ok(()),
            Some(RequestState::Denied) => return Err(ErrCode::Denied),
            Some(RequestState::TimedOut) => return Err(ErrCode::Timeout),
            Some(RequestState::Failed) => {
                return Err(state
                    .failures
                    .iter()
                    .find(|(failed_id, _)| *failed_id == id)
                    .map_or(ErrCode::Internal, |(_, error)| *error));
            }
            Some(RequestState::Pending | RequestState::Decrypting) => {
                let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                    state.queue.timeout(id, Instant::now());
                    state.kill_active(id);
                    condvar.notify_all();
                    return Err(ErrCode::Timeout);
                };
                state = wait_state(condvar, state, remaining);
            }
            None => return Err(ErrCode::Internal),
        }
    }
}

fn dispatch_access(
    shared: &Shared,
    access: &Access,
    return_value: bool,
    caller: &crate::peer::PeerIdentity,
) -> Decision {
    let (scope, key) = match resolve_access(shared, access, caller) {
        Ok(resolved) => resolved,
        Err(error) => {
            return Decision {
                outcome: Outcome::Failed(error, "request has no usable scope"),
                scope_kind: None,
            };
        }
    };
    let scope_kind = Some(scope.kind());
    let outcome = match await_approval(shared, &scope, &key) {
        Err(error) => Outcome::Failed(error, "approval did not complete"),
        Ok(()) if return_value => {
            let (mutex, _) = &**shared;
            let state = lock_state(mutex);
            state.grants.lookup(&scope, &key).cloned().map_or(
                Outcome::Failed(ErrCode::Internal, "grant disappeared"),
                Outcome::Bytes,
            )
        }
        Ok(()) => Outcome::Fields("status=granted".to_owned()),
    };
    Decision {
        outcome,
        scope_kind,
    }
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
                    }
                }
                Err(error) => Decision {
                    outcome: Outcome::Failed(error, "token is already bound to another session"),
                    scope_kind: None,
                },
            }
        }
        Err(error) => Decision {
            outcome: Outcome::Failed(error, "invalid session token"),
            scope_kind: None,
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
    }
}

fn grants(shared: &Shared) -> Decision {
    let (mutex, _) = &**shared;
    let state = lock_state(mutex);
    Decision {
        outcome: Outcome::Payload(state.grants.render(Instant::now()).into_bytes()),
        scope_kind: None,
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
    }
}

fn lock(shared: &Shared) -> Decision {
    let (mutex, condvar) = &**shared;
    let mut state = lock_state(mutex);
    state.grants.revoke_all();
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
        },
        Request::Register {
            token_hex,
            session,
            pid: _wire_pid,
        } => register(shared, &token_hex, &session, caller.clone()),
        Request::Unregister { session } => unregister(shared, &session),
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
            dispatch_access(shared, &access, true, caller)
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
            dispatch_access(shared, &access, false, caller)
        }
        Request::Grants => grants(shared),
        Request::Deny { id } => deny(shared, id),
        Request::Lock => lock(shared),
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
        | Request::Lock => None,
    }
}
