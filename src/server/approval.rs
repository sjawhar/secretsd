use std::time::Instant;

use super::dispatch::{Decision, Outcome};
use super::{Shared, lock_state, wait_state};
use crate::grants::{Scope, SessionToken};
use crate::proto::ErrCode;
use crate::requests::{RequestId, RequestState};
use crate::secret::SecretName;

#[derive(Debug)]
pub(super) struct Access {
    pub(super) key: String,
    pub(super) token_hex: Option<String>,
    pub(super) tty: Option<String>,
}

enum Approval {
    Granted {
        source: Option<String>,
        request_id: Option<RequestId>,
    },
    Refused(ErrCode),
    Incomplete {
        error: ErrCode,
        request_id: RequestId,
    },
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

fn await_approval(shared: &Shared, scope: &Scope, key: &SecretName) -> Approval {
    let (mutex, condvar) = &**shared;
    let mut state = lock_state(mutex);
    if let Some((_, source)) = state.grants.lookup(scope, key) {
        let source = source.to_owned();
        drop(state);
        return Approval::Granted {
            source: Some(source),
            request_id: None,
        };
    }
    let source = match state.store.locate(key) {
        Ok(source) => source,
        Err(error) => {
            drop(state);
            return Approval::Refused(error);
        }
    };
    let now = Instant::now();
    let Some(deadline) = now.checked_add(state.config.request_ttl) else {
        drop(state);
        return Approval::Refused(ErrCode::Internal);
    };
    let id = match state.queue.enqueue(scope.clone(), key.clone(), now) {
        Ok(id) => id,
        Err(error) => {
            drop(state);
            return Approval::Refused(error);
        }
    };
    condvar.notify_all();
    let approval = loop {
        match state.queue.state_of(id) {
            Some(RequestState::Granted) => {
                break Approval::Granted {
                    source: Some(source),
                    request_id: Some(id),
                };
            }
            Some(RequestState::Denied) => {
                break Approval::Incomplete {
                    error: ErrCode::Denied,
                    request_id: id,
                };
            }
            Some(RequestState::TimedOut) => {
                break Approval::Incomplete {
                    error: ErrCode::Timeout,
                    request_id: id,
                };
            }
            Some(RequestState::Failed) => {
                break Approval::Incomplete {
                    error: state
                        .failures
                        .iter()
                        .find(|(failed_id, _)| *failed_id == id)
                        .map_or(ErrCode::Internal, |(_, error)| *error),
                    request_id: id,
                };
            }
            Some(RequestState::Pending | RequestState::Decrypting) => {
                let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                    state.queue.timeout(id, Instant::now());
                    state.kill_active(id);
                    condvar.notify_all();
                    break Approval::Incomplete {
                        error: ErrCode::Timeout,
                        request_id: id,
                    };
                };
                state = wait_state(condvar, state, remaining);
            }
            None => {
                break Approval::Incomplete {
                    error: ErrCode::Internal,
                    request_id: id,
                };
            }
        }
    };
    drop(state);
    approval
}

pub(super) fn dispatch_access(
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
                source: None,
                request_id: None,
            };
        }
    };
    let scope_kind = Some(scope.kind());
    let (outcome, source, request_id) = match await_approval(shared, &scope, &key) {
        Approval::Refused(error) => (Outcome::Failed(error, "request refused"), None, None),
        Approval::Incomplete { error, request_id } => (
            Outcome::Failed(error, "approval did not complete"),
            None,
            Some(request_id),
        ),
        Approval::Granted { source, request_id } if return_value => {
            let (mutex, _) = &**shared;
            let outcome = lock_state(mutex)
                .grants
                .lookup(&scope, &key)
                .map(|(value, _)| value)
                .cloned()
                .map_or(
                    Outcome::Failed(ErrCode::Internal, "grant disappeared"),
                    Outcome::Bytes,
                );
            (outcome, source, request_id)
        }
        Approval::Granted { source, request_id } => (
            Outcome::Fields("status=granted".to_owned()),
            source,
            request_id,
        ),
    };
    Decision {
        outcome,
        scope_kind,
        source,
        request_id,
    }
}
