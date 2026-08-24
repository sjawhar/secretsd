use std::fmt;
use std::time::Instant;

use zeroize::Zeroizing;

use super::dispatch::{Decision, Outcome};
use super::{Shared, lock_state, wait_state};
use crate::audit::sanitize_audit_value;
use crate::grants::{Scope, SessionToken};
use crate::proto::ErrCode;
use crate::requests::{RequestId, RequestState};
use crate::secret::SecretName;

pub(super) struct Access {
    pub(super) key: String,
    pub(super) token_hex: Option<Zeroizing<String>>,
    pub(super) tty: Option<String>,
}

impl fmt::Debug for Access {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Access")
            .field("key", &self.key)
            .field("token_present", &self.token_hex.is_some())
            .field("tty", &self.tty)
            .finish()
    }
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
        .map(|token_hex| SessionToken::parse_hex(token_hex.as_str()))
        .transpose()?;
    let (mutex, _) = &**shared;
    let mut state = lock_state(mutex);
    let scope = state
        .registry
        .resolve(token.as_ref(), access.tty.as_deref(), Some(caller))?;
    drop(state);
    Ok((scope, key))
}

fn await_approval(shared: &Shared, scope: &Scope, key: &SecretName, force_fresh: bool) -> Approval {
    let (mutex, condvar) = &**shared;
    let mut state = lock_state(mutex);
    if let Some((_, source, identity)) = state.grants.lookup(scope, key) {
        let source = source.to_owned();
        let identity = identity.clone();
        if state
            .store
            .identity(key)
            .is_ok_and(|current| current == identity)
        {
            if force_fresh {
                state.grants.revoke(scope, key);
            } else {
                drop(state);
                return Approval::Granted {
                    source: Some(source),
                    request_id: None,
                };
            }
        } else {
            // Keep the lock while revoking and re-resolving: releasing it would permit
            // a concurrent request to observe cached plaintext after its file changed.
            state.grants.revoke(scope, key);
            tracing::info!(
                key = %key.as_str(),
                source = %sanitize_audit_value(&source),
                "grant invalidated after backing file changed"
            );
        }
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
    force_fresh: bool,
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
    let (outcome, source, request_id) = match await_approval(shared, &scope, &key, force_fresh) {
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
                .map(|(value, _, _)| value)
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
