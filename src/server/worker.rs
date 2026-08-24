use std::sync::Arc;
use std::time::{Duration, Instant};

use super::{Shared, lock_state, wait_state};
use crate::audit::sanitize_audit_value;
use crate::decrypt::Decryptor;
use crate::grants::{GrantOrigin, Scope};
use crate::requests::RequestId;
use crate::secret::SecretName;
use crate::store::HumanStore;

#[derive(Debug)]
struct Job {
    id: RequestId,
    scope: Scope,
    key: SecretName,
    generation: u64,
    lock_epoch: u64,
    store: HumanStore,
    decryptor: Decryptor,
}

#[allow(
    clippy::too_many_lines,
    reason = "one worker owns the security-sensitive approval lifecycle"
)]
pub(super) fn worker(shared: &Shared) {
    loop {
        let job = {
            let (mutex, condvar) = &**shared;
            let mut state = lock_state(mutex);
            let now = Instant::now();
            let max_grant = state.config.max_grant;
            let expired = state.queue.sweep_timeouts(now);
            for id in expired {
                state.kill_active(id);
            }
            state.grants.revoke_expired(now, max_grant);
            state.grants.revoke_missing_ttys();
            state.queue.prune(now);
            state.receipts.sweep(now);
            let failures = std::mem::take(&mut state.failures);
            state.failures = failures
                .into_iter()
                .filter(|(id, _)| state.queue.state_of(*id).is_some())
                .collect();
            let Some(id) = state.queue.next_ready(now) else {
                drop(wait_state(condvar, state, Duration::from_millis(100)));
                continue;
            };
            let Some(generation) = state.queue.mark_decrypting(id, now) else {
                continue;
            };
            let Some((scope, key)) = state.queue.describe(id) else {
                state.queue.fail(id, now);
                condvar.notify_all();
                continue;
            };
            Job {
                id,
                scope,
                key,
                generation,
                lock_epoch: state.lock_epoch,
                store: state.store.clone(),
                decryptor: state.decryptor.clone(),
            }
        };
        let shared_for_start = Arc::clone(shared);
        let decrypted =
            job.decryptor
                .decrypt_opened_with_start(&job.store, &job.key, move |process_group| {
                    let (mutex, _) = &*shared_for_start;
                    let mut state = lock_state(mutex);
                    if state.queue.state_of(job.id)
                        == Some(crate::requests::RequestState::Decrypting)
                    {
                        state.active_decrypt = Some(super::ActiveDecrypt {
                            id: job.id,
                            process_group,
                        });
                        drop(state);
                    } else {
                        let _ = nix::sys::signal::killpg(
                            nix::unistd::Pid::from_raw(process_group),
                            nix::sys::signal::Signal::SIGKILL,
                        );
                    }
                });
        let (mutex, condvar) = &**shared;
        let mut state = lock_state(mutex);
        state.kill_active(job.id);
        match decrypted {
            Ok(decrypted) => {
                let session_is_active = match &job.scope {
                    Scope::Session(token) => state
                        .registry
                        .registration(token)
                        // A session whose root process is gone cannot receive
                        // the value, so the approval is dropped rather than
                        // waiting for the backstop to expire it.
                        .is_some_and(|registration| registration.root.is_alive()),
                    Scope::Tty { tty, .. } => std::path::Path::new(tty).exists(),
                };
                if state.lock_epoch != job.lock_epoch || !session_is_active {
                    state.queue.deny(job.id);
                }
                if state.queue.complete(job.id, job.generation, Instant::now()) {
                    state.grants.insert(
                        job.scope,
                        job.key,
                        decrypted.value,
                        Instant::now(),
                        GrantOrigin {
                            source: decrypted.source.clone(),
                            identity: decrypted.identity,
                        },
                    );
                    tracing::info!(
                        source = %sanitize_audit_value(&decrypted.source),
                        request_id = ?job.id,
                        "grant inserted"
                    );
                }
            }
            Err(error) => {
                state.queue.fail(job.id, Instant::now());
                state.failures.push((job.id, error));
            }
        }
        drop(state);
        condvar.notify_all();
    }
}
