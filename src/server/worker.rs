use std::sync::Arc;
use std::time::{Duration, Instant};

use super::{Shared, lock_state, wait_state};
use crate::announce::{Announcement, Announcer};
use crate::decrypt::Decryptor;
use crate::grants::Scope;
use crate::proto::ErrCode;
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
    announcer: Arc<Announcer>,
    untrusted_session: Option<String>,
    untrusted_cmdline: Option<String>,
}

fn request_metadata(state: &super::State, scope: &Scope) -> (Option<String>, Option<String>) {
    match scope {
        Scope::Session(token) => state.registry.registration(token).map_or_else(
            || (None, None),
            |registration| {
                (
                    Some(registration.session.clone()),
                    Some(format!("pid {}", registration.pid)),
                )
            },
        ),
        Scope::Tty { .. } => (None, None),
    }
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
            let (untrusted_session, untrusted_cmdline) = request_metadata(&state, &scope);
            Job {
                id,
                scope,
                key,
                generation,
                lock_epoch: state.lock_epoch,
                store: state.store.clone(),
                decryptor: state.decryptor.clone(),
                announcer: Arc::clone(&state.announcer),
                untrusted_session,
                untrusted_cmdline,
            }
        };
        let announcement = Announcement {
            request_id: job.id,
            key: job.key.clone(),
            scope_kind: job.scope.kind(),
            untrusted_session: job.untrusted_session,
            untrusted_cmdline: job.untrusted_cmdline,
        };
        if !job.announcer.announce(&announcement) {
            fail_request(shared, job.id, ErrCode::NotAnnounced);
            continue;
        }
        let shared_for_start = Arc::clone(shared);
        let decrypted =
            job.decryptor
                .decrypt_with_start(&job.store, &job.key, move |process_group| {
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
            Ok(value) => {
                let session_is_active = match &job.scope {
                    Scope::Session(token) => state.registry.resolve(Some(token), None).is_ok(),
                    Scope::Tty { tty, .. } => std::path::Path::new(tty).exists(),
                };
                if state.lock_epoch != job.lock_epoch || !session_is_active {
                    state.queue.deny(job.id);
                }
                if state.queue.complete(job.id, job.generation, Instant::now()) {
                    state
                        .grants
                        .insert(job.scope, job.key, value, Instant::now());
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

fn fail_request(shared: &Shared, id: RequestId, error: ErrCode) {
    let (mutex, condvar) = &**shared;
    let mut state = lock_state(mutex);
    state.queue.fail(id, Instant::now());
    state.failures.push((id, error));
    drop(state);
    condvar.notify_all();
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::Duration;

    use super::*;
    use crate::Config;
    use crate::announce::render;
    use crate::grants::{Registration, SessionToken};

    fn test_config() -> Config {
        Config {
            socket_path: PathBuf::from("/tmp/secretsd-worker-test.sock"),
            human_dir: PathBuf::from("/tmp/secretsd-worker-test-human"),
            sops_bin: PathBuf::from("sops"),
            pcsc_socket: None,
            yubikey_probe_argv: Vec::new(),
            notify_argv: Vec::new(),
            envoy_argv: Vec::new(),
            max_grant: Duration::from_secs(43_200),
            cooldown: Duration::from_secs(16),
            request_ttl: Duration::from_secs(90),
            max_pending_per_scope: 2,
        }
    }

    #[test]
    fn announcement_includes_untrusted_metadata_when_session_token_is_registered() {
        let token = SessionToken::parse_hex(&"aa".repeat(32)).unwrap();
        let mut state = super::super::State::new(test_config()).unwrap();
        state.registry.register(Registration {
            token,
            session: "ses-review-regression".to_owned(),
            pid: 42,
        });
        let scope = Scope::Session(token);
        let (untrusted_session, untrusted_cmdline) = request_metadata(&state, &scope);

        let text = render(&Announcement {
            request_id: RequestId(1),
            key: SecretName::parse("DEEL_API_KEY").unwrap(),
            scope_kind: scope.kind(),
            untrusted_session,
            untrusted_cmdline,
        });

        assert!(
            text.contains("ses-review-regression"),
            "missing session: {text}"
        );
        assert!(text.contains("unverified"), "missing label: {text}");
    }

    #[test]
    fn announcement_renders_tokenless_when_request_has_no_session_token() {
        let state = super::super::State::new(test_config()).unwrap();
        let scope = Scope::Tty {
            tty: "/dev/pts/42".to_owned(),
            boot_id: "test-boot-id".to_owned(),
        };
        let (untrusted_session, untrusted_cmdline) = request_metadata(&state, &scope);

        let text = render(&Announcement {
            request_id: RequestId(2),
            key: SecretName::parse("DEEL_API_KEY").unwrap(),
            scope_kind: scope.kind(),
            untrusted_session,
            untrusted_cmdline,
        });

        assert!(text.contains("TOKENLESS"), "missing warning: {text}");
    }
}
