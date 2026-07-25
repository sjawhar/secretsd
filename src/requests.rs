//! Pending approval requests and the single-flight hardware queue.

use std::time::{Duration, Instant};

use crate::grants::Scope;
use crate::proto::ErrCode;
use crate::secret::SecretName;

/// Source of monotonic time, injectable for tests.
pub trait Clock: Send + Sync {
    /// Current instant.
    fn now(&self) -> Instant;
}

/// Real time.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// Identifier for a pending hardware-gated request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub struct RequestId(pub u64);

/// Lifecycle of one approval request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RequestState {
    /// Waiting for its turn at the hardware.
    Pending,
    /// A decrypt is running for this request.
    Decrypting,
    /// Completed successfully; a grant was installed.
    Granted,
    /// A human denied it.
    Denied,
    /// It expired before approval.
    TimedOut,
    /// Decryption failed.
    Failed,
}

/// Tunables for the queue.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct QueueLimits {
    /// Minimum gap between decrypts; must exceed the PIV touch cache.
    pub cooldown: Duration,
    /// How long a request may wait for approval.
    pub ttl: Duration,
    /// Concurrent pending requests allowed per scope.
    pub max_pending_per_scope: usize,
}

#[derive(Debug)]
struct PendingRequest {
    id: RequestId,
    scope: Scope,
    key: SecretName,
    state: RequestState,
    generation: u64,
    created: Instant,
}

/// The approval queue. Exactly one decrypt may be in flight.
#[derive(Debug)]
pub struct Queue {
    requests: Vec<PendingRequest>,
    limits: QueueLimits,
    next_id: u64,
    generation: u64,
    inflight: Option<RequestId>,
    last_finished: Option<Instant>,
}

impl Queue {
    /// Build an empty queue.
    pub const fn new(limits: QueueLimits) -> Self {
        Self {
            requests: Vec::new(),
            limits,
            next_id: 1,
            generation: 0,
            inflight: None,
            last_finished: None,
        }
    }

    /// Add a request, coalescing an identical pending one.
    pub fn enqueue(
        &mut self,
        scope: Scope,
        key: SecretName,
        now: Instant,
    ) -> Result<RequestId, ErrCode> {
        if let Some(existing) = self.requests.iter().find(|request| {
            request.scope == scope
                && request.key == key
                && matches!(
                    request.state,
                    RequestState::Pending | RequestState::Decrypting
                )
        }) {
            return Ok(existing.id);
        }
        let active = self
            .requests
            .iter()
            .filter(|request| {
                request.scope == scope
                    && matches!(
                        request.state,
                        RequestState::Pending | RequestState::Decrypting
                    )
            })
            .count();
        if active >= self.limits.max_pending_per_scope {
            return Err(ErrCode::TooManyPending);
        }
        let id = RequestId(self.next_id);
        self.next_id = self.next_id.saturating_add(1);
        self.requests.push(PendingRequest {
            id,
            scope,
            key,
            state: RequestState::Pending,
            generation: 0,
            created: now,
        });
        Ok(id)
    }

    /// The next request eligible to touch the hardware, if any.
    pub fn next_ready(&self, now: Instant) -> Option<RequestId> {
        if self.inflight.is_some() {
            return None;
        }
        if let Some(last) = self.last_finished
            && now
                .checked_duration_since(last)
                .is_some_and(|elapsed| elapsed < self.limits.cooldown)
        {
            return None;
        }
        self.requests
            .iter()
            .find(|request| request.state == RequestState::Pending)
            .map(|request| request.id)
    }

    /// Mark a request as decrypting, returning its generation.
    pub fn mark_decrypting(&mut self, id: RequestId, now: Instant) -> Option<u64> {
        if self.inflight.is_some()
            || self.last_finished.is_some_and(|last| {
                now.checked_duration_since(last)
                    .is_some_and(|elapsed| elapsed < self.limits.cooldown)
            })
        {
            return None;
        }
        let request = self.requests.iter_mut().find(|request| request.id == id)?;
        if request.state != RequestState::Pending {
            return None;
        }
        self.generation = self.generation.saturating_add(1);
        let generation = self.generation;
        request.state = RequestState::Decrypting;
        request.generation = generation;
        self.inflight = Some(id);
        Some(generation)
    }

    /// Whether a completing decrypt may still install its grant.
    pub fn complete(&mut self, id: RequestId, generation: u64, now: Instant) -> bool {
        let still_current = self.requests.iter().any(|request| {
            request.id == id
                && request.generation == generation
                && request.state == RequestState::Decrypting
        });
        if still_current
            && let Some(request) = self.requests.iter_mut().find(|request| request.id == id)
        {
            request.state = RequestState::Granted;
        }
        self.finish(id, now);
        still_current
    }

    /// Release the hardware and start the cooldown.
    pub fn finish(&mut self, id: RequestId, now: Instant) {
        if self.inflight == Some(id) {
            self.inflight = None;
        }
        self.last_finished = Some(now);
    }

    /// Mark a decrypt as failed.
    pub fn fail(&mut self, id: RequestId, now: Instant) {
        if let Some(request) = self.requests.iter_mut().find(|request| request.id == id) {
            request.state = RequestState::Failed;
        }
        self.finish(id, now);
    }

    /// Expire a request and invalidate any decrypt that already started.
    pub fn timeout(&mut self, id: RequestId, now: Instant) -> bool {
        let Some(request) = self.requests.iter_mut().find(|request| request.id == id) else {
            return false;
        };
        match request.state {
            RequestState::Pending | RequestState::Decrypting => {
                request.state = RequestState::TimedOut;
                request.generation = request.generation.saturating_add(1);
                self.finish(id, now);
                true
            }
            RequestState::Granted
            | RequestState::Denied
            | RequestState::TimedOut
            | RequestState::Failed => false,
        }
    }

    /// Reject a pending request.
    pub fn deny(&mut self, id: RequestId) -> bool {
        let Some(request) = self.requests.iter_mut().find(|request| request.id == id) else {
            return false;
        };
        match request.state {
            RequestState::Pending | RequestState::Decrypting => {
                request.state = RequestState::Denied;
                request.generation = request.generation.saturating_add(1);
                self.finish(id, Instant::now());
                true
            }
            RequestState::Granted
            | RequestState::Denied
            | RequestState::TimedOut
            | RequestState::Failed => false,
        }
    }

    /// Expire requests that waited too long.
    pub fn sweep_timeouts(&mut self, now: Instant) -> Vec<RequestId> {
        let ttl = self.limits.ttl;
        let mut expired = Vec::new();
        for request in &mut self.requests {
            if matches!(
                request.state,
                RequestState::Pending | RequestState::Decrypting
            ) && now
                .checked_duration_since(request.created)
                .is_some_and(|elapsed| elapsed > ttl)
            {
                request.state = RequestState::TimedOut;
                request.generation = request.generation.saturating_add(1);
                expired.push(request.id);
            }
        }
        for id in &expired {
            self.finish(*id, now);
        }
        expired
    }

    /// Current state of a request.
    pub fn state_of(&self, id: RequestId) -> Option<RequestState> {
        self.requests
            .iter()
            .find(|request| request.id == id)
            .map(|request| request.state)
    }

    /// Scope and key of a request.
    pub fn describe(&self, id: RequestId) -> Option<(Scope, SecretName)> {
        self.requests
            .iter()
            .find(|request| request.id == id)
            .map(|request| (request.scope.clone(), request.key.clone()))
    }

    /// Whether nothing is pending or in flight.
    pub fn is_idle(&self) -> bool {
        !self.requests.iter().any(|request| {
            matches!(
                request.state,
                RequestState::Pending | RequestState::Decrypting
            )
        })
    }

    /// Drop terminal requests older than twice the TTL, bounding memory.
    pub fn prune(&mut self, now: Instant) {
        let horizon = self.limits.ttl.saturating_mul(2);
        self.requests.retain(|request| {
            matches!(
                request.state,
                RequestState::Pending | RequestState::Decrypting
            ) || now
                .checked_duration_since(request.created)
                .is_some_and(|elapsed| elapsed < horizon)
        });
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;
    use crate::grants::{Scope, SessionToken};
    use crate::secret::SecretName;

    fn scope(byte: u8) -> Scope {
        Scope::Session(SessionToken::parse_hex(&format!("{byte:02x}").repeat(32)).unwrap())
    }

    fn name(raw: &str) -> SecretName {
        SecretName::parse(raw).unwrap()
    }

    fn limits() -> QueueLimits {
        QueueLimits {
            cooldown: Duration::from_secs(16),
            ttl: Duration::from_secs(90),
            max_pending_per_scope: 2,
        }
    }

    #[test]
    fn enqueue_returns_ready_request() {
        let mut queue = Queue::new(limits());
        let now = Instant::now();
        let id = queue.enqueue(scope(0xaa), name("K"), now).unwrap();
        assert_eq!(queue.next_ready(now), Some(id));
    }

    #[test]
    fn duplicate_request_for_same_scope_and_key_is_coalesced() {
        let mut queue = Queue::new(limits());
        let now = Instant::now();
        let first = queue.enqueue(scope(0xaa), name("K"), now).unwrap();
        let second = queue.enqueue(scope(0xaa), name("K"), now).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn same_key_from_different_scope_is_a_separate_request() {
        let mut queue = Queue::new(limits());
        let now = Instant::now();
        let first = queue.enqueue(scope(0xaa), name("K"), now).unwrap();
        let second = queue.enqueue(scope(0xbb), name("K"), now).unwrap();
        assert_ne!(first, second, "one approval must never serve two scopes");
    }

    #[test]
    fn only_one_decrypt_is_in_flight() {
        let mut queue = Queue::new(limits());
        let now = Instant::now();
        let first = queue.enqueue(scope(0xaa), name("K"), now).unwrap();
        queue.enqueue(scope(0xbb), name("J"), now).unwrap();
        queue.mark_decrypting(first, now);
        assert_eq!(
            queue.next_ready(now),
            None,
            "second decrypt started while first in flight"
        );
    }

    #[test]
    fn mark_decrypting_refuses_a_second_inflight_request() {
        let mut queue = Queue::new(limits());
        let now = Instant::now();
        let first = queue.enqueue(scope(0xaa), name("K"), now).unwrap();
        let second = queue.enqueue(scope(0xbb), name("J"), now).unwrap();
        assert!(queue.mark_decrypting(first, now).is_some());
        assert_eq!(queue.mark_decrypting(second, now), None);
    }

    #[test]
    fn cooldown_blocks_the_next_decrypt_until_the_touch_cache_expires() {
        let mut queue = Queue::new(limits());
        let start = Instant::now();
        let first = queue.enqueue(scope(0xaa), name("K"), start).unwrap();
        queue.mark_decrypting(first, start);
        queue.finish(first, start);
        let second = queue.enqueue(scope(0xbb), name("J"), start).unwrap();

        assert_eq!(queue.next_ready(start + Duration::from_secs(10)), None);
        assert_eq!(
            queue.next_ready(start + Duration::from_secs(17)),
            Some(second)
        );
    }

    #[test]
    fn denied_request_is_not_ready_and_reports_denied() {
        let mut queue = Queue::new(limits());
        let now = Instant::now();
        let id = queue.enqueue(scope(0xaa), name("K"), now).unwrap();
        assert!(queue.deny(id));
        assert_eq!(queue.state_of(id), Some(RequestState::Denied));
        assert_eq!(queue.next_ready(now), None);
    }

    #[test]
    fn late_completion_after_deny_is_rejected() {
        let mut queue = Queue::new(limits());
        let now = Instant::now();
        let id = queue.enqueue(scope(0xaa), name("K"), now).unwrap();
        let generation = queue.mark_decrypting(id, now).unwrap();
        queue.deny(id);
        assert!(
            !queue.complete(id, generation, now),
            "a denied request must not install a grant"
        );
    }

    #[test]
    fn pending_limit_per_scope_is_enforced() {
        let mut queue = Queue::new(limits());
        let now = Instant::now();
        queue.enqueue(scope(0xaa), name("A"), now).unwrap();
        queue.enqueue(scope(0xaa), name("B"), now).unwrap();
        assert_eq!(
            queue.enqueue(scope(0xaa), name("C"), now).err(),
            Some(ErrCode::TooManyPending)
        );
    }

    #[test]
    fn flooding_one_scope_does_not_lock_out_another() {
        let mut queue = Queue::new(limits());
        let now = Instant::now();
        queue.enqueue(scope(0xaa), name("A"), now).unwrap();
        queue.enqueue(scope(0xaa), name("B"), now).unwrap();
        assert!(queue.enqueue(scope(0xbb), name("C"), now).is_ok());
    }

    #[test]
    fn expired_requests_are_swept() {
        let mut queue = Queue::new(limits());
        let start = Instant::now();
        let id = queue.enqueue(scope(0xaa), name("K"), start).unwrap();
        let swept = queue.sweep_timeouts(start + Duration::from_secs(91));
        assert_eq!(swept, vec![id]);
        assert_eq!(queue.state_of(id), Some(RequestState::TimedOut));
    }

    #[test]
    fn timed_out_decrypt_rejects_its_old_generation() {
        let mut queue = Queue::new(limits());
        let start = Instant::now();
        let id = queue.enqueue(scope(0xaa), name("K"), start).unwrap();
        let generation = queue.mark_decrypting(id, start).unwrap();

        queue.sweep_timeouts(start + Duration::from_secs(91));

        assert_eq!(queue.state_of(id), Some(RequestState::TimedOut));
        assert!(!queue.complete(id, generation, start + Duration::from_secs(91)));
    }
}
