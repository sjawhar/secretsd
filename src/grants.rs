//! Who is asking, and what they are allowed to see.
//!
//! Authorization inputs are the presented token (verified) and the caller's
//! tty. A claimed session identifier is never an authorization input.

use std::time::{Duration, Instant};

use subtle::ConstantTimeEq;

use crate::proto::ErrCode;
use crate::secret::{SecretBytes, SecretName};

/// Length of a session token in bytes.
const TOKEN_LEN: usize = 32;

/// An unguessable per-session bearer token issued by trusted harness code.
#[derive(Clone, Copy)]
pub struct SessionToken([u8; TOKEN_LEN]);

impl SessionToken {
    /// Parse a 64-character lowercase or uppercase hex string.
    pub fn parse_hex(text: &str) -> Result<Self, ErrCode> {
        if text.len() != TOKEN_LEN * 2 {
            return Err(ErrCode::BadRequest);
        }
        let mut bytes = [0_u8; TOKEN_LEN];
        for (index, slot) in bytes.iter_mut().enumerate() {
            let start = index.checked_mul(2).ok_or(ErrCode::BadRequest)?;
            let end = start.checked_add(2).ok_or(ErrCode::BadRequest)?;
            let pair = text.get(start..end).ok_or(ErrCode::BadRequest)?;
            *slot = u8::from_str_radix(pair, 16).map_err(|_| ErrCode::BadRequest)?;
        }
        Ok(Self(bytes))
    }
}

impl PartialEq for SessionToken {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for SessionToken {}

impl std::fmt::Debug for SessionToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SessionToken(<redacted>)")
    }
}

/// What a grant belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Scope {
    /// A harness session proven by its token.
    Session(SessionToken),
    /// A human at an interactive terminal.
    Tty {
        /// Controlling terminal device path.
        tty: String,
        /// Kernel boot identity captured when the daemon started.
        boot_id: String,
    },
}

/// Coarse classification for a grant scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScopeKind {
    /// Token was presented and verified.
    VerifiedSession,
    /// No token; scoped to a terminal.
    TokenlessTty,
}

impl Scope {
    /// Classify this scope.
    pub const fn kind(&self) -> ScopeKind {
        match self {
            Self::Session(_) => ScopeKind::VerifiedSession,
            Self::Tty { .. } => ScopeKind::TokenlessTty,
        }
    }
}

/// A registered harness session.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Registration {
    /// Token issued for this session.
    pub token: SessionToken,
    /// Harness-supplied identifier. Untrusted; logging and display only.
    pub session: String,
    /// Kernel-pinned identity of the process that registered this session.
    ///
    /// Captured from the connection rather than taken from the wire, so requests
    /// can be checked against the session's real process tree.
    pub root: crate::peer::PeerIdentity,
}

/// Known sessions and learned agent terminals.
#[derive(Debug)]
pub struct Registry {
    sessions: Vec<Registration>,
    agent_ttys: Vec<String>,
    boot_id: String,
}

impl Default for Registry {
    fn default() -> Self {
        Self::new("test-boot".to_owned())
    }
}

impl Registry {
    /// Build a registry bound to one kernel boot.
    pub const fn new(boot_id: String) -> Self {
        Self {
            sessions: Vec::new(),
            agent_ttys: Vec::new(),
            boot_id,
        }
    }
    /// Record a session token, returning any *different* token previously bound
    /// to this session, whose grants must be revoked.
    ///
    /// Re-presenting a session's current token is a **no-op**: the existing
    /// registration is kept, including the kernel-pinned root it was created
    /// with. Replacing the root here instead would hand a same-uid caller that
    /// read the token file a way to become the root of a session that already
    /// holds grants, inheriting them with no touch -- defeating the ancestry
    /// check that contains callers outside the session's process tree. It also
    /// keeps `sessions` in insertion order, so a re-registration cannot move an
    /// entry behind a colliding one and change which root `resolve` finds.
    ///
    /// A token already bound to a *different* session is refused: a token
    /// identifies exactly one session, and two bindings would make the lookup
    /// in `resolve` order-dependent.
    pub fn register(&mut self, registration: Registration) -> Result<Vec<SessionToken>, ErrCode> {
        if self
            .sessions
            .iter()
            .any(|existing| existing.token == registration.token)
        {
            return if self.sessions.iter().any(|existing| {
                existing.token == registration.token && existing.session == registration.session
            }) {
                Ok(Vec::new())
            } else {
                Err(ErrCode::BadRequest)
            };
        }
        let displaced = self
            .sessions
            .iter()
            .filter(|existing| existing.session == registration.session)
            .map(|existing| existing.token)
            .collect();
        self.sessions
            .retain(|existing| existing.session != registration.session);
        self.sessions.push(registration);
        Ok(displaced)
    }

    /// Forget a session, returning the tokens whose grants must be revoked.
    pub fn unregister(&mut self, session: &str) -> Vec<SessionToken> {
        let revoked: Vec<SessionToken> = self
            .sessions
            .iter()
            .filter(|entry| entry.session == session)
            .map(|entry| entry.token)
            .collect();
        self.sessions.retain(|entry| entry.session != session);
        revoked
    }

    /// Find the untrusted registration associated with a verified token.
    pub fn registration(&self, token: &SessionToken) -> Option<&Registration> {
        self.sessions.iter().find(|entry| entry.token == *token)
    }

    /// Whether a terminal has been seen carrying agent traffic.
    pub fn is_agent_tty(&self, tty: &str) -> bool {
        self.agent_ttys.iter().any(|known| known == tty)
    }

    /// Determine the scope of a request, or why it has none.
    pub fn resolve(
        &mut self,
        token: Option<&SessionToken>,
        tty: Option<&str>,
        caller: Option<&crate::peer::PeerIdentity>,
    ) -> Result<Scope, ErrCode> {
        match token {
            Some(presented) => {
                let Some(root) = self
                    .sessions
                    .iter()
                    .find(|entry| entry.token == *presented)
                    .map(|entry| entry.root.clone())
                else {
                    return Err(ErrCode::UnknownToken);
                };
                // The token says which session, not that this caller belongs to
                // it: every process sharing the uid can read the token file.
                // Require the caller to sit inside that session's process tree,
                // and refuse outright instead of degrading to a tty scope, which
                // a caller could otherwise obtain just by allocating a pty.
                if !caller.is_some_and(|caller| caller.descends_from(&root)) {
                    return Err(ErrCode::ForeignCaller);
                }
                if let Some(tty) = tty
                    && !self.is_agent_tty(tty)
                {
                    self.agent_ttys.push(tty.to_owned());
                }
                Ok(Scope::Session(*presented))
            }
            None => match tty {
                Some(tty) if self.is_agent_tty(tty) => Err(ErrCode::AgentTty),
                Some(tty) => Ok(Scope::Tty {
                    tty: tty.to_owned(),
                    boot_id: self.boot_id.clone(),
                }),
                None => Err(ErrCode::NoScope),
            },
        }
    }
}

#[derive(Debug)]
struct Grant {
    scope: Scope,
    key: SecretName,
    value: SecretBytes,
    source: String,
    created: Instant,
}

/// Live grants. Dropping a grant zeroizes its value.
#[derive(Debug, Default)]
pub struct GrantTable {
    grants: Vec<Grant>,
}

impl GrantTable {
    /// Find a live grant.
    pub fn lookup(&self, scope: &Scope, key: &SecretName) -> Option<(&SecretBytes, &str)> {
        self.grants
            .iter()
            .find(|grant| grant.scope == *scope && grant.key == *key)
            .map(|grant| (&grant.value, grant.source.as_str()))
    }

    /// Install a grant, replacing any existing one for the same scope and key.
    pub fn insert(
        &mut self,
        scope: Scope,
        key: SecretName,
        value: SecretBytes,
        created: Instant,
        source: String,
    ) {
        self.grants
            .retain(|grant| !(grant.scope == scope && grant.key == key));
        self.grants.push(Grant {
            scope,
            key,
            value,
            source,
            created,
        });
    }

    /// Revoke every grant belonging to a scope.
    pub fn revoke_scope(&mut self, scope: &Scope) {
        self.grants.retain(|grant| grant.scope != *scope);
    }

    /// Revoke every grant belonging to any of these session tokens.
    pub fn revoke_tokens(&mut self, tokens: &[SessionToken]) {
        self.grants.retain(|grant| match &grant.scope {
            Scope::Session(token) => !tokens.contains(token),
            Scope::Tty { .. } => true,
        });
    }

    /// Revoke grants older than `max_age`, returning how many were removed.
    pub fn revoke_expired(&mut self, now: Instant, max_age: Duration) -> usize {
        let before = self.grants.len();
        self.grants
            .retain(|grant| now.duration_since(grant.created) < max_age);
        before.saturating_sub(self.grants.len())
    }

    /// Revoke everything.
    pub fn revoke_all(&mut self) {
        self.grants.clear();
    }

    /// Revoke tokenless grants whose terminal device vanished.
    pub fn revoke_missing_ttys(&mut self) {
        self.grants.retain(|grant| match &grant.scope {
            Scope::Session(_) => true,
            Scope::Tty { tty, .. } => std::path::Path::new(tty).exists(),
        });
    }

    /// Whether any grant is live.
    pub const fn is_empty(&self) -> bool {
        self.grants.is_empty()
    }

    /// Human-readable listing. Never includes secret values.
    pub fn render(&self, now: Instant) -> String {
        if self.grants.is_empty() {
            return "no active grants\n".to_owned();
        }
        let mut out = String::from("KEY\tSCOPE\tAGE\n");
        for grant in &self.grants {
            let scope = match &grant.scope {
                Scope::Session(_) => "session".to_owned(),
                Scope::Tty { tty, .. } => format!("tty {tty}"),
            };
            let age = now.duration_since(grant.created).as_secs();
            out.push_str(grant.key.as_str());
            out.push('\t');
            out.push_str(&scope);
            out.push('\t');
            out.push_str(&age.to_string());
            out.push_str("s\n");
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;

    fn token(byte: u8) -> SessionToken {
        SessionToken::parse_hex(&format!("{byte:02x}").repeat(32)).unwrap()
    }

    fn name(raw: &str) -> SecretName {
        SecretName::parse(raw).unwrap()
    }

    fn secret(raw: &str) -> SecretBytes {
        SecretBytes::from_vec(raw.as_bytes().to_vec())
    }

    #[test]
    fn lookup_returns_the_grant_source_label() {
        // Given: a grant associated with the source file that supplied its plaintext.
        let mut table = GrantTable::default();
        let scope = Scope::Session(token(0xaa));
        let key = name("K");
        table.insert(
            scope.clone(),
            key.clone(),
            secret("v"),
            Instant::now(),
            "test.local".to_owned(),
        );

        // When: the grant is looked up for a repeat request.
        let (_, source) = table.lookup(&scope, &key).unwrap();

        // Then: the label identifies the file that supplied the cached plaintext.
        assert_eq!(source, "test.local");
    }

    #[test]
    fn replacing_a_grant_replaces_its_source_label() {
        // Given: a cached grant sourced from one human file.
        let mut table = GrantTable::default();
        let scope = Scope::Session(token(0xaa));
        let key = name("K");
        table.insert(
            scope.clone(),
            key.clone(),
            secret("first"),
            Instant::now(),
            "test".to_owned(),
        );

        // When: a fresh grant replaces it after decrypting a differently labeled source.
        table.insert(
            scope.clone(),
            key.clone(),
            secret("second"),
            Instant::now(),
            "test.local".to_owned(),
        );

        // Then: repeat access observes the replacement's source label.
        let (_, source) = table.lookup(&scope, &key).unwrap();
        assert_eq!(source, "test.local");
    }

    fn registered() -> Registry {
        let mut registry = Registry::default();
        registry
            .register(Registration {
                token: token(0xaa),
                session: "ses_a".to_owned(),
                root: crate::peer::PeerIdentity::current_for_test(),
            })
            .unwrap();
        registry
    }

    #[test]
    fn rejects_malformed_token_hex() {
        assert_eq!(SessionToken::parse_hex("nothex"), Err(ErrCode::BadRequest));
        assert_eq!(SessionToken::parse_hex("aabb"), Err(ErrCode::BadRequest));
    }

    #[test]
    fn token_debug_never_reveals_raw_or_hex_bytes() {
        let rendered = format!("{:?}", token(0xaa));
        assert!(!rendered.contains("aa"), "leaked token hex: {rendered}");
        assert!(!rendered.contains('ª'), "leaked token bytes: {rendered}");
        assert!(rendered.contains("redacted"));
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn resolves_registered_token_to_session_scope() {
        let mut registry = registered();
        let scope = registry
            .resolve(
                Some(&token(0xaa)),
                Some("/dev/pts/3"),
                Some(&crate::peer::PeerIdentity::current_for_test()),
            )
            .unwrap();
        assert_eq!(scope.kind(), ScopeKind::VerifiedSession);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn rejects_unregistered_token() {
        let mut registry = registered();
        assert_eq!(
            registry
                .resolve(
                    Some(&token(0xbb)),
                    Some("/dev/pts/3"),
                    Some(&crate::peer::PeerIdentity::current_for_test())
                )
                .err(),
            Some(ErrCode::UnknownToken)
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn unknown_token_never_falls_back_to_tokenless() {
        // A stale token (broker restarted, session did not re-register) must be
        // a hard identity error -- silently degrading to a tty scope would let
        // an env-stripped agent launder itself into the interactive path.
        let mut registry = registered();
        let err = registry
            .resolve(
                Some(&token(0xcc)),
                Some("/dev/pts/9"),
                Some(&crate::peer::PeerIdentity::current_for_test()),
            )
            .err();
        assert_eq!(err, Some(ErrCode::UnknownToken));
        assert!(!registry.is_agent_tty("/dev/pts/9"));
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn tokenless_request_from_fresh_tty_is_interactive() {
        let mut registry = registered();
        let scope = registry
            .resolve(
                None,
                Some("/dev/pts/7"),
                Some(&crate::peer::PeerIdentity::current_for_test()),
            )
            .unwrap();
        assert_eq!(scope.kind(), ScopeKind::TokenlessTty);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn tokenless_request_from_learned_agent_tty_is_rejected() {
        let mut registry = registered();
        registry
            .resolve(
                Some(&token(0xaa)),
                Some("/dev/pts/3"),
                Some(&crate::peer::PeerIdentity::current_for_test()),
            )
            .unwrap();
        assert!(registry.is_agent_tty("/dev/pts/3"));
        assert_eq!(
            registry
                .resolve(
                    None,
                    Some("/dev/pts/3"),
                    Some(&crate::peer::PeerIdentity::current_for_test())
                )
                .err(),
            Some(ErrCode::AgentTty)
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn request_without_token_or_tty_has_no_scope() {
        let mut registry = registered();
        assert_eq!(
            registry
                .resolve(
                    None,
                    None,
                    Some(&crate::peer::PeerIdentity::current_for_test())
                )
                .err(),
            Some(ErrCode::NoScope)
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn unregister_returns_tokens_to_revoke() {
        let mut registry = registered();
        let revoked = registry.unregister("ses_a");
        assert_eq!(revoked, vec![token(0xaa)]);
        assert_eq!(
            registry
                .resolve(
                    Some(&token(0xaa)),
                    None,
                    Some(&crate::peer::PeerIdentity::current_for_test())
                )
                .err(),
            Some(ErrCode::UnknownToken)
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn replacing_a_session_revokes_its_displaced_token_grants_from_the_table() {
        // Given: a session and a grant associated with its original token.
        let mut registry = Registry::default();
        let mut table = GrantTable::default();
        let original = token(0xaa);
        registry
            .register(Registration {
                token: original,
                session: "ses_a".to_owned(),
                root: crate::peer::PeerIdentity::current_for_test(),
            })
            .unwrap();
        table.insert(
            Scope::Session(original),
            name("K"),
            secret("v"),
            Instant::now(),
            "test".to_owned(),
        );

        // When: the same session identifier is registered with a new token.
        let displaced = registry
            .register(Registration {
                token: token(0xbb),
                session: "ses_a".to_owned(),
                root: crate::peer::PeerIdentity::current_for_test(),
            })
            .unwrap();
        table.revoke_tokens(&displaced);

        // Then: the old token's plaintext grant was removed, not merely hidden.
        assert!(
            table.grants.is_empty(),
            "replacing a session left its displaced token grant in the table"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn re_registering_same_token_keeps_its_grants() {
        // Re-affirming a session with its own current token -- what the plugin
        // does to recover a registration the broker lost on restart -- must not
        // revoke the grants that token already holds. Only a genuine token change
        // displaces (see the test above); the same token is idempotent.
        let mut registry = Registry::default();
        let mut table = GrantTable::default();
        let token = token(0xaa);
        registry
            .register(Registration {
                token,
                session: "ses_a".to_owned(),
                root: crate::peer::PeerIdentity::current_for_test(),
            })
            .unwrap();
        table.insert(
            Scope::Session(token),
            name("K"),
            secret("v"),
            Instant::now(),
            "test".to_owned(),
        );

        // When: the same session re-registers with the identical token.
        let displaced = registry
            .register(Registration {
                token,
                session: "ses_a".to_owned(),
                root: crate::peer::PeerIdentity::current_for_test(),
            })
            .unwrap();
        table.revoke_tokens(&displaced);

        // Then: nothing was displaced and the live grant survived.
        assert!(
            displaced.is_empty(),
            "re-registering a session's own token displaced it"
        );
        assert!(
            table.lookup(&Scope::Session(token), &name("K")).is_some(),
            "re-registering a session's own token dropped its grant"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn re_registering_a_live_token_keeps_the_root_it_was_pinned_to() {
        // A same-uid caller can read a session's token file -- that is an
        // accepted residual -- so REGISTER must never let it become the root of a
        // session that already holds grants. Were the root replaced here, the
        // ancestry check would then pass for that caller and hand it the grant
        // with no touch, defeating the containment FOREIGN_CALLER provides.
        let mut registry = Registry::default();
        let token = token(0xaa);
        registry
            .register(Registration {
                token,
                session: "ses_a".to_owned(),
                root: crate::peer::PeerIdentity::current_for_test(),
            })
            .unwrap();

        // When: the same session and token are presented again.
        registry
            .register(Registration {
                token,
                session: "ses_a".to_owned(),
                root: crate::peer::PeerIdentity::current_for_test(),
            })
            .unwrap();

        // Then: exactly one registration survives, so no second binding can
        // shadow it, and its root is the one the first REGISTER pinned.
        assert_eq!(registry.sessions.len(), 1);
        assert_eq!(
            registry
                .registration(&token)
                .map(|entry| entry.session.clone()),
            Some("ses_a".to_owned())
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn refuses_a_token_already_bound_to_another_session() {
        // One token names exactly one session. Allowing a second binding would
        // make `resolve`'s lookup order-dependent, so a caller that read the
        // token file could register it under a name of its own and race to be
        // the entry that `find` returns.
        let mut registry = Registry::default();
        let token = token(0xaa);
        registry
            .register(Registration {
                token,
                session: "ses_a".to_owned(),
                root: crate::peer::PeerIdentity::current_for_test(),
            })
            .unwrap();

        let refused = registry.register(Registration {
            token,
            session: "ses_impostor".to_owned(),
            root: crate::peer::PeerIdentity::current_for_test(),
        });

        assert_eq!(refused.err(), Some(ErrCode::BadRequest));
        assert_eq!(registry.sessions.len(), 1);
        assert_eq!(
            registry
                .registration(&token)
                .map(|entry| entry.session.clone()),
            Some("ses_a".to_owned())
        );
    }

    #[test]
    fn grants_are_isolated_between_sessions() {
        let mut table = GrantTable::default();
        let now = Instant::now();
        let scope_a = Scope::Session(token(0xaa));
        let scope_b = Scope::Session(token(0xbb));
        table.insert(
            scope_a.clone(),
            name("K"),
            secret("v"),
            now,
            "test".to_owned(),
        );

        assert_eq!(
            table
                .lookup(&scope_a, &name("K"))
                .map(|(value, _)| value.as_slice()),
            Some(&b"v"[..])
        );
        assert!(
            table.lookup(&scope_b, &name("K")).is_none(),
            "sibling session inherited a grant"
        );
    }

    #[test]
    fn tty_grants_are_not_shared_across_boot_ids() {
        let mut table = GrantTable::default();
        let now = Instant::now();
        let first = Scope::Tty {
            tty: "/dev/pts/3".to_owned(),
            boot_id: "first-boot".to_owned(),
        };
        let second = Scope::Tty {
            tty: "/dev/pts/3".to_owned(),
            boot_id: "second-boot".to_owned(),
        };
        table.insert(
            first.clone(),
            name("K"),
            secret("v"),
            now,
            "test".to_owned(),
        );

        assert_ne!(first, second);
        assert!(table.lookup(&second, &name("K")).is_none());
    }

    #[test]
    fn revoking_tokens_drops_their_grants() {
        let mut table = GrantTable::default();
        let now = Instant::now();
        table.insert(
            Scope::Session(token(0xaa)),
            name("K"),
            secret("v"),
            now,
            "test".to_owned(),
        );
        table.revoke_tokens(&[token(0xaa)]);
        assert!(table.is_empty());
    }

    #[test]
    fn backstop_expires_old_grants_only() {
        let mut table = GrantTable::default();
        let now = Instant::now();
        let old = now.checked_sub(Duration::from_hours(13)).unwrap();
        table.insert(
            Scope::Session(token(0xaa)),
            name("OLD"),
            secret("v"),
            old,
            "test".to_owned(),
        );
        table.insert(
            Scope::Session(token(0xbb)),
            name("NEW"),
            secret("v"),
            now,
            "test".to_owned(),
        );

        let removed = table.revoke_expired(now, Duration::from_hours(12));
        assert_eq!(removed, 1);
        assert!(
            table
                .lookup(&Scope::Session(token(0xbb)), &name("NEW"))
                .is_some()
        );
        assert!(
            table
                .lookup(&Scope::Session(token(0xaa)), &name("OLD"))
                .is_none()
        );
    }

    #[test]
    fn lock_revokes_everything() {
        let mut table = GrantTable::default();
        let now = Instant::now();
        table.insert(
            Scope::Session(token(0xaa)),
            name("K"),
            secret("v"),
            now,
            "test".to_owned(),
        );
        table.revoke_all();
        assert!(table.is_empty());
    }

    #[test]
    fn render_never_includes_secret_values() {
        let mut table = GrantTable::default();
        let now = Instant::now();
        table.insert(
            Scope::Session(token(0xaa)),
            name("K"),
            secret("super-secret"),
            now,
            "test".to_owned(),
        );
        let rendered = table.render(now);
        assert!(rendered.contains('K'));
        assert!(
            !rendered.contains("super-secret"),
            "grant listing leaked a value"
        );
    }
}
