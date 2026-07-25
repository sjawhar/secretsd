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
    /// Harness process id, displayed as unverified request metadata.
    pub pid: i32,
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
    /// Record a session token, returning displaced tokens whose grants must be revoked.
    pub fn register(&mut self, registration: Registration) -> Vec<SessionToken> {
        let displaced = self
            .sessions
            .iter()
            .filter(|existing| existing.session == registration.session)
            .map(|existing| existing.token)
            .collect();
        self.sessions
            .retain(|existing| existing.session != registration.session);
        self.sessions.push(registration);
        displaced
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
    ) -> Result<Scope, ErrCode> {
        match token {
            Some(presented) => {
                let known = self.sessions.iter().any(|entry| entry.token == *presented);
                if !known {
                    return Err(ErrCode::UnknownToken);
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
    created: Instant,
}

/// Live grants. Dropping a grant zeroizes its value.
#[derive(Debug, Default)]
pub struct GrantTable {
    grants: Vec<Grant>,
}

impl GrantTable {
    /// Find a live grant.
    pub fn lookup(&self, scope: &Scope, key: &SecretName) -> Option<&SecretBytes> {
        self.grants
            .iter()
            .find(|grant| grant.scope == *scope && grant.key == *key)
            .map(|grant| &grant.value)
    }

    /// Install a grant, replacing any existing one for the same scope and key.
    pub fn insert(&mut self, scope: Scope, key: SecretName, value: SecretBytes, created: Instant) {
        self.grants
            .retain(|grant| !(grant.scope == scope && grant.key == key));
        self.grants.push(Grant {
            scope,
            key,
            value,
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

    fn registered() -> Registry {
        let mut registry = Registry::default();
        registry.register(Registration {
            token: token(0xaa),
            session: "ses_a".to_owned(),
            pid: 1234,
        });
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
    fn resolves_registered_token_to_session_scope() {
        let mut registry = registered();
        let scope = registry
            .resolve(Some(&token(0xaa)), Some("/dev/pts/3"))
            .unwrap();
        assert_eq!(scope.kind(), ScopeKind::VerifiedSession);
    }

    #[test]
    fn rejects_unregistered_token() {
        let mut registry = registered();
        assert_eq!(
            registry
                .resolve(Some(&token(0xbb)), Some("/dev/pts/3"))
                .err(),
            Some(ErrCode::UnknownToken)
        );
    }

    #[test]
    fn unknown_token_never_falls_back_to_tokenless() {
        // A stale token (broker restarted, session did not re-register) must be
        // a hard identity error -- silently degrading to a tty scope would let
        // an env-stripped agent launder itself into the interactive path.
        let mut registry = registered();
        let err = registry
            .resolve(Some(&token(0xcc)), Some("/dev/pts/9"))
            .err();
        assert_eq!(err, Some(ErrCode::UnknownToken));
        assert!(!registry.is_agent_tty("/dev/pts/9"));
    }

    #[test]
    fn tokenless_request_from_fresh_tty_is_interactive() {
        let mut registry = registered();
        let scope = registry.resolve(None, Some("/dev/pts/7")).unwrap();
        assert_eq!(scope.kind(), ScopeKind::TokenlessTty);
    }

    #[test]
    fn tokenless_request_from_learned_agent_tty_is_rejected() {
        let mut registry = registered();
        registry
            .resolve(Some(&token(0xaa)), Some("/dev/pts/3"))
            .unwrap();
        assert!(registry.is_agent_tty("/dev/pts/3"));
        assert_eq!(
            registry.resolve(None, Some("/dev/pts/3")).err(),
            Some(ErrCode::AgentTty)
        );
    }

    #[test]
    fn request_without_token_or_tty_has_no_scope() {
        let mut registry = registered();
        assert_eq!(registry.resolve(None, None).err(), Some(ErrCode::NoScope));
    }

    #[test]
    fn unregister_returns_tokens_to_revoke() {
        let mut registry = registered();
        let revoked = registry.unregister("ses_a");
        assert_eq!(revoked, vec![token(0xaa)]);
        assert_eq!(
            registry.resolve(Some(&token(0xaa)), None).err(),
            Some(ErrCode::UnknownToken)
        );
    }

    #[test]
    fn replacing_a_session_revokes_its_displaced_token_grants_from_the_table() {
        // Given: a session and a grant associated with its original token.
        let mut registry = Registry::default();
        let mut table = GrantTable::default();
        let original = token(0xaa);
        registry.register(Registration {
            token: original,
            session: "ses_a".to_owned(),
            pid: 1234,
        });
        table.insert(
            Scope::Session(original),
            name("K"),
            secret("v"),
            Instant::now(),
        );

        // When: the same session identifier is registered with a new token.
        let displaced = registry.register(Registration {
            token: token(0xbb),
            session: "ses_a".to_owned(),
            pid: 5678,
        });
        table.revoke_tokens(&displaced);

        // Then: the old token's plaintext grant was removed, not merely hidden.
        assert!(
            table.grants.is_empty(),
            "replacing a session left its displaced token grant in the table"
        );
    }

    #[test]
    fn grants_are_isolated_between_sessions() {
        let mut table = GrantTable::default();
        let now = Instant::now();
        let scope_a = Scope::Session(token(0xaa));
        let scope_b = Scope::Session(token(0xbb));
        table.insert(scope_a.clone(), name("K"), secret("v"), now);

        assert_eq!(
            table
                .lookup(&scope_a, &name("K"))
                .map(SecretBytes::as_slice),
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
        table.insert(first.clone(), name("K"), secret("v"), now);

        assert_ne!(first, second);
        assert!(table.lookup(&second, &name("K")).is_none());
    }

    #[test]
    fn revoking_tokens_drops_their_grants() {
        let mut table = GrantTable::default();
        let now = Instant::now();
        table.insert(Scope::Session(token(0xaa)), name("K"), secret("v"), now);
        table.revoke_tokens(&[token(0xaa)]);
        assert!(table.is_empty());
    }

    #[test]
    fn backstop_expires_old_grants_only() {
        let mut table = GrantTable::default();
        let now = Instant::now();
        let old = now.checked_sub(Duration::from_secs(13 * 3600)).unwrap();
        table.insert(Scope::Session(token(0xaa)), name("OLD"), secret("v"), old);
        table.insert(Scope::Session(token(0xbb)), name("NEW"), secret("v"), now);

        let removed = table.revoke_expired(now, Duration::from_secs(12 * 3600));
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
        table.insert(Scope::Session(token(0xaa)), name("K"), secret("v"), now);
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
        );
        let rendered = table.render(now);
        assert!(rendered.contains('K'));
        assert!(
            !rendered.contains("super-secret"),
            "grant listing leaked a value"
        );
    }
}
