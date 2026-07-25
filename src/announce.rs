//! Telling the human what is about to blink.
//!
//! No decrypt may begin until one of these channels acknowledges. Everything
//! the client supplied is displayed as unverified, because any same-user
//! process can register a session and choose its own metadata.

use std::fmt::Write as _;
use std::process::{Command, Stdio};

use crate::grants::ScopeKind;
use crate::requests::RequestId;
use crate::secret::SecretName;

/// A pending request, described for a human.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Announcement {
    /// Identifier the human can quote to `secrets deny`.
    pub request_id: RequestId,
    /// Key being requested.
    pub key: SecretName,
    /// Whether the requester proved a session token.
    pub scope_kind: ScopeKind,
    /// Client-supplied session id. Unverified.
    pub untrusted_session: Option<String>,
    /// Client-supplied command line. Unverified.
    pub untrusted_cmdline: Option<String>,
}

fn one_line(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(200)
        .collect()
}

/// Render the announcement shown to the human.
pub fn render(item: &Announcement) -> String {
    let mut text = String::new();
    let _ = write!(
        text,
        "secretsd: request #{} for {}",
        item.request_id.0,
        item.key.as_str()
    );
    match item.scope_kind {
        ScopeKind::VerifiedSession => {
            let _ = write!(text, " from a verified agent session");
        }
        ScopeKind::TokenlessTty => {
            let _ = write!(
                text,
                " -- TOKENLESS (no session token; an interactive terminal)"
            );
        }
    }
    if let Some(session) = &item.untrusted_session {
        let _ = write!(text, " [unverified session: {}]", one_line(session));
    }
    if let Some(cmdline) = &item.untrusted_cmdline {
        let _ = write!(text, " [unverified caller: {}]", one_line(cmdline));
    }
    let _ = write!(
        text,
        ". Your next YubiKey touch grants exactly this request."
    );
    text
}

/// A delivery channel for announcements.
pub trait Notifier: Send + Sync + std::fmt::Debug {
    /// Channel name, for logs.
    fn name(&self) -> &str;
    /// Deliver the text. Returns whether delivery was accepted.
    fn deliver(&self, text: &str) -> bool;
}

/// Runs an external command with the announcement appended as its last argument.
#[derive(Debug, Clone)]
pub struct CommandNotifier {
    label: String,
    argv: Vec<String>,
}

impl CommandNotifier {
    /// Build a notifier from a non-empty argv.
    pub fn new(label: impl Into<String>, argv: Vec<String>) -> Option<Self> {
        if argv.is_empty() {
            return None;
        }
        Some(Self {
            label: label.into(),
            argv,
        })
    }
}

impl Notifier for CommandNotifier {
    fn name(&self) -> &str {
        &self.label
    }

    fn deliver(&self, text: &str) -> bool {
        let Some((program, args)) = self.argv.split_first() else {
            return false;
        };
        Command::new(program)
            .args(args)
            .arg(text)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }
}

/// Fans an announcement out to every configured channel.
#[derive(Debug)]
pub struct Announcer {
    notifiers: Vec<Box<dyn Notifier>>,
}

impl Announcer {
    /// Build an announcer.
    pub const fn new(notifiers: Vec<Box<dyn Notifier>>) -> Self {
        Self { notifiers }
    }

    /// Announce a request. Returns whether any channel acknowledged.
    ///
    /// A `false` return forbids starting the decrypt.
    pub fn announce(&self, item: &Announcement) -> bool {
        let text = render(item);
        let mut acknowledged = false;
        for notifier in &self.notifiers {
            if notifier.deliver(&text) {
                acknowledged = true;
            } else {
                tracing::warn!(channel = notifier.name(), "announcement channel failed");
            }
        }
        acknowledged
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::grants::ScopeKind;
    use crate::secret::SecretName;

    #[derive(Debug)]
    struct FakeNotifier {
        succeeds: bool,
        calls: AtomicUsize,
    }

    impl FakeNotifier {
        fn new(succeeds: bool) -> Self {
            Self {
                succeeds,
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl Notifier for FakeNotifier {
        fn name(&self) -> &'static str {
            "fake"
        }
        fn deliver(&self, _text: &str) -> bool {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.succeeds
        }
    }

    fn announcement(kind: ScopeKind) -> Announcement {
        Announcement {
            request_id: RequestId(7),
            key: SecretName::parse("DEEL_API_KEY").unwrap(),
            scope_kind: kind,
            untrusted_session: Some("ses_abc".to_owned()),
            untrusted_cmdline: Some("opencode".to_owned()),
        }
    }

    #[test]
    fn render_names_the_key_and_request_id() {
        let text = render(&announcement(ScopeKind::VerifiedSession));
        assert!(text.contains("DEEL_API_KEY"));
        assert!(text.contains("#7"));
    }

    #[test]
    fn render_warns_loudly_for_tokenless_requests() {
        let text = render(&announcement(ScopeKind::TokenlessTty));
        assert!(
            text.contains("TOKENLESS"),
            "tokenless scope must be conspicuous: {text}"
        );
    }

    #[test]
    fn render_labels_client_supplied_metadata_as_untrusted() {
        let text = render(&announcement(ScopeKind::VerifiedSession));
        assert!(
            text.contains("unverified"),
            "client metadata must be labeled: {text}"
        );
    }

    #[test]
    fn render_sanitizes_metadata_so_it_cannot_forge_lines() {
        let mut item = announcement(ScopeKind::VerifiedSession);
        item.untrusted_session = Some("ses\nTOUCH APPROVED".to_owned());
        let text = render(&item);
        assert!(
            !text.contains("\nTOUCH APPROVED"),
            "metadata injected a line: {text}"
        );
    }

    #[test]
    fn announce_succeeds_when_any_channel_acknowledges() {
        let announcer = Announcer::new(vec![
            Box::new(FakeNotifier::new(false)),
            Box::new(FakeNotifier::new(true)),
        ]);
        assert!(announcer.announce(&announcement(ScopeKind::VerifiedSession)));
    }

    #[test]
    fn announce_fails_closed_when_every_channel_fails() {
        let announcer = Announcer::new(vec![Box::new(FakeNotifier::new(false))]);
        assert!(!announcer.announce(&announcement(ScopeKind::VerifiedSession)));
    }

    #[test]
    fn announce_fails_closed_when_no_channels_are_configured() {
        let announcer = Announcer::new(Vec::new());
        assert!(!announcer.announce(&announcement(ScopeKind::VerifiedSession)));
    }
}
