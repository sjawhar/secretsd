//! Secret names and secret bytes.
//!
//! `SecretBytes` is the only type permitted to hold plaintext. It wipes itself
//! on drop and refuses to render its contents in `Debug`.

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::proto::ErrCode;

/// Longest accepted key name.
const MAX_NAME_LEN: usize = 128;

/// A validated secret key name: `[A-Za-z_][A-Za-z0-9_]*`.
///
/// Validation makes it safe to build a file name from client input.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SecretName(String);

impl SecretName {
    /// Parse a client-supplied key name.
    pub fn parse(raw: &str) -> Result<Self, ErrCode> {
        if raw.is_empty() || raw.len() > MAX_NAME_LEN {
            return Err(ErrCode::BadRequest);
        }

        let mut characters = raw.chars();
        let first = characters.next().ok_or(ErrCode::BadRequest)?;
        if !first.is_ascii_alphabetic() && first != '_' {
            return Err(ErrCode::BadRequest);
        }
        if !characters.all(|character| character.is_ascii_alphanumeric() || character == '_') {
            return Err(ErrCode::BadRequest);
        }

        Ok(Self(raw.to_owned()))
    }

    /// The validated name.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// File name this key occupies inside the human-tier directory.
    pub fn file_name(&self) -> String {
        format!("{}.env", self.0)
    }

    /// Local file name this key occupies inside the human-tier directory.
    pub fn local_file_name(&self) -> String {
        format!("{}.local.env", self.0)
    }
}

/// Classification of a file name found in a human-tier directory.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(
    clippy::exhaustive_enums,
    reason = "filename classifications are an explicit shared storage contract"
)]
pub enum HumanFileName {
    /// A name that is not an `.env` file and can be skipped.
    Ignored,
    /// A committed or machine-local key file.
    Key {
        /// The validated secret key name.
        name: SecretName,
        /// Whether the file is machine-local rather than committed.
        local: bool,
    },
    /// An `.env` name whose key portion is not a valid secret key name.
    Invalid,
}

/// Classify a file name found in a human-tier directory.
pub fn parse_human_file_name(file_name: &str) -> HumanFileName {
    let Some(stem) = file_name.strip_suffix(".env") else {
        return HumanFileName::Ignored;
    };

    let (raw_name, local) = stem
        .strip_suffix(".local")
        .map_or((stem, false), |raw_name| (raw_name, true));

    SecretName::parse(raw_name).map_or(HumanFileName::Invalid, |name| HumanFileName::Key {
        name,
        local,
    })
}

/// Plaintext bytes, wiped on drop.
#[derive(Zeroize, ZeroizeOnDrop, Clone, PartialEq, Eq)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Take ownership of plaintext.
    pub const fn from_vec(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Borrow the plaintext for writing to a socket.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Length in bytes.
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the value is empty.
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SecretBytes(<redacted>)")
    }
}

/// Extract the value of `expected` from decrypted dotenv plaintext.
///
/// Requires exactly one assignment whose name equals `expected`. This anti-swap
/// check prevents substituted ciphertext from yielding a value for another key.
pub fn parse_single_assignment(
    plaintext: &[u8],
    expected: &SecretName,
) -> Result<SecretBytes, ErrCode> {
    let mut found = None;

    for line in plaintext.split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() || line.first() == Some(&b'#') {
            continue;
        }

        let split = line
            .iter()
            .position(|byte| *byte == b'=')
            .ok_or(ErrCode::Internal)?;
        let (name, rest) = line.split_at(split);
        let value = rest.get(1..).ok_or(ErrCode::Internal)?;
        if name != expected.as_str().as_bytes() || found.is_some() || value.contains(&b'\0') {
            return Err(ErrCode::Internal);
        }
        found = Some(value);
    }

    found
        .map(|value| SecretBytes::from_vec(value.to_vec()))
        .ok_or(ErrCode::Internal)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(raw: &str) -> SecretName {
        SecretName::parse(raw).unwrap()
    }

    #[test]
    fn accepts_conventional_names() {
        assert_eq!(name("DEEL_API_KEY").as_str(), "DEEL_API_KEY");
        assert_eq!(name("A").as_str(), "A");
        assert_eq!(name("K9_X").as_str(), "K9_X");
        assert_eq!(name("_A").as_str(), "_A");
        assert_eq!(name("lowercase").as_str(), "lowercase");
    }

    #[test]
    fn rejects_path_traversal_and_invalid_characters_and_empty() {
        for raw in ["", "../etc/passwd", "A-B", "A.B", "A/B", "9A", "A B"] {
            assert_eq!(
                SecretName::parse(raw),
                Err(ErrCode::BadRequest),
                "accepted {raw:?}"
            );
        }
    }

    #[test]
    fn rejects_overlong_name() {
        let raw = "A".repeat(129);
        assert_eq!(SecretName::parse(&raw), Err(ErrCode::BadRequest));
    }

    #[test]
    fn file_names_distinguish_committed_and_local_files() {
        assert_eq!(name("DEEL_API_KEY").file_name(), "DEEL_API_KEY.env");
        assert_eq!(
            name("DEEL_API_KEY").local_file_name(),
            "DEEL_API_KEY.local.env"
        );
    }

    #[test]
    fn classifies_committed_local_invalid_and_ignored() {
        let key = |raw: &str, local: bool| HumanFileName::Key {
            name: SecretName::parse(raw).unwrap(),
            local,
        };
        assert_eq!(
            parse_human_file_name("DEEL_API_KEY.env"),
            key("DEEL_API_KEY", false)
        );
        assert_eq!(
            parse_human_file_name("DEEL_API_KEY.local.env"),
            key("DEEL_API_KEY", true)
        );
        assert_eq!(parse_human_file_name("key.env"), key("key", false));
        assert_eq!(parse_human_file_name("local.env"), key("local", false));
        for ignored in ["notes.txt", "README", "X.ENV", ".local", "env"] {
            assert_eq!(
                parse_human_file_name(ignored),
                HumanFileName::Ignored,
                "{ignored}"
            );
        }
        for invalid in [
            ".env",
            ".local.env",
            "BAD-NAME.env",
            "a.b.local.env",
            "1X.env",
            "X.local.local.env",
            "x.env.env",
            "X.Local.env",
        ] {
            assert_eq!(
                parse_human_file_name(invalid),
                HumanFileName::Invalid,
                "{invalid}"
            );
        }
    }

    #[test]
    fn file_names_round_trip_through_classification() {
        for raw in ["DEEL_API_KEY", "local", "env", "_A", &"A".repeat(128)] {
            let name = name(raw);
            assert_eq!(
                parse_human_file_name(&name.file_name()),
                HumanFileName::Key {
                    name: name.clone(),
                    local: false,
                }
            );
            assert_eq!(
                parse_human_file_name(&name.local_file_name()),
                HumanFileName::Key { name, local: true }
            );
        }
        assert_eq!(
            parse_human_file_name(&format!("{}.env", "A".repeat(129))),
            HumanFileName::Invalid
        );
    }

    #[test]
    fn debug_never_reveals_bytes() {
        let secret = SecretBytes::from_vec(b"hunter2".to_vec());
        let rendered = format!("{secret:?}");
        assert!(!rendered.contains("hunter2"), "leaked: {rendered}");
        assert!(rendered.contains("redacted"));
    }

    #[test]
    fn extracts_value_when_single_assignment_matches() {
        let parsed =
            parse_single_assignment(b"DEEL_API_KEY=abc123\n", &name("DEEL_API_KEY")).unwrap();
        assert_eq!(parsed.as_slice(), b"abc123");
    }

    #[test]
    fn ignores_comments_and_blank_lines() {
        let raw = b"# comment\n\nDEEL_API_KEY=abc123\n\n";
        let parsed = parse_single_assignment(raw, &name("DEEL_API_KEY")).unwrap();
        assert_eq!(parsed.as_slice(), b"abc123");
    }

    #[test]
    fn preserves_equals_and_whitespace_inside_value() {
        let parsed = parse_single_assignment(b"K=a=b c\n", &name("K")).unwrap();
        assert_eq!(parsed.as_slice(), b"a=b c");
    }

    #[test]
    fn rejects_nul_bytes_in_values() {
        assert_eq!(
            parse_single_assignment(b"K=ab\0c\n", &name("K")).err(),
            Some(ErrCode::Internal)
        );
    }

    #[test]
    fn strips_trailing_carriage_return() {
        let parsed = parse_single_assignment(b"K=abc\r\n", &name("K")).unwrap();
        assert_eq!(parsed.as_slice(), b"abc");
    }

    #[test]
    fn rejects_when_name_does_not_match_request() {
        let error = parse_single_assignment(b"OTHER_KEY=abc\n", &name("DEEL_API_KEY"));
        assert_eq!(error.err(), Some(ErrCode::Internal));
    }

    #[test]
    fn rejects_multiple_assignments() {
        let error = parse_single_assignment(b"K=a\nJ=b\n", &name("K"));
        assert_eq!(error.err(), Some(ErrCode::Internal));
    }

    #[test]
    fn rejects_empty_plaintext() {
        assert_eq!(
            parse_single_assignment(b"", &name("K")).err(),
            Some(ErrCode::Internal)
        );
    }

    #[test]
    fn rejects_line_without_assignment() {
        assert_eq!(
            parse_single_assignment(b"garbage\n", &name("K")).err(),
            Some(ErrCode::Internal)
        );
    }

    #[test]
    fn zeroizes_on_drop() {
        let mut secret = SecretBytes::from_vec(b"hunter2".to_vec());
        secret.zeroize();
        assert!(secret.as_slice().iter().all(|byte| *byte == 0));
    }
}
