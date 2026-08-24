//! Capability names and their backing key namespace.
//!
//! A capability is a touch-gated yes/no, not a secret: its `CAP_<NAME>` key
//! exists only as the ceremony fixture the decrypt path needs, and nothing —
//! not GET, not REQUEST — can retrieve a `CAP_` value.

use crate::proto::ErrCode;

/// Every capability key starts with this; the whole prefix is reserved.
pub const CAPABILITY_KEY_PREFIX: &str = "CAP_";

const MAX_CAPABILITY_LEN: usize = 32;
const MAX_CAPABILITY_KEY_LEN: usize = CAPABILITY_KEY_PREFIX.len() + MAX_CAPABILITY_LEN;

/// A validated capability name: `[a-z][a-z0-9_]*`, at most 32 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability(String);

impl Capability {
    /// Parse a client-supplied capability name.
    pub fn parse(raw: &str) -> Result<Self, ErrCode> {
        if raw.is_empty() || raw.len() > MAX_CAPABILITY_LEN {
            return Err(ErrCode::BadRequest);
        }
        let mut bytes = raw.bytes();
        let first_is_letter = bytes.next().is_some_and(|byte| byte.is_ascii_lowercase());
        if !first_is_letter
            || !raw
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(ErrCode::BadRequest);
        }
        Ok(Self(raw.to_owned()))
    }

    /// The human-store key backing this capability.
    pub fn key_name(&self) -> String {
        let mut name = String::with_capacity(MAX_CAPABILITY_KEY_LEN);
        name.push_str(CAPABILITY_KEY_PREFIX);
        for byte in self.0.bytes() {
            name.push(char::from(byte.to_ascii_uppercase()));
        }
        name
    }

    /// The validated name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_names_are_lowercase_snake_and_map_to_cap_keys() {
        let cap = Capability::parse("browser").unwrap();
        assert_eq!(cap.key_name(), "CAP_BROWSER");
        assert_eq!(cap.as_str(), "browser");
        for bad in [
            "",
            "Browser",
            "CAP_BROWSER",
            "brow ser",
            "a".repeat(33).as_str(),
            "1browser",
        ] {
            assert!(Capability::parse(bad).is_err(), "{bad:?} parsed");
        }
    }

    #[test]
    fn rejects_protocol_delimiters_and_controls() {
        for bad in [
            "browser\tcap=admin",
            "browser\ncap=admin",
            "browser\r",
            "browser\0",
        ] {
            assert!(Capability::parse(bad).is_err(), "{bad:?} parsed");
        }
    }
}
