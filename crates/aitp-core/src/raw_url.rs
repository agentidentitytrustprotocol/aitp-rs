//! [`RawUrl`] — a URL that preserves its on-the-wire byte form.
//!
//! The `url` crate normalizes URLs per RFC 3986 §6 (e.g. adds a
//! trailing `/` to bare authorities, lowercases scheme/host, sorts
//! query parameters). That's correct for transport-layer
//! comparison, but it's the wrong choice when the URL is part of a
//! signed canonical body: the signature is over the **original**
//! bytes, and a verifier that round-trips through `Url` would
//! produce a different SHA-256 input than the issuer signed.
//!
//! `RawUrl` keeps the input string verbatim for serde, while
//! exposing a `parse()` method that hands back a real `Url` for
//! transport-layer use.
//!
//! # Examples
//!
//! ```rust
//! use aitp_core::RawUrl;
//!
//! // Round-trip preserves the trailing-slash-less form.
//! let raw: RawUrl = serde_json::from_str("\"https://idp.example.com\"").unwrap();
//! assert_eq!(raw.as_str(), "https://idp.example.com");
//! let parsed = raw.parse_url().unwrap();
//! assert_eq!(parsed.as_str(), "https://idp.example.com/");
//! ```

use serde::{Deserialize, Serialize};

/// A URL stored as its original string form. See module docs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(transparent)]
pub struct RawUrl(String);

impl RawUrl {
    /// Wrap a string verbatim. Does **not** validate that the
    /// string is a syntactically valid URL — call [`Self::parse_url`]
    /// to validate.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// The original string form, byte-for-byte.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Parse the wrapped string as a `url::Url`. Returns the parse
    /// error if the wrapped string isn't a valid URL.
    pub fn parse_url(&self) -> Result<url::Url, url::ParseError> {
        url::Url::parse(&self.0)
    }
}

impl From<String> for RawUrl {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for RawUrl {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<url::Url> for RawUrl {
    fn from(u: url::Url) -> Self {
        Self(u.to_string())
    }
}

impl std::fmt::Display for RawUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::str::FromStr for RawUrl {
    type Err = std::convert::Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_no_trailing_slash() {
        let raw: RawUrl = serde_json::from_str("\"https://idp.example.com\"").unwrap();
        assert_eq!(raw.as_str(), "https://idp.example.com");
        let s = serde_json::to_string(&raw).unwrap();
        assert_eq!(s, "\"https://idp.example.com\"");
    }

    #[test]
    fn preserves_path_query_fragment() {
        let raw: RawUrl = serde_json::from_str("\"https://h/p?a=1&b=2#frag\"").unwrap();
        assert_eq!(raw.as_str(), "https://h/p?a=1&b=2#frag");
        // Round-trip
        let s = serde_json::to_string(&raw).unwrap();
        assert_eq!(s, "\"https://h/p?a=1&b=2#frag\"");
    }

    #[test]
    fn parse_url_works() {
        let raw = RawUrl::new("https://example.com");
        let u = raw.parse_url().unwrap();
        // url::Url normalizes — that's fine, this is the parsed
        // view, not the canonical-bytes view.
        assert_eq!(u.as_str(), "https://example.com/");
    }

    #[test]
    fn invalid_url_parse_fails() {
        let raw = RawUrl::new("not a url");
        assert!(raw.parse_url().is_err());
    }
}
