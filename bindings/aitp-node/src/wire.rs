//! Wire-JSON parsing shared by every binding entry point that takes a
//! peer's JSON (issue #152).
//!
//! Each function here routes the caller's text through
//! [`aitp::core::CheckedJson`] (duplicate-key rejection, RFC-AITP-0001
//! §5.4.5) and then the matching `parse_*_wire` function (member-set
//! check, RFC-AITP-0001 §7), the same path the HTTP transport and the
//! conformance adapter use. A plain `serde_json::from_str` on the typed
//! envelope would skip both: a repeated key would silently keep its last
//! value, and an unknown member would surface as a generic serde error
//! rather than `UNKNOWN_FIELD`.
//!
//! The binding modules map [`WireError`] onto their own error conventions;
//! [`WireError::code`] is the cause code used where a binding exposes one.
//! This file is kept identical in `aitp-node` and `aitp-py`.

use aitp::core::{
    check_members, from_serde_error, parse_envelope_wire, AitpEnvelope, CheckedJson,
    EnvelopeParseError,
};
use aitp::manifest::{parse_manifest_wire, Manifest, ManifestError};
use aitp::tct::{parse_revocation_snapshot_wire, RevocationListEnvelope, TctError};

/// Why wire JSON was rejected before any verification ran.
#[derive(Debug)]
pub enum WireError {
    /// An envelope whose `version` is absent or not the revision this
    /// implementation speaks (RFC-AITP-0001 §5.4 check order, step 1;
    /// `UNKNOWN_VERSION`). Checked before the member set.
    UnknownVersion(String),
    /// A member outside the object's declared member set
    /// (RFC-AITP-0001 §7, `UNKNOWN_FIELD`).
    UnknownField(String),
    /// Anything else: invalid JSON, a duplicate key, a missing or
    /// mistyped member, a missing transport wrapper.
    Malformed(String),
}

impl WireError {
    /// Stable cause code: `unknown_version`, `unknown_field` or
    /// `malformed`.
    pub fn code(&self) -> &'static str {
        match self {
            WireError::UnknownVersion(_) => "unknown_version",
            WireError::UnknownField(_) => "unknown_field",
            WireError::Malformed(_) => "malformed",
        }
    }
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WireError::UnknownVersion(v) => write!(f, "unknown protocol version {v}"),
            WireError::UnknownField(field) => write!(f, "unknown field `{field}`"),
            WireError::Malformed(msg) => f.write_str(msg),
        }
    }
}

/// Parse `json`, rejecting a duplicate key anywhere in it.
fn checked(json: &str) -> Result<CheckedJson, WireError> {
    json.parse()
        .map_err(|e: aitp::core::CheckedJsonError| WireError::Malformed(e.to_string()))
}

/// Require the `{"<key>": {...}}` transport wrapper. The `parse_*_wire`
/// functions also accept a bare body (for the conformance adapter); the
/// binding entry points have always taken the wrapped form only.
fn require_wrapper(value: &CheckedJson, key: &str) -> Result<(), WireError> {
    if value.get(key).is_some() {
        Ok(())
    } else {
        Err(WireError::Malformed(format!(
            "missing `{key}` transport wrapper"
        )))
    }
}

/// An [`AitpEnvelope`] from wire JSON.
pub fn envelope(json: &str) -> Result<AitpEnvelope, WireError> {
    parse_envelope_wire(&checked(json)?).map_err(|e| match e {
        EnvelopeParseError::UnknownVersion(v) => WireError::UnknownVersion(v),
        EnvelopeParseError::UnknownField(field) => WireError::UnknownField(field),
        EnvelopeParseError::Malformed(msg) => WireError::Malformed(msg),
        other => WireError::Malformed(other.to_string()),
    })
}

/// Member-set check for an envelope's `payload` (RFC-AITP-0001 §7),
/// ahead of the caller's typed `serde_json::from_value`.
pub fn check_payload(
    envelope: &AitpEnvelope,
    object: &'static str,
    members: &[&str],
) -> Result<(), WireError> {
    check_members(object, &envelope.payload, members).map_err(|e| WireError::UnknownField(e.field))
}

/// Classify a typed-deserialize error: a nested closed object's unknown
/// member is still `UnknownField`.
pub fn from_serde(e: serde_json::Error) -> WireError {
    match from_serde_error(&e) {
        Some(field) => WireError::UnknownField(field),
        None => WireError::Malformed(e.to_string()),
    }
}

/// The [`Manifest`] inside a `{"manifest": {...}}` wire envelope.
pub fn manifest(json: &str) -> Result<Manifest, WireError> {
    let value = checked(json)?;
    require_wrapper(&value, "manifest")?;
    parse_manifest_wire(&value).map_err(|e| match e {
        ManifestError::UnknownField(field) => WireError::UnknownField(field),
        other => WireError::Malformed(other.to_string()),
    })
}

/// A [`RevocationListEnvelope`] from wire JSON.
pub fn revocation_snapshot(json: &str) -> Result<RevocationListEnvelope, WireError> {
    parse_revocation_snapshot_wire(&checked(json)?).map_err(|e| match e {
        TctError::UnknownField(field) => WireError::UnknownField(field),
        other => WireError::Malformed(other.to_string()),
    })
}

/// The bundle inside a `{"session_bundle": {...}}` wire envelope.
#[cfg(feature = "experimental-session-bundle")]
pub fn session_bundle(
    json: &str,
) -> Result<aitp_experimental::session_bundle::SessionTrustBundle, WireError> {
    use aitp_experimental::session_bundle::{parse_session_bundle_wire, SessionBundleError};
    let value = checked(json)?;
    require_wrapper(&value, "session_bundle")?;
    parse_session_bundle_wire(&value).map_err(|e| match e {
        SessionBundleError::UnknownField(field) => WireError::UnknownField(field),
        other => WireError::Malformed(other.to_string()),
    })
}
