//! Session Trust Bundle (RFC-AITP-0010).
//!
//! In a multi-agent session of N participants, requiring O(N²) bilateral
//! Mutual Handshakes is unscalable. The Session Trust Bundle is a signed
//! artifact a coordinator constructs from N coordinator↔participant
//! Mutual Handshakes (each producing a peer-issued TCT) and distributes
//! to all participants, so that every agent-to-agent pair within the
//! session has a verifiable trust artifact without a full mesh of
//! handshakes.
//!
//! # Trust model
//!
//! A bundle provides **coordinator-attested membership**, not
//! peer-to-peer identity binding. If A and B both appear in the same
//! bundle, they know:
//! 1. The coordinator authenticated each of them directly via a
//!    bilateral handshake (the coordinator holds a peer-issued TCT for
//!    each participant).
//! 2. The coordinator signed both of those TCTs into the same bundle.
//!
//! Pairs that need direct peer-to-peer identity binding (rather than
//! coordinator-attested membership) MUST run a separate bilateral
//! Mutual Handshake.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod builder;
pub mod error;
pub mod types;
pub mod verifier;
pub mod wire;

pub use builder::{SessionBundleBuilder, DEFAULT_BUNDLE_VERSION};
pub use error::SessionBundleError;
pub use types::{
    ParticipantEntry, SessionBundleEnvelope, SessionTrustBundle, SESSION_BUNDLE_MEMBERS,
};
pub use verifier::{
    verify_session_bundle, BundleOutcome, CoordinatorKeySource, VerifySessionBundleContext,
};
pub use wire::{parse_session_bundle_envelope, parse_session_bundle_wire};

/// Manifest `extensions` key under which a coordinator advertises the
/// concrete HTTPS URL of its session-bundle endpoint (RFC-AITP-0010
/// §4.3.1; registered in the spec's `registries/extension-keys.md`).
///
/// The §4.3.1 paths (`/aitp/session/bundle` and
/// `/aitp/session/bundle/{session_id}`) are RECOMMENDED, not reserved:
/// participants MUST discover the actual endpoint via this extension
/// key and MUST NOT probe the default paths when the key is absent.
pub const RFC_AITP_0010_BUNDLE_URI: &str = "rfc-aitp-0010.bundle_uri";

/// Advertise a coordinator's session-bundle endpoint in the Manifest it
/// is about to sign (RFC-AITP-0010 §4.3.1): sets
/// `extensions["rfc-aitp-0010.bundle_uri"]` to `bundle_uri`, the
/// **concrete** URL the coordinator exposes (e.g.
/// `https://coord.example/aitp/session/bundle`). Because the key lives in
/// the Manifest's `extensions`, the Manifest signature covers it.
///
/// `bundle_uri` MUST be HTTPS outside localhost development
/// (`registries/extension-keys.md`); [`bundle_uri_from_manifest`] ignores
/// any other value.
pub fn advertise_bundle_uri<'a>(
    builder: aitp_manifest::ManifestBuilder<'a>,
    bundle_uri: &url::Url,
) -> aitp_manifest::ManifestBuilder<'a> {
    builder.extension(
        RFC_AITP_0010_BUNDLE_URI,
        serde_json::Value::String(bundle_uri.to_string()),
    )
}

/// Read the advertised session-bundle endpoint from a coordinator's
/// (verified) Manifest. `None` when the key is absent, not a string, not
/// a URL, or neither HTTPS nor `http://localhost` / `http://127.0.0.1`.
///
/// Per RFC-AITP-0010 §4.3.1, `None` means HTTPS is unavailable for that
/// coordinator: callers MUST use a non-HTTPS transport and MUST NOT probe
/// the default `/aitp/session/bundle` path.
pub fn bundle_uri_from_manifest(manifest: &aitp_manifest::Manifest) -> Option<url::Url> {
    manifest
        .extensions
        .as_ref()?
        .get(RFC_AITP_0010_BUNDLE_URI)
        .and_then(|v| v.as_str())
        .and_then(|s| url::Url::parse(s).ok())
        .filter(|u| {
            u.scheme() == "https"
                || (u.scheme() == "http"
                    && matches!(u.host_str(), Some("localhost") | Some("127.0.0.1")))
        })
}
