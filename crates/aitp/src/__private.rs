//! Plumbing for the sibling crates of this workspace (`aitp-experimental`,
//! `aitp-conformance`, the language bindings and the fuzz targets). It is
//! not part of the public API: it is hidden from the docs, carries no
//! semver promise and may change in any release.

pub use crate::core::unknown_field::{
    check_members, from_serde_error, reject_duplicate_keys, UnknownField,
};

pub use crate::handshake::identity::svid::SvidType;

/// The `svid_type` member of a `spiffe` descriptor.
pub fn svid_type(identity: &crate::handshake::IdentityDescriptor) -> Option<SvidType> {
    identity.svid_type
}

/// The `x5c` member of a `spiffe` descriptor.
pub fn x5c(identity: &crate::handshake::IdentityDescriptor) -> Option<&[String]> {
    identity.x5c.as_deref()
}

/// The request body ceiling of a handshake router served without a
/// configured limit.
#[cfg(feature = "http-server")]
pub const DEFAULT_MAX_BODY_BYTES: usize = crate::transport::server::DEFAULT_MAX_BODY_BYTES;

/// The `typ` header of a compact JWS, read without verifying it.
pub fn peek_typ(token: &str) -> Option<String> {
    crate::crypto::jws::peek_typ(token)
}

/// Bootstrap-verify a peer's Manifest and identity proof
/// (RFC-AITP-0004 §5.1 steps 3–6), returning the peer's verifying key.
pub fn bootstrap_verify_peer(
    envelope: &crate::core::AitpEnvelope,
    payload_manifest: &crate::manifest::Manifest,
    payload_identity: &crate::handshake::IdentityDescriptor,
    payload_pop_nonce: &str,
    cfg: &crate::handshake::PeerConfig<'_>,
) -> Result<crate::crypto::AitpVerifyingKey, crate::handshake::HandshakeError> {
    crate::handshake::state_machine::bootstrap_verify_peer(
        envelope,
        payload_manifest,
        payload_identity,
        payload_pop_nonce,
        cfg,
    )
}

/// The local identity-type policy check (RFC-AITP-0004 §5.1 step 8),
/// run after [`bootstrap_verify_peer`] and the envelope signature.
pub fn apply_peer_policy(
    payload_identity: &crate::handshake::IdentityDescriptor,
    cfg: &crate::handshake::PeerConfig<'_>,
) -> Result<(), crate::handshake::HandshakeError> {
    crate::handshake::state_machine::apply_peer_policy(payload_identity, cfg)
}
