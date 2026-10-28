//! Verification of identity types `aitp` does not verify itself.
//!
//! `aitp` verifies `oidc` and `pinned_key` identities. A peer presenting
//! any other [`IdentityKind`] is verified by the [`IdentityVerifier`]
//! attached with [`PeerConfig::with_identity_verifier`]; with none
//! attached, or one whose [`IdentityVerifier::handles`] returns `false`,
//! the handshake fails with `INCOMPATIBLE_IDENTITY_TYPE`
//! (RFC-AITP-0002 §6.6).
//!
//! [`PeerConfig::with_identity_verifier`]: crate::handshake::PeerConfig::with_identity_verifier

use std::sync::Arc;

use uuid::Uuid;

use crate::core::{Aid, Timestamp};
use crate::handshake::error::HandshakeError;
use crate::handshake::identity::{IdentityDescriptor, IdentityKind};
use crate::manifest::Manifest;

/// Verifies identity descriptors of the kinds `aitp` does not verify
/// itself.
///
/// It runs in `bootstrap_verify_peer`, at the step where `aitp` verifies
/// an `oidc` or `pinned_key` proof: after the Manifest, the
/// `identity.subject` / `identity_hint.subject` match and the
/// `identity.type` / `identity_hint.type` match, and before the envelope
/// signature. On success the peer key is always derived from
/// [`IdentityVerifyContext::sender_aid`].
pub trait IdentityVerifier: Send + Sync {
    /// Whether this verifier handles `kind`. It is never called for
    /// `oidc` or `pinned_key`.
    fn handles(&self, kind: IdentityKind) -> bool;

    /// Verify `identity`. `Ok` means the proof is valid and bound to
    /// [`IdentityVerifyContext::sender_aid`].
    ///
    /// Return [`HandshakeError::Identity`] (`IDENTITY_FAILED`) for a
    /// defective proof, and [`HandshakeError::KeyResolutionFailed`] only
    /// when key material could not be reached. The error is returned to
    /// the handshake unchanged.
    fn verify(
        &self,
        identity: &IdentityDescriptor,
        ctx: &IdentityVerifyContext<'_>,
    ) -> Result<(), HandshakeError>;
}

impl<T: IdentityVerifier + ?Sized> IdentityVerifier for &T {
    fn handles(&self, kind: IdentityKind) -> bool {
        (**self).handles(kind)
    }
    fn verify(
        &self,
        identity: &IdentityDescriptor,
        ctx: &IdentityVerifyContext<'_>,
    ) -> Result<(), HandshakeError> {
        (**self).verify(identity, ctx)
    }
}

impl<T: IdentityVerifier + ?Sized> IdentityVerifier for Arc<T> {
    fn handles(&self, kind: IdentityKind) -> bool {
        (**self).handles(kind)
    }
    fn verify(
        &self,
        identity: &IdentityDescriptor,
        ctx: &IdentityVerifyContext<'_>,
    ) -> Result<(), HandshakeError> {
        (**self).verify(identity, ctx)
    }
}

impl<T: IdentityVerifier + ?Sized> IdentityVerifier for Box<T> {
    fn handles(&self, kind: IdentityKind) -> bool {
        (**self).handles(kind)
    }
    fn verify(
        &self,
        identity: &IdentityDescriptor,
        ctx: &IdentityVerifyContext<'_>,
    ) -> Result<(), HandshakeError> {
        (**self).verify(identity, ctx)
    }
}

/// The handshake context an [`IdentityVerifier`] verifies against.
/// Built by `aitp` only.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct IdentityVerifyContext<'a> {
    /// The peer's verified Manifest.
    pub peer_manifest: &'a Manifest,
    /// The envelope's `sender.agent_id`, equal to `peer_manifest.aid`.
    pub sender_aid: &'a Aid,
    /// The verifying peer's own AID.
    pub receiver_aid: &'a Aid,
    /// The envelope's `message_id`.
    pub message_id: &'a Uuid,
    /// The envelope's `timestamp`.
    pub timestamp: Timestamp,
    /// The handshake message's `pop_nonce`.
    pub pop_nonce: &'a str,
    /// Current time.
    pub now: Timestamp,
}
