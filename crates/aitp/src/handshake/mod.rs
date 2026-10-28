//! Mutual Handshake state machine (RFC-AITP-0004).
//!
//! **No stability promise.** This crate is published so the AITP bindings
//! and tools can build on it; its API can change in any release. Depend
//! on the [`aitp`](https://docs.rs/aitp) facade crate instead.
//!
//! Two peers exchange four messages — `MUTUAL_HELLO`, `MUTUAL_HELLO_ACK`,
//! `MUTUAL_COMMIT`, `MUTUAL_COMMIT_ACK` — and end with each holding a
//! peer-issued TCT.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "pinned-admission")]
pub mod admission;
pub(crate) mod error;
pub(crate) mod identity;
pub(crate) mod identity_oidc;
pub(crate) mod identity_verifier;
pub(crate) mod jwk;
pub(crate) mod payloads;
pub(crate) mod pinned_key;
pub(crate) mod state_machine;

/// The pinned-key proof's domain-separation prefix (RFC-AITP-0002 §3.1).
/// The pinned-key functions and types are at [`crate::handshake`].
pub mod identity_pinned {
    pub use super::pinned_key::PINNED_KEY_PROOF_DOMAIN;
}

pub use error::HandshakeError;
pub use identity::{IdentityDescriptor, IdentityKind};
pub use identity_oidc::{
    verify_oidc, JwksResolver, OidcVerifyContext, OidcVerifyContextBuilder, ResolveError,
};
pub use identity_verifier::{
    IdentityVerifier, IdentityVerifyContext, IdentityVerifyError, VerifiedIdentity,
};
pub use jwk::{
    verify_jws_signature, JwkKeyMaterial, JwkParseError, JwkPublicKey, JwsAlgorithm, JwsVerifyError,
};
pub use payloads::{
    MutualCommitAckPayload, MutualCommitPayload, MutualHelloAckPayload, MutualHelloPayload,
    MUTUAL_COMMIT_ACK_PAYLOAD_MEMBERS, MUTUAL_COMMIT_PAYLOAD_MEMBERS,
    MUTUAL_HELLO_ACK_PAYLOAD_MEMBERS, MUTUAL_HELLO_PAYLOAD_MEMBERS,
};
pub use pinned_key::{
    pinned_key_proof_input, sign_pinned_key_proof, verify_pinned_key, NoPinnedKeys, PinnedKeyEntry,
    PinnedKeyEntryError, PinnedKeyStore, PinnedKeyVerifyContext, PinnedKeyVerifyContextBuilder,
    StaticPinnedKeyStore, SubjectBinding, VerifiedPinnedKey, VerifiedPinnedKeyParts,
};
/// RFC-AITP-0009 §3.1 recommended handshake requests per source (peer
/// IP address or TLS client-certificate fingerprint) per 60 s. The
/// default of `aitp::transport::RateLimitConfig` and of
/// `aitp::handshake::admission::RecommendedLimiter`.
pub const RECOMMENDED_REQUESTS_PER_SOURCE_PER_60S: u32 = 30;
/// RFC-AITP-0009 §3.1 recommended handshake requests per claimed
/// initiator AID per 60 s. The default of
/// `aitp::transport::RateLimitConfig` and of
/// `aitp::handshake::admission::RecommendedLimiter`.
pub const RECOMMENDED_REQUESTS_PER_AID_PER_60S: u32 = 10;

pub use state_machine::{
    CompletedHandshake, CompletedHandshakeParts, GrantPolicyContext, GrantPolicyError,
    GrantPolicyFn, Initiator, LocalOidcMintJwtFn, OidcMintError, OidcMintJwtFn, PeerConfig,
    PresentedIdentity, Responder, SessionId,
};
