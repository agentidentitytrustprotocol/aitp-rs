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
pub mod error;
pub mod identity;
pub mod identity_oidc;
pub mod identity_pinned;
pub mod identity_verifier;
pub mod jwk;
pub mod payloads;
pub mod state_machine;

pub use error::HandshakeError;
pub use identity::{IdentityDescriptor, IdentityKind};
pub use identity_oidc::{verify_oidc, JwksResolver, OidcVerifyContext, ResolveError};
pub use identity_pinned::{
    pinned_key_proof_input, sign_pinned_key_proof, verify_pinned_key, NoPinnedKeys, PinnedKeyEntry,
    PinnedKeyEntryError, PinnedKeyStore, PinnedKeyVerifyContext, StaticPinnedKeyStore,
    SubjectBinding, VerifiedPinnedKey, VerifiedPinnedKeyParts, POP_NONCE_LEN,
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
pub use state_machine::{
    CompletedHandshake, CompletedHandshakeParts, GrantPolicyContext, GrantPolicyError,
    GrantPolicyFn, Initiator, LocalOidcMintJwtFn, OidcMintError, OidcMintJwtFn, PeerConfig,
    PresentedIdentity, Responder, SessionId,
};
