//! Mutual Handshake state machine (RFC-AITP-0004).
//!
//! Two peers exchange four messages — `MUTUAL_HELLO`, `MUTUAL_HELLO_ACK`,
//! `MUTUAL_COMMIT`, `MUTUAL_COMMIT_ACK` — and end with each holding a
//! peer-issued TCT.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod identity;
pub mod identity_oidc;
pub mod identity_pinned;
pub mod jwk;
pub mod payloads;
pub mod state_machine;

pub use error::HandshakeError;
pub use identity::{IdentityDescriptor, IdentityKind};
pub use identity_oidc::{verify_oidc, JwksResolver, OidcVerifyContext, ResolveError};
pub use identity_pinned::{sign_pinned_key_proof, verify_pinned_key, PinnedKeyVerifyContext};
pub use jwk::{
    verify_jws_signature, JwkKeyMaterial, JwkParseError, JwkPublicKey, JwsAlgorithm, JwsVerifyError,
};
pub use payloads::{
    MutualCommitAckPayload, MutualCommitPayload, MutualHelloAckPayload, MutualHelloPayload,
    MUTUAL_COMMIT_ACK_PAYLOAD_MEMBERS, MUTUAL_COMMIT_PAYLOAD_MEMBERS,
    MUTUAL_HELLO_ACK_PAYLOAD_MEMBERS, MUTUAL_HELLO_PAYLOAD_MEMBERS,
};
pub use state_machine::{
    bootstrap_verify_peer, CompletedHandshake, HandshakeRevocationDecision, Initiator,
    OidcMintJwtFn, PeerConfig, PinnedKeyStore, PresentedIdentity, Responder, RevocationCheckFn,
    SessionId, StaticPinnedKeyStore,
};
