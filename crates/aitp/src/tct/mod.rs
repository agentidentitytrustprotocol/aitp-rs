//! Trust Context Token (TCT) — the canonical output of AITP.
//!
//! **No stability promise.** This crate is published so the AITP bindings
//! and tools can build on it; its API can change in any release. Depend
//! on the [`aitp`](https://docs.rs/aitp) facade crate instead.
//!
//! A TCT is a signed, audience-bound, capability-scoped grant. Each peer
//! holds the TCT issued by its counterpart in a Mutual Handshake.
//!
//! In `aitp/0.3` the TCT and its companion grant voucher are **compact
//! JWS strings** (RFC-AITP-0001 §5.4.5): signatures cover the exact
//! transmitted bytes, so any off-the-shelf JOSE library can verify them
//! given only the issuer public key. The revocation snapshot
//! (RFC-AITP-0008) is protocol-internal and stays JCS-signed.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod builder;
pub mod error;
pub mod pop;
pub mod revocation;
pub mod types;
pub mod verifier;

pub use builder::{TctBuilder, ATTESTATION_GRANT};
pub use error::TctError;
pub use pop::{sign_pop_response, verify_pop_response, PopChallenge, PopResponse};
pub use revocation::{
    parse_revocation_snapshot_wire, revocation_signing_bytes, sign_revocation_list,
    verify_revocation_list, RevocationCheckFn, RevocationEntry, RevocationList,
    RevocationListEnvelope, RevocationListVerifyContext, RevocationQuery, RevocationSource,
    RevocationStatus, RevocationUnavailable, REVOCATION_ENVELOPE_MEMBERS, REVOCATION_LIST_MEMBERS,
};
pub use types::{
    Cnf, GrantVoucherClaims, IssuedTct, TctClaims, VerifiedTct, VerifiedTctParts,
    GRANT_VOUCHER_CLAIMS_MEMBERS, TCT_CLAIMS_MEMBERS,
};
pub use verifier::{
    verify_attestation, verify_tct, verify_voucher, AttestationVerifyContext,
    AttestationVerifyContextBuilder, TctVerifyContext, TctVerifyContextBuilder,
    TctVerifyContextError, VerifiedAttestation, VerifiedAttestationParts,
};

/// Recommended TCT TTL (1 hour).
pub const DEFAULT_TCT_TTL: std::time::Duration = std::time::Duration::from_secs(3600);
