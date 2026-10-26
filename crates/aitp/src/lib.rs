//! Agent Identity & Trust Protocol (AITP) — facade crate.
//!
//! `aitp` is the supported way to use this implementation:
//!
//! ```toml
//! [dependencies]
//! aitp = "0.20"
//! ```
//!
//! # Stable surface
//!
//! Each module below re-exports a curated list of items by name, frozen in
//! `crates/aitp/public-api.stable.txt` and checked in CI:
//!
//! - [`core`]: AIDs, envelopes, timestamps, error codes, nonce stores.
//! - [`crypto`]: signing keys, the signer traits, digests, compact JWS.
//! - [`tct`]: TCT issuance and verification, grant vouchers, revocation
//!   lists.
//! - [`manifest`]: Manifest building, resolution and verification.
//! - [`handshake`]: the mutual handshake state machine, `PeerConfig` and
//!   identity verification.
//! - [`delegation`]: delegation tokens.
//! - `transport` (feature `http-client`; server items need `http-server`):
//!   fetchers, `HandshakeServer`, revocation sources.
//! - `facade` (feature `http-client`): `run_initiator_handshake`,
//!   `renew_tct`, `TctStore`.
//! - [`prelude`]: the most common types.
//!
//! The internal crates (`aitp-core`, `aitp-tct`, `aitp-transport-http`, …)
//! are published so the bindings and tools can build on them, but they
//! carry **no stability promise**: their submodules, wire-level helpers
//! and member-list constants can change in any release. Use `aitp`.
//! `session_bundle` (feature `experimental-session-bundle`) and
//! `handshake::admission` (feature `pinned-admission`) are re-exported
//! whole and are experimental.
//!
//! # Example: issue and verify a TCT (compact JWS)
//!
//! ```
//! use aitp::core::Timestamp;
//! use aitp::prelude::*;
//! use aitp::tct::{verify_tct, TctBuilder, TctVerifyContext};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let alice = AitpSigningKey::from_seed(&[0x11; 32]);
//! let bob = AitpSigningKey::from_seed(&[0x22; 32]);
//! let now = Timestamp(1_700_000_000);
//!
//! // `issued.token` is the opaque compact JWS that goes on the wire;
//! // `issued.voucher` is the companion grant voucher bob can later
//! // delegate with.
//! let issued = TctBuilder::new(&alice)
//!     .subject(bob.aid().clone())
//!     .audience(bob.aid().clone())  // v0.2: audience == subject
//!     .grants(["demo.echo"])
//!     .ttl_secs(3600)
//!     .subject_pubkey(bob.verifying_key())
//!     .issued_at(now)
//!     .build()?;
//!
//! // The strict builder forces an explicit decision on the two
//! // silent-accept surfaces (revocation source, issuer-Manifest expiry
//! // cap). Here — a self-issued holder receipt with no Manifest
//! // resolved — both are deliberately waived; production verifiers
//! // supply `.revocation_check(..)` and `.issuer_manifest_expires_at(..)`.
//! let ctx = TctVerifyContext::builder(bob.aid(), alice.aid(), now)
//!     .accept_unchecked_revocation_dangerous()
//!     .skip_manifest_expiry_cap_dangerous()
//!     .build()?;
//! let verified = verify_tct(&issued.token, &ctx)?;
//! assert_eq!(verified.claims.grants, vec!["demo.echo".to_string()]);
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

// The curated, stable surface. Each module lists
// its items by name: the internal crates are public on crates.io but carry
// no stability promise, so nothing reaches `aitp` by glob. Adding or
// removing an item here changes `public-api.stable.txt`; regenerate it
// with `make public-api` (CI runs `make public-api-check`).

/// Identifiers, envelopes, timestamps and error codes (RFC-AITP-0001).
pub mod core {
    pub use aitp_core::base64url;
    pub use aitp_core::nonce_store::{InMemoryNonceStore, NonceStore};
    pub use aitp_core::{
        envelope_signing_digest, parse_envelope_wire, Aid, AidAlgorithm, AidParseError,
        AitpEnvelope, AitpError, CheckedJson, CheckedJsonError, EnvelopeParseError, ErrorCode,
        ExtensionsMap, MessageType, RawUrl, Sender, Timestamp, DEFAULT_TIMESTAMP_TOLERANCE_SECS,
        PROTOCOL_VERSION,
    };
}

/// Signing keys, signers, digests and compact JWS.
pub mod crypto {
    pub use aitp_crypto::jws;
    pub use aitp_crypto::{
        check_public_key, check_public_key_async, compute_jwk_thumbprint,
        compute_jwk_thumbprint_p256, sign_jcs, sign_jcs_async, sign_raw, sign_raw_async,
        AitpSigner, AitpSigningKey, AitpVerifyingKey, AsyncAitpSigner, BackendSignature,
        BlockingSigner, CryptoError, Digest32, DynAsyncAitpSigner, SignRequest, Signature,
        SignatureAlgorithm, SignerError,
    };
}

/// Trust Context Tokens, grant vouchers and revocation lists
/// (RFC-AITP-0005, RFC-AITP-0008).
pub mod tct {
    #[cfg(feature = "experimental-renewal")]
    pub use aitp_tct::{
        build_renewal_request, process_renewal_request, RenewalContext, RenewalGrantPolicyFn,
        TctRenewalPayload,
    };
    pub use aitp_tct::{
        sign_pop_response, sign_revocation_list, verify_attestation, verify_pop_response,
        verify_revocation_list, verify_tct, verify_voucher, AttestationVerifyContext,
        AttestationVerifyContextBuilder, Cnf, GrantVoucherClaims, IssuedTct, PopChallenge,
        PopResponse, RevocationCheckFn, RevocationEntry, RevocationList, RevocationListEnvelope,
        TctBuilder, TctClaims, TctError, TctVerifyContext, TctVerifyContextBuilder,
        TctVerifyContextError, VerifiedAttestation, VerifiedTct, VerifyRevocationListContext,
        ATTESTATION_GRANT, DEFAULT_TCT_TTL_SECS,
    };
}

/// Agent Manifests (RFC-AITP-0003).
pub mod manifest {
    pub use aitp_manifest::{
        resolve_verified_manifest, verify_manifest, IdentityHint, IdentityHintKind, Manifest,
        ManifestBuilder, ManifestEnvelope, ManifestError, ManifestPop, ManifestResolver,
        VerifyManifestContext, DEFAULT_MANIFEST_TTL_SECS, REVOCATION_LIST_URI_EXT,
    };
}

/// The mutual handshake state machine and identity verification
/// (RFC-AITP-0004, RFC-AITP-0002).
pub mod handshake {
    #[cfg(feature = "pinned-admission")]
    pub use aitp_handshake::admission;
    #[cfg(feature = "experimental-spiffe-identity")]
    pub use aitp_handshake::identity_spiffe;
    pub use aitp_handshake::state_machine::GrantPolicyFn;
    pub use aitp_handshake::{
        sign_pinned_key_proof, verify_jws_signature, verify_oidc, verify_pinned_key,
        CompletedHandshake, HandshakeError, HandshakeRevocationDecision, IdentityDescriptor,
        IdentityKind, Initiator, JwkKeyMaterial, JwkParseError, JwkPublicKey, JwksResolver,
        JwsAlgorithm, JwsVerifyError, MutualCommitAckPayload, MutualCommitPayload,
        MutualHelloAckPayload, MutualHelloPayload, NoPinnedKeys, OidcMintJwtFn, OidcVerifyContext,
        PeerConfig, PinnedKeyEntry, PinnedKeyEntryError, PinnedKeyStore, PinnedKeyVerifyContext,
        PresentedIdentity, ResolveError, Responder, RevocationCheckFn, RevocationSource, SessionId,
        StaticPinnedKeyStore, SubjectBinding, SvidType, VerifiedPinnedKey,
    };
}

/// Delegation tokens (RFC-AITP-0006).
pub mod delegation {
    pub use aitp_delegation::{
        verify_delegation, DelegationBuilder, DelegationClaims, DelegationError,
        DelegationRevocation, HopRevocationCheck, SourceRevocationCheck, VerifiedDelegation,
        VerifyDelegationContext, DEFAULT_DELEGATION_TTL_SECS, DEFAULT_MAX_DELEGATION_HOPS,
    };
}

/// Session Trust Bundles (RFC-AITP-0010, Draft). Experimental: no
/// stability promise.
#[cfg(feature = "experimental-session-bundle")]
pub use aitp_session_bundle as session_bundle;

/// HTTP transport: Manifest and JWKS fetchers, the handshake server and
/// revocation sources (RFC-AITP-0007, RFC-AITP-0008, RFC-AITP-0009).
#[cfg(feature = "http-client")]
pub mod transport {
    pub use aitp_transport_http::{
        renew_uri_from_manifest, revocation_list_uri_from_manifest, sign_envelope,
        sign_envelope_async, sign_envelope_with, sign_envelope_with_async,
        verify_envelope_signature, AsyncJwksResolver, ClientConfig, FetchError, GuardMode,
        HostGuard, HostGuardError, InMemoryReplayGuard, JwksFetcher, JwksFetcherError,
        KeyResolutionFailMode, KeyResolutionOutcome, KeyResolutionPolicy,
        KeyResolutionPolicyBuilder, ManifestFetcher, PinnedIssuerKeyStore, PreparedRevocation,
        ReplayGuard, RetryPolicy, RevocationCache, RevocationError, RevocationFailMode,
        RevocationFetcher, RevocationOutcome, RevocationPolicy, RevocationProvider,
        StaticPinnedIssuerKeyStore, DEFAULT_MAX_REVOCATION_LIST_BYTES,
        DEFAULT_REVOCATION_FETCH_TIMEOUT, RENEW_URI_EXT, REVOCATION_LIST_URI_EXT,
    };
    #[cfg(feature = "http-server")]
    pub use aitp_transport_http::{
        resolve_source_ip, with_request_body_limit, with_request_body_limit_default,
        HandshakeServer, ManifestServer, RateLimitConfig, RateLimitOutcome, RevocationListProducer,
        TrustedProxy, TrustedProxyParseError, DEFAULT_REQUEST_BODY_LIMIT, DEFAULT_SESSION_TTL,
        RECOMMENDED_MAX_HEADER_BYTES, REVOCATION_LIST_PATH,
    };
    #[cfg(feature = "experimental-session-bundle")]
    pub use aitp_transport_http::{SessionBundleServer, MAX_BUNDLE_BYTES, SESSION_BUNDLE_PATH};
}

/// High-level client helpers: run a handshake, renew a TCT, cache TCTs.
#[cfg(feature = "http-client")]
pub mod facade;

/// Convenience re-exports of the most common types.
pub mod prelude {
    pub use crate::core::{Aid, AitpEnvelope, Timestamp};
    pub use crate::crypto::{
        check_public_key, check_public_key_async, sign_jcs, sign_jcs_async, sign_raw,
        sign_raw_async, AitpSigner, AitpSigningKey, AitpVerifyingKey, AsyncAitpSigner,
        BackendSignature, BlockingSigner, DynAsyncAitpSigner, SignRequest, SignerError,
    };
    pub use crate::manifest::Manifest;
    pub use crate::tct::{IssuedTct, TctBuilder, TctClaims, VerifiedTct};
}
