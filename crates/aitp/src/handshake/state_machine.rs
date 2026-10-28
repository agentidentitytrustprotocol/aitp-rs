//! Initiator and Responder state machines (RFC-AITP-0004).
//!
//! These are pure: they receive parsed payloads and parsed envelopes from
//! the caller, do every cryptographic check, and return the next payload
//! to send (or the final TCT). The caller wraps payloads in
//! [`AitpEnvelope`]s, applies replay-protection state, and drives I/O.

use crate::core::{base64url, Aid, AitpEnvelope, Timestamp};
use crate::crypto::{AitpSigner, AitpVerifyingKey, CryptoError, Signature};
use crate::handshake::error::HandshakeError;
use crate::handshake::identity::{IdentityDescriptor, IdentityKind};
use crate::handshake::identity_oidc::{verify_oidc, JwksResolver, OidcVerifyContext};
use crate::handshake::identity_pinned::{
    sign_pinned_key_proof, verify_pinned_key, PinnedKeyVerifyContext,
};
use crate::handshake::identity_verifier::{IdentityVerifier, IdentityVerifyContext};
use crate::handshake::payloads::{
    MutualCommitAckPayload, MutualCommitPayload, MutualHelloAckPayload, MutualHelloPayload,
};
use crate::manifest::{verify_manifest, Manifest, ManifestVerifyContext};
use crate::tct::verifier::{check_revocation, verify_tct_before_revocation};
use crate::tct::{
    IssuedTct, RevocationSource, TctBuilder, TctError, TctVerifyContext, VerifiedTct,
};
use rand::TryRng;
use tracing::debug;
use uuid::Uuid;

pub use crate::handshake::identity_pinned::{NoPinnedKeys, PinnedKeyStore, StaticPinnedKeyStore};

/// Opaque session identifier — handle for an in-progress handshake.
pub type SessionId = Uuid;

/// Configuration shared by Initiator and Responder.
///
/// Construct with [`PeerConfig::new`] and set the optional parts with the
/// `with_*` methods. The struct is `#[non_exhaustive]`, so a struct
/// literal does not compile outside this crate:
///
/// ```compile_fail
/// # use aitp::handshake::{PeerConfig, NoPinnedKeys, JwksResolver};
/// # fn demo<'a>(
/// #     key: &'a aitp::crypto::AitpSigningKey,
/// #     manifest: &'a aitp::manifest::Manifest,
/// #     resolver: &'a dyn JwksResolver,
/// # ) -> PeerConfig<'a> {
/// PeerConfig {
///     signing_key: key,
///     manifest,
///     trust_anchors: &[],
///     jwks_resolver: resolver,
///     pinned_key_store: &NoPinnedKeys,
///     grant_policy: None,
///     revocation: aitp::tct::RevocationSource::FailOpen,
///     now: aitp::core::Timestamp(0),
/// }
/// # }
/// ```
#[derive(Clone)]
#[non_exhaustive]
pub struct PeerConfig<'a> {
    /// Our long-term signing key. Accepts any [`AitpSigner`] (in-process
    /// key, KMS, HSM); a backend failure surfaces as
    /// `HandshakeError::Crypto(CryptoError::Signer(_))` (or wrapped in
    /// `HandshakeError::Tct` when minting the peer's TCT).
    pub signing_key: &'a dyn AitpSigner,
    /// Our published Manifest (must equal `payload.manifest` we send).
    pub manifest: &'a Manifest,
    /// Accepted OIDC issuers (when peers present OIDC identities).
    /// `RawUrl` so wire-byte comparison matches the issuer-signed
    /// canonical input.
    pub trust_anchors: &'a [crate::core::RawUrl],
    /// JWKS resolver. May be a no-op for pinned-key-only deployments.
    pub jwks_resolver: &'a dyn JwksResolver,
    /// Local pinned-key trust store (RFC-AITP-0002 §3.2 step 3), keyed
    /// by `(algorithm, key)`. REQUIRED: a pinned-key peer whose key is
    /// not in the store is rejected with `IDENTITY_FAILED` before its
    /// proof is checked. There is no possession-only mode. OIDC-only
    /// deployments pass [`NoPinnedKeys`]; tests use a
    /// [`StaticPinnedKeyStore`].
    pub pinned_key_store: &'a dyn PinnedKeyStore,
    /// Optional grant-policy hook (RFC-AITP-0004 §4.1). Applied to the
    /// `peer_requested ∩ self.offered` intersection before issuing a
    /// TCT — typically used to derive identity-based capability
    /// restrictions. `None` means policy-allow-all (the default).
    pub grant_policy: Option<&'a GrantPolicyFn>,
    /// How the peer-issued TCT received in MUTUAL_COMMIT /
    /// MUTUAL_COMMIT_ACK is checked for revocation (RFC-AITP-0008).
    /// Required by [`PeerConfig::new`]; see [`RevocationSource`].
    pub revocation: RevocationSource<'a>,
    /// Verifier for the identity types `aitp` does not verify itself
    /// (see [`IdentityVerifier`]). `None`: a peer presenting one fails
    /// with `INCOMPATIBLE_IDENTITY_TYPE`.
    pub identity_verifier: Option<&'a dyn IdentityVerifier>,
    /// Current time (Unix seconds).
    pub now: Timestamp,
}

impl<'a> PeerConfig<'a> {
    /// Construct a config from its required parts. It starts with no
    /// trust anchors and no grant policy; set them with the `with_*`
    /// methods. The revocation decision is required: there is no
    /// default that skips it.
    ///
    /// ```
    /// # use aitp::handshake::{PeerConfig, StaticPinnedKeyStore, JwksResolver};
    /// # fn demo(
    /// #     key: &aitp::crypto::AitpSigningKey,
    /// #     manifest: &aitp::manifest::Manifest,
    /// #     resolver: &dyn JwksResolver,
    /// #     peer: &aitp::crypto::AitpSigningKey,
    /// #     now: aitp::core::Timestamp,
    /// # ) {
    /// let trusted = StaticPinnedKeyStore::new([peer.verifying_key()]);
    /// let cfg = PeerConfig::new(
    ///     key,
    ///     manifest,
    ///     resolver,
    ///     &trusted,
    ///     aitp::tct::RevocationSource::FailOpen,
    ///     now,
    /// )
    /// .with_trust_anchors(&[]);
    /// # let _ = cfg;
    /// # }
    /// ```
    pub fn new(
        signing_key: &'a dyn AitpSigner,
        manifest: &'a Manifest,
        jwks_resolver: &'a dyn JwksResolver,
        pinned_key_store: &'a dyn PinnedKeyStore,
        revocation: RevocationSource<'a>,
        now: Timestamp,
    ) -> Self {
        Self {
            signing_key,
            manifest,
            trust_anchors: &[],
            jwks_resolver,
            pinned_key_store,
            grant_policy: None,
            revocation,
            identity_verifier: None,
            now,
        }
    }

    /// Set the accepted OIDC issuers (default: none).
    pub fn with_trust_anchors(mut self, trust_anchors: &'a [crate::core::RawUrl]) -> Self {
        self.trust_anchors = trust_anchors;
        self
    }

    /// Set the identity verifier (default: none). See
    /// [`PeerConfig::identity_verifier`].
    pub fn with_identity_verifier(mut self, verifier: &'a dyn IdentityVerifier) -> Self {
        self.identity_verifier = Some(verifier);
        self
    }

    /// Set the grant-policy hook (default: allow all). See
    /// [`PeerConfig::grant_policy`].
    pub fn with_grant_policy(mut self, grant_policy: &'a GrantPolicyFn) -> Self {
        self.grant_policy = Some(grant_policy);
        self
    }
}

/// Identity-aware grant-policy hook (RFC-AITP-0004 §4.1).
///
/// Returns the subset of [`GrantPolicyContext::candidate_grants`] the
/// policy permits. It can only narrow: a returned capability outside the
/// candidates is dropped. An empty result, or an error, fails the
/// handshake with `POLICY_VIOLATION`.
pub type GrantPolicyFn =
    dyn Fn(&GrantPolicyContext<'_>) -> Result<Vec<String>, GrantPolicyError> + Send + Sync;

/// What a [`GrantPolicyFn`] decides on.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct GrantPolicyContext<'a> {
    /// The peer's verified identity descriptor.
    pub peer_identity: &'a IdentityDescriptor,
    /// The peer's AID, the subject of the TCT being issued.
    pub peer_aid: &'a Aid,
    /// `peer_requested ∩ self.offered`, in the peer's request order.
    pub candidate_grants: &'a [String],
    /// The handshake's clock.
    pub now: Timestamp,
}

/// A [`GrantPolicyFn`] failed to decide.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct GrantPolicyError(crate::core::BoxError);

impl GrantPolicyError {
    /// Wrap any error or message.
    pub fn new(error: impl Into<crate::core::BoxError>) -> Self {
        Self(error.into())
    }
}

/// Inputs the issuing side needs to mint a fresh identity proof bound
/// to an outbound envelope. RFC-AITP-0002 §3.1 requires every pinned-key
/// proof to bind the full (sender, receiver, message_id, timestamp,
/// pop_nonce) tuple; collecting them in one struct prevents call sites
/// from forgetting fields.
#[non_exhaustive]
pub(crate) struct IdentityPresentationContext<'a> {
    /// Sender's AID (= signer's AID — must match
    /// `signing_key.aid()`).
    pub sender_aid: &'a Aid,
    /// Receiver's AID (the verifying peer). For an Initiator's HELLO
    /// this is the peer AID (caller fetched from peer Manifest); for
    /// a Responder's HELLO_ACK this is the responder's own AID since
    /// the *initiator* is the sender of HELLO and receiver of HELLO_ACK
    /// — see RFC-AITP-0002 §3.1 for the exact role mapping.
    pub receiver_aid: &'a Aid,
    /// Outbound envelope's `message_id`.
    pub envelope_message_id: &'a Uuid,
    /// Outbound envelope's `timestamp`.
    pub envelope_timestamp: Timestamp,
    /// `pop_nonce` carried by the outbound payload (the holder's own
    /// nonce on HELLO/HELLO_ACK).
    pub pop_nonce: &'a str,
}

/// An OIDC mint callback: receives the handshake-generated `pop_nonce`
/// and returns a freshly-minted compact JWT whose `nonce` claim equals
/// that nonce. `Send + Sync`, so a configuration holding one can be
/// moved into a spawned task (`facade::IdentityMode::Oidc`). A
/// `Box<OidcMintJwtFn>` coerces into a `Box<LocalOidcMintJwtFn>`.
pub type OidcMintJwtFn = dyn Fn(&str) -> Result<String, OidcMintError> + Send + Sync;

/// The mint callback of [`PresentedIdentity::OidcMinter`]. It need not be
/// `Send`: the state machine calls it inside the `Initiator::start` or
/// `Responder::on_hello` call that receives it, so a binding can wrap a
/// host-runtime callable.
pub type LocalOidcMintJwtFn = dyn Fn(&str) -> Result<String, OidcMintError>;

/// The error an OIDC mint callback returns. The handshake reports it as
/// `IDENTITY_FAILED` before anything is sent.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct OidcMintError(crate::core::BoxError);

impl OidcMintError {
    /// Wrap the callback's own error, or a message.
    pub fn new(error: impl Into<crate::core::BoxError>) -> Self {
        Self(error.into())
    }
}

/// What identity this peer will present.
#[non_exhaustive]
pub enum PresentedIdentity {
    /// Self-sign a pinned-key proof over `message_id|timestamp` of the
    /// envelope being sent.
    PinnedKey {
        /// Subject identifier (free-form; bound to the AID's pubkey).
        subject: String,
    },
    /// Use a JWT supplied by the caller (already minted by the IdP). The
    /// caller is responsible for ensuring the JWT's `nonce` claim matches
    /// the handshake-generated nonce; for use cases where the nonce is
    /// known up-front (e.g. fixture-driven tests), prefer
    /// [`PresentedIdentity::oidc_checked`] which validates this at
    /// construction time. For use cases where the JWT must be minted with
    /// the handshake-generated nonce, use [`PresentedIdentity::OidcMinter`].
    Oidc {
        /// OIDC issuer URI.
        issuer: url::Url,
        /// Subject identifier at the issuer.
        subject: String,
        /// Compact-serialized JWT to embed.
        proof_jwt: String,
    },
    /// Defer JWT minting until the handshake nonce is generated. The
    /// state machine calls `mint_jwt(&pop_nonce)` while building the
    /// outbound payload; the returned JWT must have its `nonce` claim
    /// equal to that nonce (the receiving peer's `verify_oidc` enforces
    /// this).
    ///
    /// This is the production-grade OIDC presentation path — it removes
    /// the need to pre-mint a JWT with a guessed nonce and re-mint on
    /// state-machine output (the awkward dance the `Oidc` variant
    /// otherwise requires).
    OidcMinter {
        /// OIDC issuer URI.
        issuer: url::Url,
        /// Subject identifier at the issuer.
        subject: String,
        /// Callback that receives the just-generated `pop_nonce` and
        /// returns a freshly-minted compact JWT. Errors bubble out as
        /// `HandshakeError::Identity`.
        mint_jwt: Box<LocalOidcMintJwtFn>,
    },
}

impl std::fmt::Debug for PresentedIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PinnedKey { subject } => f
                .debug_struct("PinnedKey")
                .field("subject", subject)
                .finish(),
            Self::Oidc {
                issuer, subject, ..
            } => f
                .debug_struct("Oidc")
                .field("issuer", issuer)
                .field("subject", subject)
                .finish_non_exhaustive(),
            Self::OidcMinter {
                issuer, subject, ..
            } => f
                .debug_struct("OidcMinter")
                .field("issuer", issuer)
                .field("subject", subject)
                .finish_non_exhaustive(),
        }
    }
}

/// Extract the `nonce` claim from a compact JWT **without** verifying
/// its signature. Returns `Ok(None)` when the claim is absent.
///
/// This reads only the (base64url) claims segment; signature
/// verification is the receiving peer's responsibility against the
/// issuer's resolved key.
fn jwt_nonce_claim(jwt: &str) -> Result<Option<String>, HandshakeError> {
    let mut parts = jwt.split('.');
    let payload = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(_header), Some(payload), Some(_sig), None) => payload,
        _ => {
            return Err(HandshakeError::Identity(
                "OIDC proof_jwt is not a compact JWS (expected three dot-separated segments)"
                    .into(),
            ))
        }
    };
    let decoded = base64url::decode_strict(payload).map_err(|_| {
        HandshakeError::Identity("OIDC proof_jwt claims segment is not valid base64url".into())
    })?;
    let claims: serde_json::Value = serde_json::from_slice(&decoded).map_err(|_| {
        HandshakeError::Identity("OIDC proof_jwt claims segment is not valid JSON".into())
    })?;
    Ok(claims
        .get("nonce")
        .and_then(|v| v.as_str())
        .map(String::from))
}

impl PresentedIdentity {
    /// Construct an OIDC `PresentedIdentity`, validating at construction
    /// time that the JWT's `nonce` claim equals `pop_nonce` — the
    /// handshake nonce the proof will be bound to (RFC-AITP-0002 §3.1).
    ///
    /// This is a defensive check *in addition to* the receiving peer's
    /// `verify_oidc`: it surfaces a stale or mismatched JWT before the
    /// HELLO is sent rather than after a network round trip. The JWT's
    /// **signature is not verified here** — that remains the receiving
    /// peer's responsibility against the issuer's resolved key.
    ///
    /// Use this when the handshake `pop_nonce` is known before the JWT
    /// is minted (e.g. the caller drives [`Initiator`] and re-mints the
    /// JWT once the nonce is available). The plain
    /// [`PresentedIdentity::Oidc`] variant skips the construction-time
    /// check.
    pub fn oidc_checked(
        proof_jwt: &str,
        pop_nonce: &str,
        issuer: url::Url,
        subject: String,
    ) -> Result<Self, HandshakeError> {
        match jwt_nonce_claim(proof_jwt)? {
            Some(nonce) if nonce == pop_nonce => Ok(Self::Oidc {
                issuer,
                subject,
                proof_jwt: proof_jwt.to_string(),
            }),
            Some(other) => Err(HandshakeError::Identity(format!(
                "OIDC proof_jwt nonce claim `{other}` does not match handshake pop_nonce"
            ))),
            None => Err(HandshakeError::Identity(
                "OIDC proof_jwt has no `nonce` claim to bind to the handshake pop_nonce".into(),
            )),
        }
    }

    /// Mint the `IdentityDescriptor` to embed in an outbound payload.
    ///
    /// For pinned-key, this signs over the full RFC-AITP-0002 §3.1
    /// proof input (sender + receiver + message_id + timestamp +
    /// pop_nonce). For OIDC, this validates that the supplied JWT's
    /// `nonce` claim matches `ctx.pop_nonce` — a defensive check at
    /// construction time, in addition to the receiving peer's
    /// signature-and-nonce verification.
    fn build_descriptor(
        &self,
        ctx: &IdentityPresentationContext<'_>,
        signing_key: &dyn AitpSigner,
    ) -> Result<IdentityDescriptor, HandshakeError> {
        match self {
            Self::PinnedKey { subject } => {
                // RFC-AITP-0002 §3.3 (proposal #72 Item 2): `public_key`
                // is the AID-identifier form for the key's algorithm, 32
                // raw bytes (Ed25519) or a 33-byte SEC1 compressed point
                // (P-256). A P-256 proof is `p256.`-tagged by `sign_jcs`.
                let pk_bytes = AitpVerifyingKey::from_aid(signing_key.aid())?.to_compressed();
                let proof = sign_pinned_key_proof(
                    signing_key,
                    ctx.sender_aid,
                    ctx.receiver_aid,
                    ctx.envelope_message_id,
                    ctx.envelope_timestamp,
                    ctx.pop_nonce,
                )?;
                Ok(IdentityDescriptor::pinned_key(
                    subject.clone(),
                    base64url::encode(&pk_bytes),
                    proof,
                ))
            }
            Self::Oidc {
                issuer,
                subject,
                proof_jwt,
            } => {
                // Note: per Phase 2.4 of the unified plan we considered
                // adding a defensive construction-time check that
                // `proof_jwt`'s `nonce` claim equals `ctx.pop_nonce`.
                // The receiving peer already verifies that under
                // `verify_oidc`, and the construction-time check
                // conflicts with the common test pattern of
                // pre-minting a JWT then re-minting once the
                // handshake-generated nonce is known. Left to a
                // future logging-aware revisit (plans/defered/deferred.md).
                Ok(IdentityDescriptor::oidc(
                    crate::core::RawUrl::from(issuer.clone()),
                    subject.clone(),
                    proof_jwt.clone(),
                ))
            }
            Self::OidcMinter {
                issuer,
                subject,
                mint_jwt,
            } => {
                let proof = mint_jwt(ctx.pop_nonce).map_err(|e| {
                    HandshakeError::Identity(format!("oidc mint_jwt callback failed: {e}"))
                })?;
                Ok(IdentityDescriptor::oidc(
                    crate::core::RawUrl::from(issuer.clone()),
                    subject.clone(),
                    proof,
                ))
            }
        }
    }
}

/// Generate a fresh 22-char base64url-unpadded nonce (128 random bits).
fn fresh_nonce() -> Result<String, HandshakeError> {
    let mut buf = [0u8; 16];
    rand::rngs::SysRng
        .try_fill_bytes(&mut buf)
        .map_err(|e| HandshakeError::Rng(e.into()))?;
    Ok(base64url::encode(&buf))
}

/// Bootstrap-verify a peer's Manifest + identity proof
/// (RFC-AITP-0004 §5.1 steps 3–6).
///
/// Returns the peer's verifying key on success.
pub(crate) fn bootstrap_verify_peer(
    envelope: &AitpEnvelope,
    payload_manifest: &Manifest,
    payload_identity: &IdentityDescriptor,
    payload_pop_nonce: &str,
    cfg: &PeerConfig<'_>,
) -> Result<AitpVerifyingKey, HandshakeError> {
    if payload_manifest.aid != envelope.sender.agent_id {
        return Err(HandshakeError::InvalidEnvelope(
            "manifest.aid does not match sender.agent_id".into(),
        ));
    }
    verify_manifest(payload_manifest, &ManifestVerifyContext { now: cfg.now })?;
    if payload_identity.subject != payload_manifest.identity_hint.subject {
        return Err(HandshakeError::Identity(
            "identity.subject != manifest.identity_hint.subject".into(),
        ));
    }
    // RFC-AITP-0002 §3 / RFC-AITP-0004 §5.1: the proof's mechanism
    // (`identity.kind`) MUST match the manifest's advertised
    // mechanism (`identity_hint.kind`). Without this check, a peer
    // whose manifest advertises OIDC could present a pinned-key proof
    // and bypass OIDC trust-anchor checks (type confusion).
    let expected_kind = match payload_manifest.identity_hint.kind {
        crate::manifest::IdentityHintKind::Oidc => IdentityKind::Oidc,
        crate::manifest::IdentityHintKind::PinnedKey => IdentityKind::PinnedKey,
        crate::manifest::IdentityHintKind::Spiffe => IdentityKind::Spiffe,
    };
    if payload_identity.kind != expected_kind {
        return Err(HandshakeError::Identity(
            "identity.type does not match manifest.identity_hint.type".into(),
        ));
    }
    // RFC-AITP-0002 §6.1: `svid_type` and `x5c` belong to `spiffe` only.
    if payload_identity.kind != IdentityKind::Spiffe
        && (payload_identity.svid_type.is_some() || payload_identity.x5c.is_some())
    {
        return Err(HandshakeError::Identity(format!(
            "{} descriptor must not carry svid_type or x5c",
            payload_identity.kind.as_str()
        )));
    }
    match payload_identity.kind {
        IdentityKind::Oidc => {
            let issuer = payload_identity
                .issuer
                .as_ref()
                .ok_or_else(|| HandshakeError::Identity("oidc missing issuer".into()))?;
            if Some(issuer) != payload_manifest.identity_hint.issuer.as_ref() {
                return Err(HandshakeError::Identity("issuer hint mismatch".into()));
            }
            let ctx = OidcVerifyContext {
                expected_audience: &cfg.manifest.aid,
                expected_nonce: payload_pop_nonce,
                trust_anchors: cfg.trust_anchors,
                jwks_resolver: cfg.jwks_resolver,
                subject_aid: &payload_manifest.aid,
                iat_tolerance: crate::core::DEFAULT_TIMESTAMP_TOLERANCE,
                now: cfg.now,
            };
            verify_oidc(payload_identity, &ctx)?;
        }
        IdentityKind::PinnedKey => {
            // RFC-AITP-0002 §3.2: type, key binding and the trust store
            // are all checked inside, before the proof.
            let verified = verify_pinned_key(
                payload_identity,
                &PinnedKeyVerifyContext {
                    sender_aid: &payload_manifest.aid,
                    receiver_aid: &cfg.manifest.aid,
                    message_id: &envelope.message_id,
                    timestamp: envelope.timestamp,
                    pop_nonce: payload_pop_nonce,
                    subject: Default::default(),
                },
                cfg.pinned_key_store,
            )?;
            return Ok(verified.key);
        }
        kind => {
            // RFC-AITP-0002 §6.6: a type no verifier handles is rejected
            // even when our Manifest lists it.
            let verifier = cfg.identity_verifier.filter(|v| v.handles(kind)).ok_or(
                crate::manifest::ManifestError::IncompatibleIdentityType(kind.as_str()),
            )?;
            let verified = verifier.verify(
                payload_identity,
                &IdentityVerifyContext {
                    peer_manifest: payload_manifest,
                    sender_aid: &payload_manifest.aid,
                    receiver_aid: &cfg.manifest.aid,
                    message_id: &envelope.message_id,
                    timestamp: envelope.timestamp,
                    pop_nonce: payload_pop_nonce,
                    now: cfg.now,
                },
            )?;
            if verified.kind() != kind || verified.subject() != payload_identity.subject {
                return Err(HandshakeError::Identity(
                    "the identity verifier proved a different identity than the one presented"
                        .into(),
                ));
            }
        }
    }
    AitpVerifyingKey::from_aid(&payload_manifest.aid).map_err(Into::into)
}

/// Apply our identity-type policy to a bootstrapped peer (RFC-AITP-0004
/// §5.1 step 8 / §5.2): the peer's `identity.type` MUST appear in our own
/// `accepted_identity_types` (absent means `["oidc"]`), else
/// `INCOMPATIBLE_IDENTITY_TYPE`.
///
/// Call it only after [`bootstrap_verify_peer`] (step 6) and the envelope
/// signature (step 7) pass: the order is frozen, so a payload failing both
/// the proof and this check reports `IDENTITY_FAILED`. The OIDC
/// trust-anchor check stays inside the proof, before any JWKS fetch.
pub(crate) fn apply_peer_policy(
    payload_identity: &IdentityDescriptor,
    cfg: &PeerConfig<'_>,
) -> Result<(), HandshakeError> {
    crate::manifest::check_identity_type_compatibility(
        cfg.manifest,
        payload_identity.kind.as_str(),
    )?;
    Ok(())
}

/// Round-2 PoP: `sign(my_key, sha256(base64url_decode(peer_nonce)))`.
///
/// Per RFC-AITP-0004 §3 (preamble), `sha256(<nonce>)` denotes the SHA-256
/// hash of the **raw bytes obtained by base64url-decoding the nonce
/// string** — not the ASCII bytes of the base64url encoding. This brings
/// the handshake PoP into alignment with the TCT downstream PoP in
/// `aitp::tct::pop`.
fn sign_pop(my_key: &dyn AitpSigner, peer_nonce: &str) -> Result<String, HandshakeError> {
    let nonce_bytes = base64url::decode_strict(peer_nonce)
        .map_err(|_| HandshakeError::InvalidEnvelope("pop nonce is not valid base64url".into()))?;
    let digest = crate::crypto::Digest32::sha256(&nonce_bytes);
    Ok(crate::crypto::sign_jcs(my_key, &digest)
        .map_err(CryptoError::Signer)?
        .into_string())
}

/// Round-2 PoP verify.
fn verify_pop(
    peer_pubkey: &AitpVerifyingKey,
    my_nonce: &str,
    pop_signature: &str,
) -> Result<(), HandshakeError> {
    let nonce_bytes =
        base64url::decode_strict(my_nonce).map_err(|_| HandshakeError::PopVerificationFailed)?;
    let digest = crate::crypto::Digest32::sha256(&nonce_bytes);
    let sig = Signature::parse(pop_signature).map_err(|_| HandshakeError::PopVerificationFailed)?;
    peer_pubkey
        .verify_jcs(&digest, &sig)
        .map_err(|_| HandshakeError::PopVerificationFailed)
}

/// Build a TCT for the peer.
///
/// Grants are the three-way intersection per RFC-AITP-0004 §4.1:
///
/// ```text
///   peer_requested ∩ identity_policy(peer_identity, ...) ∩ self.offered
/// ```
///
/// Empty intersection ⇒ `PolicyViolation`. The TCT's `expires_at` is
/// bounded by `cfg.manifest.expires_at` per RFC-AITP-0004 §4.3 — a
/// peer-issued TCT MUST NOT outlive the issuing peer's own Manifest,
/// because the issuer's keys could legitimately rotate at that point.
fn issue_tct_for_peer(
    cfg: &PeerConfig<'_>,
    peer_identity: &IdentityDescriptor,
    peer_aid: &Aid,
    peer_pubkey: &AitpVerifyingKey,
    peer_requested: &[String],
) -> Result<IssuedTct, HandshakeError> {
    let mut grants: Vec<String> = peer_requested
        .iter()
        .filter(|g| cfg.manifest.offered_capabilities.contains(g))
        .cloned()
        .collect();
    if let Some(policy) = cfg.grant_policy {
        let permitted = policy(&GrantPolicyContext {
            peer_identity,
            peer_aid,
            candidate_grants: &grants,
            now: cfg.now,
        })?;
        grants.retain(|g| permitted.contains(g));
    }
    if grants.is_empty() {
        return Err(HandshakeError::PolicyViolation);
    }

    // Bound expiry by the issuing-peer Manifest's expiry. If our own
    // Manifest is already past expiry, refuse to issue.
    let manifest_expires = cfg.manifest.expires_at.0;
    let default_expires = cfg.now.saturating_add(crate::tct::DEFAULT_TCT_TTL).0;
    let effective_expires = default_expires.min(manifest_expires);
    let ttl = effective_expires.saturating_sub(cfg.now.0);
    let Ok(ttl @ 1..) = u64::try_from(ttl) else {
        return Err(HandshakeError::InvalidEnvelope(
            "issuing peer's manifest is expired; cannot issue TCT".into(),
        ));
    };
    TctBuilder::new(cfg.signing_key)
        .subject(peer_aid.clone())
        .audience(peer_aid.clone())
        .grants(grants)
        .ttl(std::time::Duration::from_secs(ttl))
        .subject_pubkey(peer_pubkey.clone())
        .issued_at(cfg.now)
        .build()
        .map_err(HandshakeError::Tct)
}

/// Verify a peer-issued TCT compact JWS (and its optional companion
/// voucher) and that it satisfies our `required_peer_capabilities`.
///
/// Returns the verified TCT; its `effective_grants` are the grants the
/// verifying side honors, narrowed under a revocation soft-fail safe
/// subset (RFC-AITP-0008).
fn verify_received_tct(
    token: &str,
    grant_voucher: Option<&str>,
    cfg: &PeerConfig<'_>,
    issuer: &Aid,
    issuer_manifest_expires_at: Option<Timestamp>,
    issuer_offered_capabilities: &[String],
) -> Result<VerifiedTct, HandshakeError> {
    // RFC-AITP-0008 §3.3: the TCT signature MUST be verified before any
    // remote revocation lookup. The claims are attacker-controlled
    // bytes until `verify_tct` succeeds; routing a revocation lookup
    // through them first turns the verifier into a reflector for
    // network-amplification DoS. The issuer AID (and therefore the
    // sole acceptable key and JWS alg) comes from the handshake state,
    // not from the token.
    let ctx = {
        let builder = TctVerifyContext::builder(&cfg.manifest.aid, issuer, cfg.now)
            .revocation(cfg.revocation.clone());
        // RFC-AITP-0004 §4.3 / RFC-AITP-0005 §10.4: the issuer Manifest's
        // expiry caps the TCT's expiry. We have it in scope from
        // bootstrap_verify_peer (initiator) or hello.manifest (responder)
        // when available; §10.4 permits skipping when it is not.
        let builder = match issuer_manifest_expires_at {
            Some(exp) => builder.issuer_manifest_expires_at(exp),
            None => builder.skip_manifest_expiry_cap_dangerous(),
        };
        builder
            .build()
            .expect("both verify decisions are made above")
    };
    // The revocation lookup runs below, after the voucher and
    // grant-overflow checks.
    let claims = verify_tct_before_revocation(token, &ctx)?;

    // Companion voucher (when delivered): MUST verify under the same
    // issuer and mirror the TCT exactly (RFC-AITP-0005 §8.2). A
    // mismatched voucher is an issuance bug or tampering — reject
    // rather than store a delegation credential we can't use.
    if let Some(voucher_token) = grant_voucher {
        let voucher = crate::tct::verify_voucher(voucher_token, issuer)?;
        if voucher.sub != claims.sub
            || voucher.grants != claims.grants
            || voucher.iat != claims.iat
            || voucher.exp != claims.exp
            || voucher.src_jti != claims.jti
        {
            return Err(HandshakeError::Tct(crate::tct::TctError::ClaimsMalformed(
                "grant voucher does not mirror the companion TCT".into(),
            )));
        }
    }

    // Grant-overflow (RFC-AITP-0004 §5.3/§5.4 step 4): a peer's TCT MUST
    // NOT grant capabilities outside that peer's own advertised
    // `offered_capabilities`. Maps to `GRANT_OVERFLOW`.
    for grant in &claims.grants {
        if !issuer_offered_capabilities.contains(grant) {
            return Err(HandshakeError::GrantOverflow);
        }
    }

    // Revocation — `iss` and `jti` are authenticated now that the TCT
    // has verified under the handshake-pinned issuer AID, so a hook
    // keyed off the issuer cannot be steered by an attacker. An empty
    // soft-fail intersection is a policy failure.
    let effective_grants = match check_revocation(&ctx.revocation, &claims, cfg.now) {
        Ok(grants) => grants,
        Err(TctError::SafeSubsetEmpty) => return Err(HandshakeError::PolicyViolation),
        Err(e) => return Err(HandshakeError::Tct(e)),
    };

    // `required_peer_capabilities` is checked against the effective
    // grant set — under soft-fail, the safe subset must cover every
    // required cap.
    if let Some(required_caps) = cfg.manifest.required_peer_capabilities.as_deref() {
        for required in required_caps {
            if !effective_grants.contains(required) {
                return Err(HandshakeError::InsufficientGrants);
            }
        }
    }
    Ok(VerifiedTct {
        token: token.to_string(),
        claims,
        effective_grants,
    })
}

/// What a completed handshake leaves each side holding: the peer-issued
/// TCT (verbatim token + trusted claims) and, when the peer's policy
/// allowed delegation, the companion grant voucher to delegate with
/// later (RFC-AITP-0005 §8).
///
/// Only this crate constructs it, and its fields are read-only:
/// [`Self::into_parts`] hands out the owned pieces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletedHandshake {
    pub(crate) tct: VerifiedTct,
    pub(crate) grant_voucher: Option<String>,
    pub(crate) effective_grants: Vec<String>,
}

impl CompletedHandshake {
    /// The TCT the peer issued to us.
    pub fn tct(&self) -> &VerifiedTct {
        &self.tct
    }

    /// The companion grant voucher, verbatim. `None` when the issuing
    /// peer's policy forbids us from delegating.
    pub fn grant_voucher(&self) -> Option<&str> {
        self.grant_voucher.as_deref()
    }

    /// The grants we may exercise under the peer-issued TCT: its
    /// `grants`, narrowed to the safe subset when the revocation source
    /// answered [`crate::tct::RevocationStatus::SoftFailSafeSubset`].
    pub fn effective_grants(&self) -> &[String] {
        &self.effective_grants
    }

    /// The owned pieces.
    pub fn into_parts(self) -> CompletedHandshakeParts {
        CompletedHandshakeParts {
            tct: self.tct,
            grant_voucher: self.grant_voucher,
            effective_grants: self.effective_grants,
        }
    }
}

/// The owned pieces of a [`CompletedHandshake`], from [`CompletedHandshake::into_parts`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CompletedHandshakeParts {
    /// See [`CompletedHandshake::tct`].
    pub tct: VerifiedTct,
    /// See [`CompletedHandshake::grant_voucher`].
    pub grant_voucher: Option<String>,
    /// See [`CompletedHandshake::effective_grants`].
    pub effective_grants: Vec<String>,
}

// ── Initiator ────────────────────────────────────────────────────────────

/// Initiator-side handshake driver.
pub struct Initiator {
    state: InitiatorState,
}

impl std::fmt::Debug for Initiator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Initiator").finish_non_exhaustive()
    }
}

#[allow(dead_code, clippy::large_enum_variant)] // size diff between Done/Failed and Awaiting* is acceptable.
enum InitiatorState {
    AwaitingHelloAck {
        session_id: SessionId,
        my_pop_nonce: String,
        // The AID the initiator intends to authenticate (the peer whose
        // Manifest was fetched and whose `handshake_endpoint` the HELLO
        // was POSTed to). The HELLO_ACK's identity MUST belong to this
        // AID — see `on_hello_ack`.
        intended_peer_aid: Aid,
    },
    AwaitingCommitAck {
        session_id: SessionId,
        my_pop_nonce: String,
        peer_aid: Aid,
        peer_pubkey: AitpVerifyingKey,
        // The peer Manifest's `expires_at`, captured during HELLO_ACK.
        // Passed back into `verify_received_tct` on COMMIT_ACK so the
        // TCT's `expires_at` can be capped by the issuer Manifest's
        // expiry per RFC-AITP-0004 §4.3 / RFC-AITP-0005 §9.
        peer_manifest_expires_at: Timestamp,
        // The peer Manifest's `offered_capabilities`, captured during
        // HELLO_ACK. Used on COMMIT_ACK to reject a peer-issued TCT that
        // grants more than the peer advertises (GRANT_OVERFLOW).
        peer_offered_capabilities: Vec<String>,
        // The peer Manifest's advertised `ListRevoked` URL, if any
        // (RFC-AITP-0008 §1.4). See `peer_revocation_list_uri`.
        peer_revocation_list_uri: Option<String>,
    },
    Done,
    Failed,
}

/// The `rfc-aitp-0008.revocation_list_uri` extension of a Manifest, as
/// a raw string. The transport validates it (HTTPS only) before use.
fn revocation_list_uri(manifest: &Manifest) -> Option<String> {
    manifest
        .extensions
        .as_ref()?
        .get(crate::manifest::REVOCATION_LIST_URI_EXT)?
        .as_str()
        .map(str::to_owned)
}

impl Initiator {
    /// The `ListRevoked` URL the peer's Manifest advertises
    /// (RFC-AITP-0008 §1.4), available after [`Self::on_hello_ack`]
    /// verifies that Manifest. A caller that fetches revocation
    /// asynchronously reads it here to prepare the
    /// [`RevocationSource`] for [`Self::on_commit_ack`]. `None` before
    /// HELLO_ACK, after completion, or when the Manifest has none.
    pub fn peer_revocation_list_uri(&self) -> Option<&str> {
        match &self.state {
            InitiatorState::AwaitingCommitAck {
                peer_revocation_list_uri,
                ..
            } => peer_revocation_list_uri.as_deref(),
            _ => None,
        }
    }

    /// The peer AID authenticated by [`Self::on_hello_ack`]; the issuer
    /// of the TCT [`Self::on_commit_ack`] will verify.
    pub fn peer_aid(&self) -> Option<&Aid> {
        match &self.state {
            InitiatorState::AwaitingCommitAck { peer_aid, .. } => Some(peer_aid),
            _ => None,
        }
    }

    /// Begin a new handshake. Returns the session and the
    /// `MutualHelloPayload` to wrap in an envelope and POST.
    ///
    /// `peer_aid` is the receiving peer's AID — typically obtained by
    /// fetching the peer's Manifest before the handshake starts. It
    /// is required because the pinned-key proof input binds both
    /// sender AND receiver (RFC-AITP-0002 §3.1) to defend against
    /// cross-peer replay.
    pub fn start(
        cfg: &PeerConfig<'_>,
        identity: PresentedIdentity,
        peer_aid: &Aid,
        envelope_message_id: &Uuid,
        envelope_timestamp: Timestamp,
        requested_grants: Vec<String>,
    ) -> Result<(Self, MutualHelloPayload), HandshakeError> {
        let session_id = Uuid::new_v4();
        debug!(
            initiator_aid = %cfg.signing_key.aid(),
            peer_aid = %peer_aid,
            %session_id,
            "handshake start (Initiator → AwaitingHelloAck)"
        );
        let pop_nonce = fresh_nonce()?;
        let descriptor = identity.build_descriptor(
            &IdentityPresentationContext {
                sender_aid: cfg.signing_key.aid(),
                receiver_aid: peer_aid,
                envelope_message_id,
                envelope_timestamp,
                pop_nonce: &pop_nonce,
            },
            cfg.signing_key,
        )?;
        let payload = MutualHelloPayload {
            identity: descriptor,
            manifest: cfg.manifest.clone(),
            requested_grants,
            pop_nonce: pop_nonce.clone(),
            extensions: None,
        };
        Ok((
            Self {
                state: InitiatorState::AwaitingHelloAck {
                    session_id,
                    my_pop_nonce: pop_nonce,
                    intended_peer_aid: peer_aid.clone(),
                },
            },
            payload,
        ))
    }

    /// Process MUTUAL_HELLO_ACK; produce MUTUAL_COMMIT.
    pub fn on_hello_ack(
        &mut self,
        envelope: &AitpEnvelope,
        ack: &MutualHelloAckPayload,
        cfg: &PeerConfig<'_>,
    ) -> Result<MutualCommitPayload, HandshakeError> {
        let (session_id, my_pop_nonce, intended_peer_aid) = match &self.state {
            InitiatorState::AwaitingHelloAck {
                session_id,
                my_pop_nonce,
                intended_peer_aid,
            } => (*session_id, my_pop_nonce.clone(), intended_peer_aid.clone()),
            _ => return Err(HandshakeError::State("on_hello_ack out of order")),
        };
        debug!(
            %session_id,
            message_id = %envelope.message_id,
            "Initiator: AwaitingHelloAck → AwaitingCommitAck"
        );
        // RFC-AITP-0004 §5.2 step 3: the HELLO_ACK sender is the peer
        // this initiator addressed (PEER_MISMATCH). Step 4: the presented
        // Manifest is the sender's (INVALID_ENVELOPE).
        if envelope.sender.agent_id != intended_peer_aid {
            self.state = InitiatorState::Failed;
            return Err(HandshakeError::PeerMismatch);
        }
        if ack.manifest.aid != intended_peer_aid {
            self.state = InitiatorState::Failed;
            return Err(HandshakeError::InvalidEnvelope(
                "HELLO_ACK manifest AID does not match the intended peer".into(),
            ));
        }
        if ack.pop_nonce_echo != my_pop_nonce {
            self.state = InitiatorState::Failed;
            return Err(HandshakeError::NonceMismatch);
        }
        let peer_pubkey = match bootstrap_verify_peer(
            envelope,
            &ack.manifest,
            &ack.identity,
            &ack.pop_nonce,
            cfg,
        ) {
            Ok(p) => p,
            Err(e) => {
                self.state = InitiatorState::Failed;
                return Err(e);
            }
        };
        if let Err(e) = apply_peer_policy(&ack.identity, cfg) {
            self.state = InitiatorState::Failed;
            return Err(e);
        }
        let issued = issue_tct_for_peer(
            cfg,
            &ack.identity,
            &ack.manifest.aid,
            &peer_pubkey,
            &ack.requested_grants,
        )?;
        let pop_signature = sign_pop(cfg.signing_key, &ack.pop_nonce)?;
        let commit = MutualCommitPayload {
            tct: issued.token,
            grant_voucher: issued.voucher,
            pop_signature,
            pop_nonce_echo: ack.pop_nonce.clone(),
            extensions: None,
        };
        self.state = InitiatorState::AwaitingCommitAck {
            session_id,
            my_pop_nonce,
            peer_aid: ack.manifest.aid.clone(),
            peer_pubkey,
            peer_manifest_expires_at: ack.manifest.expires_at,
            peer_offered_capabilities: ack.manifest.offered_capabilities.clone(),
            peer_revocation_list_uri: revocation_list_uri(&ack.manifest),
        };
        Ok(commit)
    }

    /// Process MUTUAL_COMMIT_ACK; return the peer-issued TCT (and
    /// companion voucher) we now hold.
    pub fn on_commit_ack(
        &mut self,
        envelope: &AitpEnvelope,
        ack: &MutualCommitAckPayload,
        cfg: &PeerConfig<'_>,
    ) -> Result<CompletedHandshake, HandshakeError> {
        debug!(
            message_id = %envelope.message_id,
            "Initiator: AwaitingCommitAck → Done"
        );
        let (peer_aid, peer_pubkey, my_pop_nonce, peer_manifest_expires_at, peer_offered_caps) =
            match &self.state {
                InitiatorState::AwaitingCommitAck {
                    peer_aid,
                    peer_pubkey,
                    my_pop_nonce,
                    peer_manifest_expires_at,
                    peer_offered_capabilities,
                    ..
                } => (
                    peer_aid.clone(),
                    peer_pubkey.clone(),
                    my_pop_nonce.clone(),
                    *peer_manifest_expires_at,
                    peer_offered_capabilities.clone(),
                ),
                _ => return Err(HandshakeError::State("on_commit_ack out of order")),
            };
        if envelope.sender.agent_id != peer_aid {
            self.state = InitiatorState::Failed;
            return Err(HandshakeError::InvalidEnvelope(
                "commit_ack sender mismatch".into(),
            ));
        }
        if ack.pop_nonce_echo != my_pop_nonce {
            self.state = InitiatorState::Failed;
            return Err(HandshakeError::NonceMismatch);
        }
        verify_pop(&peer_pubkey, &my_pop_nonce, &ack.pop_signature)?;
        let verified = verify_received_tct(
            &ack.tct,
            ack.grant_voucher.as_deref(),
            cfg,
            &peer_aid,
            Some(peer_manifest_expires_at),
            &peer_offered_caps,
        )?;
        self.state = InitiatorState::Done;
        Ok(CompletedHandshake {
            effective_grants: verified.effective_grants.clone(),
            tct: verified,
            grant_voucher: ack.grant_voucher.clone(),
        })
    }
}

// ── Responder ────────────────────────────────────────────────────────────

/// Responder-side handshake driver.
pub struct Responder {
    state: ResponderState,
}

impl std::fmt::Debug for Responder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Responder").finish_non_exhaustive()
    }
}

#[allow(dead_code, clippy::large_enum_variant)] // size diff between Done/Failed and AwaitingCommit is acceptable.
enum ResponderState {
    AwaitingCommit {
        session_id: SessionId,
        my_pop_nonce: String,
        peer_pop_nonce: String,
        peer_aid: Aid,
        peer_pubkey: AitpVerifyingKey,
        peer_requested_grants: Vec<String>,
        // Captured from MUTUAL_HELLO after `bootstrap_verify_peer`
        // succeeds, then handed to `issue_tct_for_peer` so the
        // responder's `grant_policy` sees the same identity the
        // initiator's `grant_policy` saw — symmetric policy across
        // both peers (RFC-AITP-0004 §4.1).
        peer_identity: IdentityDescriptor,
        // The peer Manifest's `expires_at` from MUTUAL_HELLO. Passed
        // back into `verify_received_tct` on COMMIT so the TCT's
        // `expires_at` can be capped by the issuer Manifest's expiry
        // (RFC-AITP-0004 §4.3 / RFC-AITP-0005 §9).
        peer_manifest_expires_at: Timestamp,
        // The peer Manifest's `offered_capabilities` from MUTUAL_HELLO.
        // Used on COMMIT to reject a peer-issued TCT that grants more
        // than the peer advertises (GRANT_OVERFLOW).
        peer_offered_capabilities: Vec<String>,
        // The peer Manifest's advertised `ListRevoked` URL, if any.
        peer_revocation_list_uri: Option<String>,
    },
    Done,
    Failed,
}

impl Responder {
    /// The `ListRevoked` URL the initiator's Manifest advertises
    /// (RFC-AITP-0008 §1.4), available after [`Self::on_hello`]
    /// verifies that Manifest. A server that fetches revocation
    /// asynchronously reads it here to prepare the
    /// [`RevocationSource`] for [`Self::on_commit`]. `None` after
    /// completion or when the Manifest has none.
    pub fn peer_revocation_list_uri(&self) -> Option<&str> {
        match &self.state {
            ResponderState::AwaitingCommit {
                peer_revocation_list_uri,
                ..
            } => peer_revocation_list_uri.as_deref(),
            _ => None,
        }
    }

    /// The initiator AID authenticated by [`Self::on_hello`]; the
    /// issuer of the TCT [`Self::on_commit`] will verify.
    pub fn peer_aid(&self) -> Option<&Aid> {
        match &self.state {
            ResponderState::AwaitingCommit { peer_aid, .. } => Some(peer_aid),
            _ => None,
        }
    }

    /// Process MUTUAL_HELLO; return (responder, MUTUAL_HELLO_ACK payload).
    pub fn on_hello(
        envelope: &AitpEnvelope,
        hello: &MutualHelloPayload,
        my_identity: PresentedIdentity,
        ack_envelope_message_id: &Uuid,
        ack_envelope_timestamp: Timestamp,
        cfg: &PeerConfig<'_>,
        my_requested_grants: Vec<String>,
    ) -> Result<(Self, MutualHelloAckPayload), HandshakeError> {
        debug!(
            responder_aid = %cfg.signing_key.aid(),
            initiator_aid = ?envelope.sender.agent_id,
            message_id = %envelope.message_id,
            "Responder: Initial → AwaitingCommit"
        );
        let peer_pubkey = bootstrap_verify_peer(
            envelope,
            &hello.manifest,
            &hello.identity,
            &hello.pop_nonce,
            cfg,
        )?;
        apply_peer_policy(&hello.identity, cfg)?;
        let my_pop_nonce = fresh_nonce()?;
        let descriptor = my_identity.build_descriptor(
            &IdentityPresentationContext {
                sender_aid: cfg.signing_key.aid(),
                receiver_aid: &hello.manifest.aid,
                envelope_message_id: ack_envelope_message_id,
                envelope_timestamp: ack_envelope_timestamp,
                pop_nonce: &my_pop_nonce,
            },
            cfg.signing_key,
        )?;
        let ack = MutualHelloAckPayload {
            identity: descriptor,
            manifest: cfg.manifest.clone(),
            requested_grants: my_requested_grants,
            pop_nonce: my_pop_nonce.clone(),
            pop_nonce_echo: hello.pop_nonce.clone(),
            extensions: None,
        };
        Ok((
            Self {
                state: ResponderState::AwaitingCommit {
                    session_id: Uuid::new_v4(),
                    my_pop_nonce,
                    peer_pop_nonce: hello.pop_nonce.clone(),
                    peer_aid: hello.manifest.aid.clone(),
                    peer_pubkey,
                    peer_requested_grants: hello.requested_grants.clone(),
                    peer_identity: hello.identity.clone(),
                    peer_manifest_expires_at: hello.manifest.expires_at,
                    peer_offered_capabilities: hello.manifest.offered_capabilities.clone(),
                    peer_revocation_list_uri: revocation_list_uri(&hello.manifest),
                },
            },
            ack,
        ))
    }

    /// Process MUTUAL_COMMIT; return (MUTUAL_COMMIT_ACK payload, the
    /// peer-issued TCT + voucher we now hold).
    pub fn on_commit(
        &mut self,
        envelope: &AitpEnvelope,
        commit: &MutualCommitPayload,
        cfg: &PeerConfig<'_>,
    ) -> Result<(MutualCommitAckPayload, CompletedHandshake), HandshakeError> {
        debug!(
            message_id = %envelope.message_id,
            "Responder: AwaitingCommit → Done"
        );
        let (
            peer_aid,
            peer_pubkey,
            my_pop_nonce,
            peer_pop_nonce,
            peer_requested_grants,
            peer_identity,
            peer_manifest_expires_at,
            peer_offered_caps,
        ) = match &self.state {
            ResponderState::AwaitingCommit {
                peer_aid,
                peer_pubkey,
                my_pop_nonce,
                peer_pop_nonce,
                peer_requested_grants,
                peer_identity,
                peer_manifest_expires_at,
                peer_offered_capabilities,
                ..
            } => (
                peer_aid.clone(),
                peer_pubkey.clone(),
                my_pop_nonce.clone(),
                peer_pop_nonce.clone(),
                peer_requested_grants.clone(),
                peer_identity.clone(),
                *peer_manifest_expires_at,
                peer_offered_capabilities.clone(),
            ),
            _ => return Err(HandshakeError::State("on_commit out of order")),
        };
        if envelope.sender.agent_id != peer_aid {
            self.state = ResponderState::Failed;
            return Err(HandshakeError::InvalidEnvelope(
                "commit sender mismatch".into(),
            ));
        }
        if commit.pop_nonce_echo != my_pop_nonce {
            self.state = ResponderState::Failed;
            return Err(HandshakeError::NonceMismatch);
        }
        verify_pop(&peer_pubkey, &my_pop_nonce, &commit.pop_signature)?;
        let verified = verify_received_tct(
            &commit.tct,
            commit.grant_voucher.as_deref(),
            cfg,
            &peer_aid,
            Some(peer_manifest_expires_at),
            &peer_offered_caps,
        )?;

        // Issue our TCT for the initiator using the peer's verified
        // identity captured during MUTUAL_HELLO. RFC-AITP-0004 §4.1
        // requires both peers' grant policies to see the real peer
        // identity (not a placeholder), so policies that branch on
        // identity kind, issuer, or subject behave symmetrically
        // regardless of which side initiated.
        let issued = issue_tct_for_peer(
            cfg,
            &peer_identity,
            &peer_aid,
            &peer_pubkey,
            &peer_requested_grants,
        )?;
        let ack = MutualCommitAckPayload {
            tct: issued.token,
            grant_voucher: issued.voucher,
            pop_signature: sign_pop(cfg.signing_key, &peer_pop_nonce)?,
            pop_nonce_echo: peer_pop_nonce.clone(),
            extensions: None,
        };
        self.state = ResponderState::Done;
        Ok((
            ack,
            CompletedHandshake {
                effective_grants: verified.effective_grants.clone(),
                tct: verified,
                grant_voucher: commit.grant_voucher.clone(),
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::AitpSigningKey;

    /// Build a compact JWT (`header.payload.sig`) with the given claims
    /// JSON. Header and signature are placeholders — `oidc_checked`
    /// reads only the claims segment.
    fn jwt_with_claims(claims_json: &str) -> String {
        let header = base64url::encode(br#"{"alg":"EdDSA","typ":"JWT"}"#);
        let payload = base64url::encode(claims_json.as_bytes());
        let sig = base64url::encode(&[0u8; 64]);
        format!("{header}.{payload}.{sig}")
    }

    #[test]
    fn oidc_checked_accepts_matching_nonce() {
        let jwt = jwt_with_claims(r#"{"nonce":"abc123","sub":"alice"}"#);
        let id = PresentedIdentity::oidc_checked(
            &jwt,
            "abc123",
            "https://idp.example.com".parse().unwrap(),
            "alice".into(),
        )
        .expect("a matching nonce must be accepted");
        assert!(matches!(id, PresentedIdentity::Oidc { .. }));
    }

    #[test]
    fn oidc_checked_rejects_mismatched_nonce() {
        let jwt = jwt_with_claims(r#"{"nonce":"stale-nonce"}"#);
        let err = PresentedIdentity::oidc_checked(
            &jwt,
            "fresh-nonce",
            "https://idp.example.com".parse().unwrap(),
            "alice".into(),
        )
        .expect_err("a mismatched nonce must be rejected");
        assert!(matches!(err, HandshakeError::Identity(_)), "got {err:?}");
    }

    #[test]
    fn oidc_checked_rejects_missing_nonce() {
        let jwt = jwt_with_claims(r#"{"sub":"alice"}"#);
        let err = PresentedIdentity::oidc_checked(
            &jwt,
            "x",
            "https://idp.example.com".parse().unwrap(),
            "alice".into(),
        )
        .expect_err("a JWT with no nonce claim must be rejected");
        assert!(matches!(err, HandshakeError::Identity(_)), "got {err:?}");
    }

    #[test]
    fn oidc_checked_rejects_malformed_jwt() {
        let err = PresentedIdentity::oidc_checked(
            "not-a-compact-jwt",
            "x",
            "https://idp.example.com".parse().unwrap(),
            "alice".into(),
        )
        .expect_err("a non-JWS string must be rejected");
        assert!(matches!(err, HandshakeError::Identity(_)), "got {err:?}");
    }

    #[test]
    fn pinned_key_descriptor_supports_p256_signing_key() {
        // 0.13.x refused P-256 here. Proposal #72 Item 2 makes P-256 a
        // pinned-key algorithm: 44-char compressed `public_key`, tagged
        // proof, and it verifies against a store holding the key.
        let p256 = AitpSigningKey::generate_p256();
        let other = AitpSigningKey::from_ed25519_seed(&[1u8; 32]);
        let mid = Uuid::new_v4();
        let ts = Timestamp(1_700_000_000);
        let nonce = base64url::encode(&[42u8; 16]);
        let ctx = IdentityPresentationContext {
            sender_aid: p256.aid(),
            receiver_aid: other.aid(),
            envelope_message_id: &mid,
            envelope_timestamp: ts,
            pop_nonce: &nonce,
        };
        let id = PresentedIdentity::PinnedKey {
            subject: "p256-agent".into(),
        };
        let desc = id.build_descriptor(&ctx, &p256).expect("P-256 descriptor");
        assert_eq!(desc.public_key.as_deref(), Some(p256.aid().identifier()));
        assert!(desc.proof.starts_with("p256."));
        let store = StaticPinnedKeyStore::new([p256.verifying_key()]);
        let verified = verify_pinned_key(
            &desc,
            &PinnedKeyVerifyContext {
                sender_aid: p256.aid(),
                receiver_aid: other.aid(),
                message_id: &mid,
                timestamp: ts,
                pop_nonce: &nonce,
                subject: Default::default(),
            },
            &store,
        )
        .expect("P-256 pinned key verifies");
        assert_eq!(verified.key, p256.verifying_key());
    }

    fn grant_policy_issue(policy: &GrantPolicyFn) -> Result<Vec<String>, HandshakeError> {
        struct NoKeys;
        impl JwksResolver for NoKeys {
            fn resolve(
                &self,
                _issuer: &url::Url,
            ) -> Result<Vec<crate::handshake::JwkPublicKey>, crate::handshake::ResolveError>
            {
                Ok(vec![])
            }
        }
        let me = AitpSigningKey::from_ed25519_seed(&[0x70; 32]);
        let peer = AitpSigningKey::from_ed25519_seed(&[0x71; 32]);
        let manifest = crate::manifest::ManifestBuilder::new(&me)
            .display_name("issuer")
            .handshake_endpoint("https://example.com/aitp/handshake".parse().unwrap())
            .identity_hint(
                crate::manifest::IdentityHint::new(
                    crate::manifest::IdentityHintKind::PinnedKey,
                    "issuer",
                )
                .with_public_key(me.aid().identifier()),
            )
            .offer("chat.send")
            .offer("files.read")
            .build()
            .unwrap();
        let store = StaticPinnedKeyStore::new([]);
        let cfg = PeerConfig::new(
            &me,
            &manifest,
            &NoKeys,
            &store,
            RevocationSource::FailOpen,
            Timestamp::now(),
        )
        .with_grant_policy(policy);
        let identity: IdentityDescriptor = serde_json::from_value(serde_json::json!({
            "type": "pinned_key",
            "subject": "peer",
            "public_key": peer.aid().identifier(),
            "proof": "x",
        }))
        .unwrap();
        issue_tct_for_peer(
            &cfg,
            &identity,
            peer.aid(),
            &peer.verifying_key(),
            &["chat.send".into(), "files.read".into(), "admin".into()],
        )
        .map(|issued| issued.claims.grants)
    }

    #[test]
    fn grant_policy_sees_the_candidates_and_can_only_narrow() {
        let policy: &GrantPolicyFn = &|ctx| {
            assert_eq!(ctx.candidate_grants, ["chat.send", "files.read"]);
            assert_eq!(ctx.peer_identity.subject, "peer");
            Ok(vec!["files.read".into(), "admin".into()])
        };
        assert_eq!(grant_policy_issue(policy).unwrap(), ["files.read"]);
    }

    #[test]
    fn a_failing_or_empty_grant_policy_is_policy_violation() {
        let failing: &GrantPolicyFn = &|_| Err(GrantPolicyError::new("policy store down"));
        let err = grant_policy_issue(failing).unwrap_err();
        assert!(matches!(err, HandshakeError::GrantPolicy(_)), "{err}");
        assert_eq!(err.error_code(), crate::core::ErrorCode::PolicyViolation);
        let empty: &GrantPolicyFn = &|_| Ok(vec![]);
        assert!(matches!(
            grant_policy_issue(empty).unwrap_err(),
            HandshakeError::PolicyViolation
        ));
    }
}
