//! Pinned-key admission: a verifier admits a pinned-key subject by
//! challenge and presentation, without a full Mutual Handshake
//! (proposal agentidentitytrustprotocol#72 Items 5 and 7d).
//!
//! ```text
//! verifier                                   subject
//!   challenge(source) ── {pop_nonce, verifier_aid, expires_at} ──▶
//!   ◀── envelope{message_type: identity_presentation,
//!                payload: {identity, pop_nonce}} ── present_pinned()
//!   admit(envelope)
//! ```
//!
//! The challenge is a 16-byte CSPRNG nonce, single-use, valid for at most
//! [`MAX_NONCE_TTL`] and bound to the verifier's AID. [`admit`] runs
//! RFC-AITP-0002 §3.2 steps 1–5 with `receiver_aid` = the verifier AID,
//! checks the envelope signature and timestamp (RFC-AITP-0001 §5.4/§5.5),
//! and only then consumes the nonce atomically. A malformed nonce is
//! rejected `IDENTITY_FAILED` before any signature work. Outstanding
//! nonces are bounded: at the bound new challenges are refused, never
//! evicted. Challenge issuance is always rate limited per transport
//! source ([`RecommendedLimiter`] unless replaced). Either refusal is
//! `CHALLENGE_REFUSED`, retryable, and does not say which limit fired.
//!
//! [`admit`]: PinnedAdmission::admit

mod nonce_store;
mod rate_limit;

pub use nonce_store::{
    ConsumeOutcome, InMemoryNonceStore, IssuedNonce, Nonce, NonceStore, NonceStoreError,
};
pub use rate_limit::{
    ChallengeRateLimiter, ChallengeSource, RecommendedLimiter, TokenBucketLimiter, TransportId,
};

use crate::identity_pinned::{
    pinned_key_proof_input, PinnedKeyStore, PinnedKeyVerifyContext, SubjectBinding,
};
use crate::{verify_pinned_key, IdentityDescriptor, IdentityKind, VerifiedPinnedKey};
use aitp_core::envelope::{envelope_signing_digest, parse_envelope_wire, EnvelopeParseError};
use aitp_core::{
    base64url, check_members, from_serde_error, Aid, AitpEnvelope, ExtensionsMap, MessageType,
    Sender, Timestamp, DEFAULT_TIMESTAMP_TOLERANCE_SECS, PROTOCOL_VERSION,
};
use aitp_crypto::{AitpSigner, Digest32, DynAsyncAitpSigner, Signature, SignerError};
use rand::TryRng;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

/// Upper bound on a challenge's lifetime (proposal Item 5).
pub const MAX_NONCE_TTL: Duration = Duration::from_secs(300);

/// Wire members of an `identity_presentation` payload.
pub const IDENTITY_PRESENTATION_PAYLOAD_MEMBERS: &[&str] = &["identity", "pop_nonce", "extensions"];

/// A challenge handed to a subject. Transport-defined and unsigned: its
/// integrity comes from the nonce being single-use and verifier-bound,
/// not from a signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct AdmissionChallenge {
    /// 16 random bytes, base64url-unpadded.
    pub pop_nonce: String,
    /// The verifier the presentation must be addressed to.
    pub verifier_aid: Aid,
    /// Last second the nonce is accepted (inclusive).
    pub expires_at: Timestamp,
}

/// `payload` of an `identity_presentation` envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct IdentityPresentationPayload {
    /// The subject's `pinned_key` identity descriptor.
    pub identity: IdentityDescriptor,
    /// The challenge nonce being answered.
    pub pop_nonce: String,
    /// Extension namespace (RFC-AITP-0001 §7).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<ExtensionsMap>,
}

/// A successful admission.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Admitted {
    /// The subject's key, from the trust store.
    pub key: VerifiedPinnedKey,
    /// `identity.subject` as presented.
    pub subject: String,
    /// The envelope's `message_id`.
    pub message_id: Uuid,
}

/// Failure to issue a challenge or admit a presentation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AdmissionError {
    /// Envelope or payload failed validation, or `message_type` is not
    /// `identity_presentation`.
    #[error("invalid envelope: {0}")]
    InvalidEnvelope(String),
    /// A member outside the schema and outside `extensions`.
    #[error("unknown field `{0}`")]
    UnknownField(String),
    /// `version` is not one this implementation speaks.
    #[error("unknown version `{0}`")]
    UnknownVersion(String),
    /// Envelope timestamp outside the tolerance window.
    #[error("timestamp outside tolerance")]
    TimestampExpired,
    /// Identity verification failed: bad nonce, untrusted key, bad
    /// proof, or a nonce that is unknown, used, expired or bound to
    /// another verifier.
    #[error("identity verification failed: {0}")]
    Identity(String),
    /// The envelope signature does not verify under the admitted key.
    #[error("envelope signature invalid")]
    InvalidSignature,
    /// No challenge issued. Wire code `CHALLENGE_REFUSED`, retryable;
    /// send it in the out-of-band challenge response (HTTP 429 alongside
    /// is fine). The message never names the cause.
    #[error("challenge refused")]
    ChallengeRefused {
        /// When a retry may succeed, if known (a `Retry-After` value).
        retry_after: Option<Duration>,
        /// Which limit fired. For local logs and metrics only: telling
        /// the peer would leak the store's state.
        cause: RefusalCause,
    },
    /// The nonce store backend failed. Not the subject's fault.
    #[error("nonce store: {0}")]
    Store(#[source] NonceStoreError),
    /// The presenter's signer failed.
    #[error(transparent)]
    Signer(#[from] SignerError),
    /// The OS CSPRNG failed.
    #[error("rng: {0}")]
    Rng(String),
}

impl AdmissionError {
    /// The wire error code (RFC-AITP-0001 §6) to report to the peer, or
    /// `None` for a local failure that is not the peer's fault.
    pub fn code(&self) -> Option<&'static str> {
        Some(match self {
            Self::InvalidEnvelope(_) => "INVALID_ENVELOPE",
            Self::UnknownField(_) => "UNKNOWN_FIELD",
            Self::UnknownVersion(_) => "UNKNOWN_VERSION",
            Self::TimestampExpired => "TIMESTAMP_EXPIRED",
            Self::Identity(_) => "IDENTITY_FAILED",
            Self::InvalidSignature => "INVALID_SIGNATURE",
            Self::ChallengeRefused { .. } => "CHALLENGE_REFUSED",
            Self::Store(_) | Self::Signer(_) | Self::Rng(_) => return None,
        })
    }
}

/// Why a challenge was refused. Local only; see
/// [`AdmissionError::ChallengeRefused`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RefusalCause {
    /// The source's rate limit.
    RateLimited,
    /// The outstanding-nonce bound.
    AtCapacity,
}

/// Builder for [`PinnedAdmission`].
pub struct PinnedAdmissionBuilder {
    verifier_aid: Aid,
    nonces: Arc<dyn NonceStore>,
    pinned_keys: Arc<dyn PinnedKeyStore>,
    limiter: Arc<dyn ChallengeRateLimiter>,
    ttl: Duration,
    tolerance_secs: i64,
    subject: SubjectBinding,
}

impl PinnedAdmissionBuilder {
    /// Challenge lifetime, clamped to `1s..=`[`MAX_NONCE_TTL`]. Default
    /// [`MAX_NONCE_TTL`].
    pub fn nonce_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl.clamp(Duration::from_secs(1), MAX_NONCE_TTL);
        self
    }

    /// Replace the per-source challenge rate limiter. Default
    /// [`RecommendedLimiter::default`]. Rate limiting cannot be turned
    /// off (RFC-AITP-0004 §11.4); a deployment that needs more headroom
    /// passes a limiter with higher rates.
    pub fn rate_limiter(mut self, limiter: Arc<dyn ChallengeRateLimiter>) -> Self {
        self.limiter = limiter;
        self
    }

    /// Envelope timestamp tolerance in seconds, clamped to
    /// `0..=`[`DEFAULT_TIMESTAMP_TOLERANCE_SECS`]. Default 300.
    pub fn timestamp_tolerance_secs(mut self, secs: i64) -> Self {
        self.tolerance_secs = secs.clamp(0, DEFAULT_TIMESTAMP_TOLERANCE_SECS);
        self
    }

    /// How the descriptor's `subject` is checked. Default
    /// [`SubjectBinding::Unchecked`]: `subject` is a label, reported in
    /// [`Admitted::subject`] but not authenticated by `proof`.
    pub fn subject_binding(mut self, binding: SubjectBinding) -> Self {
        self.subject = binding;
        self
    }

    /// Finish.
    pub fn build(self) -> PinnedAdmission {
        PinnedAdmission {
            verifier_aid: self.verifier_aid,
            nonces: self.nonces,
            pinned_keys: self.pinned_keys,
            limiter: self.limiter,
            ttl: self.ttl,
            tolerance_secs: self.tolerance_secs,
            subject: self.subject,
        }
    }
}

/// The verifier side of pinned-key admission. Cheap to share: wrap in an
/// `Arc` and call from any number of tasks.
pub struct PinnedAdmission {
    verifier_aid: Aid,
    nonces: Arc<dyn NonceStore>,
    pinned_keys: Arc<dyn PinnedKeyStore>,
    limiter: Arc<dyn ChallengeRateLimiter>,
    ttl: Duration,
    tolerance_secs: i64,
    subject: SubjectBinding,
}

impl PinnedAdmission {
    /// Start a builder. `pinned_keys` is required: there is no
    /// possession-only admission.
    pub fn builder(
        verifier_aid: Aid,
        nonces: Arc<dyn NonceStore>,
        pinned_keys: Arc<dyn PinnedKeyStore>,
    ) -> PinnedAdmissionBuilder {
        PinnedAdmissionBuilder {
            verifier_aid,
            nonces,
            pinned_keys,
            limiter: Arc::new(RecommendedLimiter::default()),
            ttl: MAX_NONCE_TTL,
            tolerance_secs: DEFAULT_TIMESTAMP_TOLERANCE_SECS,
            subject: SubjectBinding::Unchecked,
        }
    }

    /// The verifier AID presentations must be addressed to.
    pub fn verifier_aid(&self) -> &Aid {
        &self.verifier_aid
    }

    /// Issue a challenge to `source` at wall-clock time.
    pub async fn challenge(
        &self,
        source: &ChallengeSource,
    ) -> Result<AdmissionChallenge, AdmissionError> {
        self.challenge_at(source, Timestamp::now()).await
    }

    /// As [`Self::challenge`] at an explicit `now`.
    pub async fn challenge_at(
        &self,
        source: &ChallengeSource,
        now: Timestamp,
    ) -> Result<AdmissionChallenge, AdmissionError> {
        self.limiter
            .check(source)
            .map_err(|retry_after| AdmissionError::ChallengeRefused {
                retry_after: Some(retry_after),
                cause: RefusalCause::RateLimited,
            })?;
        let expires_at = now.plus_secs(self.ttl.as_secs() as i64);
        // A duplicate means the CSPRNG repeated 128 bits; one retry is
        // already paranoid.
        for _ in 0..2 {
            let mut nonce: Nonce = [0; crate::POP_NONCE_LEN];
            rand::rngs::SysRng
                .try_fill_bytes(&mut nonce)
                .map_err(|e| AdmissionError::Rng(e.to_string()))?;
            let rec = IssuedNonce::new(
                nonce,
                self.verifier_aid.clone(),
                source.to_string(),
                now,
                expires_at,
            );
            match self.nonces.issue(&rec).await {
                Ok(()) => {
                    return Ok(AdmissionChallenge {
                        pop_nonce: base64url::encode(&nonce),
                        verifier_aid: self.verifier_aid.clone(),
                        expires_at,
                    })
                }
                Err(NonceStoreError::Duplicate) => continue,
                Err(NonceStoreError::AtCapacity { .. }) => {
                    return Err(AdmissionError::ChallengeRefused {
                        retry_after: None,
                        cause: RefusalCause::AtCapacity,
                    })
                }
                Err(e) => return Err(AdmissionError::Store(e)),
            }
        }
        Err(AdmissionError::Rng(
            "CSPRNG repeated a 128-bit nonce".into(),
        ))
    }

    /// Admit a presentation received as raw JSON, enforcing the envelope
    /// member set first.
    pub async fn admit_wire(
        &self,
        envelope: &serde_json::Value,
    ) -> Result<Admitted, AdmissionError> {
        self.admit_wire_at(envelope, Timestamp::now()).await
    }

    /// As [`Self::admit_wire`] at an explicit `now`.
    pub async fn admit_wire_at(
        &self,
        envelope: &serde_json::Value,
        now: Timestamp,
    ) -> Result<Admitted, AdmissionError> {
        let env = parse_envelope_wire(envelope).map_err(|e| match e {
            EnvelopeParseError::UnknownField(f) => AdmissionError::UnknownField(f),
            other => AdmissionError::InvalidEnvelope(other.to_string()),
        })?;
        self.admit_at(&env, now).await
    }

    /// Admit a presentation at wall-clock time.
    pub async fn admit(&self, envelope: &AitpEnvelope) -> Result<Admitted, AdmissionError> {
        self.admit_at(envelope, Timestamp::now()).await
    }

    /// Admit a presentation at an explicit `now`.
    ///
    /// Order: envelope shape → timestamp → payload → nonce length →
    /// §3.2 steps 1–5 → envelope signature → atomic consume. The nonce
    /// is consumed only by a presentation that verified, so a party that
    /// merely observed a nonce cannot burn it.
    pub async fn admit_at(
        &self,
        env: &AitpEnvelope,
        now: Timestamp,
    ) -> Result<Admitted, AdmissionError> {
        if env.version != PROTOCOL_VERSION {
            return Err(AdmissionError::UnknownVersion(env.version.clone()));
        }
        if env.message_type != MessageType::IdentityPresentation {
            return Err(AdmissionError::InvalidEnvelope(format!(
                "message_type {} is not identity_presentation",
                env.message_type.as_wire_str()
            )));
        }
        if env.message_id.get_version_num() != 4
            || env.message_id.get_variant() != uuid::Variant::RFC4122
        {
            return Err(AdmissionError::InvalidEnvelope(
                "message_id is not a UUID v4".into(),
            ));
        }
        if !env
            .timestamp
            .is_within_tolerance_of(now, self.tolerance_secs)
        {
            return Err(AdmissionError::TimestampExpired);
        }
        check_members(
            "IdentityPresentationPayload",
            &env.payload,
            IDENTITY_PRESENTATION_PAYLOAD_MEMBERS,
        )
        .map_err(|e| AdmissionError::UnknownField(e.field))?;
        let payload: IdentityPresentationPayload = serde_json::from_value(env.payload.clone())
            .map_err(|e| match from_serde_error(&e) {
                Some(f) => AdmissionError::UnknownField(f),
                None => AdmissionError::InvalidEnvelope(format!("payload: {e}")),
            })?;

        // Nonce length before any signature work (Item 5).
        let nonce: Nonce = base64url::decode_strict_exact(&payload.pop_nonce).map_err(|_| {
            AdmissionError::Identity("pop_nonce must be 16 bytes, base64url-unpadded".into())
        })?;

        let sender = &env.sender.agent_id;
        let key = verify_pinned_key(
            &payload.identity,
            &PinnedKeyVerifyContext {
                sender_aid: sender,
                receiver_aid: &self.verifier_aid,
                message_id: &env.message_id,
                timestamp: env.timestamp,
                pop_nonce: &payload.pop_nonce,
                subject: self.subject,
            },
            self.pinned_keys.as_ref(),
        )
        .map_err(|e| AdmissionError::Identity(e.to_string()))?;

        let digest = envelope_signing_digest(&env.message_id, env.timestamp, sender, &env.payload)
            .map_err(|e| AdmissionError::InvalidEnvelope(e.to_string()))?;
        let sig = Signature::parse(&env.signature).map_err(|_| AdmissionError::InvalidSignature)?;
        key.key
            .verify_jcs(&Digest32::from_bytes(digest), &sig)
            .map_err(|_| AdmissionError::InvalidSignature)?;

        match self
            .nonces
            .consume(&nonce, &self.verifier_aid, now)
            .await
            .map_err(AdmissionError::Store)?
        {
            ConsumeOutcome::Consumed => Ok(Admitted {
                key,
                subject: payload.identity.subject,
                message_id: env.message_id,
            }),
            ConsumeOutcome::Expired => Err(AdmissionError::Identity("challenge expired".into())),
            _ => Err(AdmissionError::Identity(
                "challenge unknown, already used, or for another verifier".into(),
            )),
        }
    }
}

/// Answer `challenge` as the subject behind `signer`: an
/// `identity_presentation` envelope addressed to the challenge's
/// verifier. `subject` is the free-form `identity.subject`.
pub fn present_pinned(
    signer: &dyn AitpSigner,
    subject: &str,
    challenge: &AdmissionChallenge,
    now: Timestamp,
) -> Result<AitpEnvelope, AdmissionError> {
    let draft = Draft::new(signer.aid(), subject, challenge, now)?;
    let proof = aitp_crypto::sign_jcs(signer, &draft.proof_digest)?;
    let (envelope_digest, payload) = draft.payload(proof)?;
    let signature = aitp_crypto::sign_jcs(signer, &envelope_digest)?;
    Ok(draft.envelope(payload, signature))
}

/// As [`present_pinned`] through an async (KMS, HSM) signer.
pub async fn present_pinned_async(
    signer: &dyn DynAsyncAitpSigner,
    subject: &str,
    challenge: &AdmissionChallenge,
    now: Timestamp,
) -> Result<AitpEnvelope, AdmissionError> {
    let draft = Draft::new(signer.aid(), subject, challenge, now)?;
    let proof = aitp_crypto::sign_jcs_async(signer, &draft.proof_digest).await?;
    let (envelope_digest, payload) = draft.payload(proof)?;
    let signature = aitp_crypto::sign_jcs_async(signer, &envelope_digest).await?;
    Ok(draft.envelope(payload, signature))
}

/// Everything about a presentation except its two signatures.
struct Draft {
    sender: Aid,
    subject: String,
    pop_nonce: String,
    message_id: Uuid,
    timestamp: Timestamp,
    proof_digest: Digest32,
}

impl Draft {
    fn new(
        sender: &Aid,
        subject: &str,
        challenge: &AdmissionChallenge,
        now: Timestamp,
    ) -> Result<Self, AdmissionError> {
        let message_id = Uuid::new_v4();
        let input = pinned_key_proof_input(
            sender,
            &challenge.verifier_aid,
            &message_id,
            now,
            &challenge.pop_nonce,
        )
        .map_err(|e| AdmissionError::Identity(e.to_string()))?;
        Ok(Self {
            sender: sender.clone(),
            subject: subject.to_owned(),
            pop_nonce: challenge.pop_nonce.clone(),
            message_id,
            timestamp: now,
            proof_digest: Digest32::sha256(&input),
        })
    }

    fn payload(&self, proof: Signature) -> Result<(Digest32, serde_json::Value), AdmissionError> {
        let payload = serde_json::to_value(IdentityPresentationPayload {
            identity: IdentityDescriptor {
                kind: IdentityKind::PinnedKey,
                issuer: None,
                subject: self.subject.clone(),
                proof: proof.into_string(),
                public_key: Some(base64url::encode(&self.sender.pubkey_compressed_bytes())),
                extensions: None,
            },
            pop_nonce: self.pop_nonce.clone(),
            extensions: None,
        })
        .map_err(|e| AdmissionError::InvalidEnvelope(e.to_string()))?;
        let d = envelope_signing_digest(&self.message_id, self.timestamp, &self.sender, &payload)
            .map_err(|e| AdmissionError::InvalidEnvelope(e.to_string()))?;
        Ok((Digest32::from_bytes(d), payload))
    }

    fn envelope(self, payload: serde_json::Value, signature: Signature) -> AitpEnvelope {
        AitpEnvelope {
            version: PROTOCOL_VERSION.to_owned(),
            message_type: MessageType::IdentityPresentation,
            message_id: self.message_id,
            timestamp: self.timestamp,
            sender: Sender {
                agent_id: self.sender,
            },
            payload,
            extensions: None,
            signature: signature.into_string(),
        }
    }
}
