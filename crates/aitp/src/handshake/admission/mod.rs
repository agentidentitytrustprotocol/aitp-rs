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
//! [`MAX_NONCE_TTL`] and bound to the verifier's AID. Outstanding nonces
//! are bounded: at the bound new challenges are refused, never evicted.
//! Challenge issuance is always rate limited per transport source
//! ([`RecommendedLimiter`] unless replaced). RFC-AITP-0002 §3.4 requires
//! the two refusals to stay distinguishable: a rate-limited source gets
//! HTTP 429 and no AITP code ([`AdmissionError::RateLimited`]); a full
//! nonce store gets `CHALLENGE_REFUSED`, retryable, which over HTTP is 503
//! with `Retry-After` and `{"error":"CHALLENGE_REFUSED"}`
//! ([`AdmissionError::ChallengeRefused`]).
//!
//! [`admit`] runs the RFC-AITP-0002 §3.4 check order:
//!
//! 1. `message_id` deny list ⇒ `REPLAY_DETECTED` (costs no rate-limit slot);
//! 2. per-source presentation rate limit ⇒ HTTP 429, no wire code;
//! 3. timestamp window ⇒ `TIMESTAMP_EXPIRED`;
//! 4. structure, payload exactly `{identity, pop_nonce}` ⇒
//!    `INVALID_ENVELOPE` / `UNKNOWN_FIELD`;
//! 5. nonce length ⇒ `IDENTITY_FAILED`;
//! 6. §3.2 steps 1–3 (type, key equality, trust store) ⇒ `IDENTITY_FAILED`;
//! 7. envelope signature ⇒ `INVALID_SIGNATURE`;
//! 8. §3.2 steps 4–5 (the proof) ⇒ `IDENTITY_FAILED`;
//! 9. atomic nonce lookup-and-consume ⇒ `IDENTITY_FAILED`;
//!
//! then records the `message_id`. The nonce is consumed only by a
//! presentation that verified, so a party that merely observed a nonce
//! cannot burn it.
//!
//! [`admit`]: PinnedAdmission::admit

mod deny_list;
pub mod metrics_names;
mod nonce_store;
mod rate_limit;

pub use deny_list::{DenyListError, InMemoryMessageIdDenyList, MessageIdDenyList};
pub use nonce_store::{
    ConsumeOutcome, InMemoryNonceStore, IssuedNonce, Nonce, NonceStore, NonceStoreError,
};
pub use rate_limit::{
    ChallengeRateLimiter, ChallengeSource, RecommendedLimiter, TokenBucketLimiter, TransportId,
};

use crate::core::envelope::{envelope_signing_digest, parse_envelope_wire, EnvelopeParseError};
use crate::core::CheckedJson;
use crate::core::{
    base64url, check_members, from_serde_error, Aid, AitpEnvelope, MessageType, Sender, Timestamp,
    DEFAULT_TIMESTAMP_TOLERANCE, PROTOCOL_VERSION,
};
use crate::crypto::{AitpSigner, Digest32, DynAsyncAitpSigner, Signature, SignerError};
use crate::handshake::identity_pinned::{
    check_pinned_key_proof, pinned_key_proof_input, resolve_pinned_key, PinnedKeyStore,
    PinnedKeyVerifyContext, SubjectBinding,
};
use crate::handshake::{IdentityDescriptor, IdentityKind, VerifiedPinnedKey};
use rand::TryRng;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

/// Upper bound on a challenge's lifetime (proposal Item 5).
pub const MAX_NONCE_TTL: Duration = Duration::from_secs(300);

/// Wire members of an `identity_presentation` payload: exactly these two
/// (RFC-AITP-0002 §3.4 check order, step 4).
pub const IDENTITY_PRESENTATION_PAYLOAD_MEMBERS: &[&str] = &["identity", "pop_nonce"];

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
}

/// A successful admission.
///
/// Only this crate constructs it, and its fields are read-only:
/// [`Self::into_parts`] hands out the owned pieces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admitted {
    pub(crate) key: VerifiedPinnedKey,
    pub(crate) subject: String,
    pub(crate) message_id: Uuid,
}

impl Admitted {
    /// The subject's key, from the trust store.
    pub fn key(&self) -> &VerifiedPinnedKey {
        &self.key
    }

    /// `identity.subject` as presented.
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// The envelope's `message_id`.
    pub fn message_id(&self) -> Uuid {
        self.message_id
    }

    /// The owned pieces.
    pub fn into_parts(self) -> AdmittedParts {
        AdmittedParts {
            key: self.key,
            subject: self.subject,
            message_id: self.message_id,
        }
    }
}

/// The owned pieces of an [`Admitted`], from [`Admitted::into_parts`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AdmittedParts {
    /// See [`Admitted::key`].
    pub key: VerifiedPinnedKey,
    /// See [`Admitted::subject`].
    pub subject: String,
    /// See [`Admitted::message_id`].
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
    /// A member outside the schema.
    #[error("unknown field `{0}`")]
    UnknownField(String),
    /// `version` is not one this implementation speaks.
    #[error("unknown version `{0}`")]
    UnknownVersion(String),
    /// The `message_id` is on the deny list: this presentation, or one
    /// reusing its `message_id`, was already admitted.
    #[error("message_id already admitted")]
    Replay,
    /// The source exceeded its challenge or presentation rate limit
    /// (RFC-AITP-0009 §3.1). No AITP error envelope: within the profile
    /// RFC-AITP-0002 §3.4 requires HTTP 429, with `Retry-After` from
    /// `retry_after`. See [`Self::http_status`].
    #[error("rate limit exceeded")]
    RateLimited {
        /// When the source may present again.
        retry_after: Duration,
    },
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
    /// No challenge issued: the outstanding-nonce bound is reached. Wire
    /// code `CHALLENGE_REFUSED`, retryable. It is not an AITP error
    /// envelope and travels in the challenge's own transport: over HTTP,
    /// answer [`Self::http_status`] (503) with a `Retry-After` header from
    /// [`Self::retry_after`] and the body [`Self::http_body`]
    /// (RFC-AITP-0002 §3.4). Never 429, which the client must be able to
    /// tell apart as a per-source rate limit.
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
    /// The `message_id` deny list failed or is full. Not the subject's
    /// fault; the presentation was not admitted.
    #[error("deny list: {0}")]
    DenyList(#[source] DenyListError),
    /// The presenter's signer failed.
    #[error(transparent)]
    Signer(#[from] SignerError),
    /// The OS CSPRNG failed.
    #[error("rng: {0}")]
    Rng(#[source] crate::core::BoxError),
}

impl AdmissionError {
    /// The wire error code (RFC-AITP-0001 §6) to report to the peer, or
    /// `None` when there is none: a rate-limited presentation (see
    /// [`Self::http_status`]) or a local failure that is not the peer's
    /// fault.
    pub fn code(&self) -> Option<&'static str> {
        Some(match self {
            Self::Replay => "REPLAY_DETECTED",
            Self::InvalidEnvelope(_) => "INVALID_ENVELOPE",
            Self::UnknownField(_) => "UNKNOWN_FIELD",
            Self::UnknownVersion(_) => "UNKNOWN_VERSION",
            Self::TimestampExpired => "TIMESTAMP_EXPIRED",
            Self::Identity(_) => "IDENTITY_FAILED",
            Self::InvalidSignature => "INVALID_SIGNATURE",
            Self::ChallengeRefused { .. } => "CHALLENGE_REFUSED",
            Self::RateLimited { .. }
            | Self::Store(_)
            | Self::DenyList(_)
            | Self::Signer(_)
            | Self::Rng(_) => return None,
        })
    }

    /// The HTTP status a transport answers with when it must not send an
    /// AITP error envelope (RFC-AITP-0002 §3.4): 429 for
    /// [`Self::RateLimited`], 503 for [`Self::ChallengeRefused`], else
    /// `None`.
    pub fn http_status(&self) -> Option<u16> {
        match self {
            Self::RateLimited { .. } => Some(429),
            Self::ChallengeRefused { .. } => Some(503),
            _ => None,
        }
    }

    /// The `Retry-After` to send with [`Self::http_status`]. For a
    /// [`Self::ChallengeRefused`] whose store did not know when a slot
    /// frees, [`MAX_NONCE_TTL`]: every outstanding nonce expires within
    /// it. `None` for every other error.
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after } => Some(*retry_after),
            Self::ChallengeRefused { retry_after, .. } => {
                Some(retry_after.unwrap_or(MAX_NONCE_TTL))
            }
            _ => None,
        }
    }

    /// The HTTP body to send with [`Self::http_status`]:
    /// `{"error":"CHALLENGE_REFUSED"}` for [`Self::ChallengeRefused`]
    /// (RFC-AITP-0002 §3.4); `None`, an empty body, for
    /// [`Self::RateLimited`] (RFC-AITP-0009 §3.1) and every other error.
    pub fn http_body(&self) -> Option<&'static str> {
        matches!(self, Self::ChallengeRefused { .. }).then_some(r#"{"error":"CHALLENGE_REFUSED"}"#)
    }
}

/// Why a challenge was refused. Local only; see
/// [`AdmissionError::ChallengeRefused`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RefusalCause {
    /// The outstanding-nonce bound. (A rate-limited challenge request is
    /// [`AdmissionError::RateLimited`], not a refusal.)
    AtCapacity,
}

/// Builder for [`PinnedAdmission`].
pub struct PinnedAdmissionBuilder {
    verifier_aid: Aid,
    nonces: Arc<dyn NonceStore>,
    pinned_keys: Arc<dyn PinnedKeyStore>,
    limiter: Arc<dyn ChallengeRateLimiter>,
    presentation_limiter: Arc<dyn ChallengeRateLimiter>,
    deny_list: Arc<dyn MessageIdDenyList>,
    ttl: Duration,
    tolerance: Duration,
    subject: SubjectBinding,
}

impl std::fmt::Debug for PinnedAdmissionBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PinnedAdmissionBuilder")
            .field("verifier_aid", &self.verifier_aid)
            .field("ttl", &self.ttl)
            .field("tolerance", &self.tolerance)
            .field("subject", &self.subject)
            .finish_non_exhaustive()
    }
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
    /// off (RFC-AITP-0009 §3.1); a deployment that needs more headroom
    /// passes a limiter with higher rates.
    pub fn rate_limiter(mut self, limiter: Arc<dyn ChallengeRateLimiter>) -> Self {
        self.limiter = limiter;
        self
    }

    /// Replace the per-source presentation rate limiter (§3.4 check
    /// order, step 2). Default [`RecommendedLimiter::default`], separate
    /// from the challenge limiter. Cannot be turned off (RFC-AITP-0009
    /// §3.1).
    pub fn presentation_rate_limiter(mut self, limiter: Arc<dyn ChallengeRateLimiter>) -> Self {
        self.presentation_limiter = limiter;
        self
    }

    /// Replace the `message_id` deny list (§3.4 check order, step 1).
    /// Default a fresh [`InMemoryMessageIdDenyList`]. Verifiers behind a
    /// load balancer share one, as they share the nonce store.
    pub fn message_id_deny_list(mut self, deny_list: Arc<dyn MessageIdDenyList>) -> Self {
        self.deny_list = deny_list;
        self
    }

    /// Envelope timestamp tolerance, capped at
    /// [`DEFAULT_TIMESTAMP_TOLERANCE`] (the default, 300 s) and counted in
    /// whole seconds.
    pub fn timestamp_tolerance(mut self, tolerance: Duration) -> Self {
        self.tolerance = tolerance.min(DEFAULT_TIMESTAMP_TOLERANCE);
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
            presentation_limiter: self.presentation_limiter,
            deny_list: self.deny_list,
            ttl: self.ttl,
            tolerance: self.tolerance,
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
    presentation_limiter: Arc<dyn ChallengeRateLimiter>,
    deny_list: Arc<dyn MessageIdDenyList>,
    ttl: Duration,
    tolerance: Duration,
    subject: SubjectBinding,
}

impl std::fmt::Debug for PinnedAdmission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PinnedAdmission")
            .field("verifier_aid", &self.verifier_aid)
            .field("ttl", &self.ttl)
            .field("tolerance", &self.tolerance)
            .field("subject", &self.subject)
            .finish_non_exhaustive()
    }
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
            presentation_limiter: Arc::new(RecommendedLimiter::default()),
            deny_list: Arc::new(InMemoryMessageIdDenyList::default()),
            ttl: MAX_NONCE_TTL,
            tolerance: DEFAULT_TIMESTAMP_TOLERANCE,
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
        let r = self.issue_challenge(source, now).await;
        metrics_names::record_challenge(&r);
        r
    }

    async fn issue_challenge(
        &self,
        source: &ChallengeSource,
        now: Timestamp,
    ) -> Result<AdmissionChallenge, AdmissionError> {
        self.limiter
            .check(source)
            .map_err(|retry_after| AdmissionError::RateLimited { retry_after })?;
        let expires_at = now.saturating_add(self.ttl);
        // A duplicate means the CSPRNG repeated 128 bits; one retry is
        // already paranoid.
        for _ in 0..2 {
            let mut nonce: Nonce = [0; crate::core::nonce_store::NONCE_LEN];
            rand::rngs::SysRng
                .try_fill_bytes(&mut nonce)
                .map_err(|e| AdmissionError::Rng(e.into()))?;
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
                Err(NonceStoreError::AtCapacity { retry_after, .. }) => {
                    return Err(AdmissionError::ChallengeRefused {
                        retry_after,
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

    /// Admit a presentation received as raw JSON from `source`. Check
    /// order steps 1–3 run on the raw members, before any parsing, so a
    /// replay or an over-limit source is answered without schema work.
    ///
    /// `envelope` is a [`CheckedJson`], built from the request body's
    /// bytes, so a duplicate key (RFC-AITP-0001 §5.4.5) has already been
    /// rejected before this is reached.
    pub async fn admit_wire(
        &self,
        envelope: &CheckedJson,
        source: &ChallengeSource,
    ) -> Result<Admitted, AdmissionError> {
        self.admit_wire_at(envelope, source, Timestamp::now()).await
    }

    /// As [`Self::admit_wire`] at an explicit `now`.
    pub async fn admit_wire_at(
        &self,
        envelope: &CheckedJson,
        source: &ChallengeSource,
        now: Timestamp,
    ) -> Result<Admitted, AdmissionError> {
        let r = self.admit_wire_inner(envelope, source, now).await;
        metrics_names::record_admit(&r);
        r
    }

    async fn admit_wire_inner(
        &self,
        envelope: &CheckedJson,
        source: &ChallengeSource,
        now: Timestamp,
    ) -> Result<Admitted, AdmissionError> {
        // A member that is missing or mistyped skips its gate here and
        // fails at step 4.
        let message_id = envelope
            .get("message_id")
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::try_parse(s).ok());
        let timestamp = envelope
            .get("timestamp")
            .and_then(|v| v.as_i64())
            .map(Timestamp);
        self.gate(message_id.as_ref(), timestamp, source, now)
            .await?;
        let env = parse_envelope_wire(envelope).map_err(|e| match e {
            EnvelopeParseError::UnknownVersion(v) => AdmissionError::UnknownVersion(v),
            EnvelopeParseError::UnknownField(f) => AdmissionError::UnknownField(f),
            other => AdmissionError::InvalidEnvelope(other.to_string()),
        })?;
        self.verify(&env, now).await
    }

    /// Admit a presentation from `source` at wall-clock time.
    pub async fn admit(
        &self,
        envelope: &AitpEnvelope,
        source: &ChallengeSource,
    ) -> Result<Admitted, AdmissionError> {
        self.admit_at(envelope, source, Timestamp::now()).await
    }

    /// Admit a presentation from `source` at an explicit `now`, in the
    /// §3.4 check order (module docs).
    pub async fn admit_at(
        &self,
        env: &AitpEnvelope,
        source: &ChallengeSource,
        now: Timestamp,
    ) -> Result<Admitted, AdmissionError> {
        let r = async {
            self.gate(Some(&env.message_id), Some(env.timestamp), source, now)
                .await?;
            self.verify(env, now).await
        }
        .await;
        metrics_names::record_admit(&r);
        r
    }

    /// Check order steps 1–3.
    async fn gate(
        &self,
        message_id: Option<&Uuid>,
        timestamp: Option<Timestamp>,
        source: &ChallengeSource,
        now: Timestamp,
    ) -> Result<(), AdmissionError> {
        if let Some(id) = message_id {
            if self
                .deny_list
                .contains(id, now)
                .await
                .map_err(AdmissionError::DenyList)?
            {
                return Err(AdmissionError::Replay);
            }
        }
        self.presentation_limiter
            .check(source)
            .map_err(|retry_after| AdmissionError::RateLimited { retry_after })?;
        if let Some(ts) = timestamp {
            if !ts.is_within_tolerance_of(now, self.tolerance) {
                return Err(AdmissionError::TimestampExpired);
            }
        }
        Ok(())
    }

    /// Check order steps 4–9, then the deny-list record.
    async fn verify(&self, env: &AitpEnvelope, now: Timestamp) -> Result<Admitted, AdmissionError> {
        // Step 4: structure.
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

        // Step 5: nonce length, before any signature work.
        let nonce: Nonce = base64url::decode_strict_exact(&payload.pop_nonce).map_err(|_| {
            AdmissionError::Identity("pop_nonce must be 16 bytes, base64url-unpadded".into())
        })?;

        let sender = &env.sender.agent_id;
        let ctx = PinnedKeyVerifyContext {
            sender_aid: sender,
            receiver_aid: &self.verifier_aid,
            message_id: &env.message_id,
            timestamp: env.timestamp,
            pop_nonce: &payload.pop_nonce,
            subject: self.subject,
        };
        // Step 6: §3.2 steps 1–3.
        let key = resolve_pinned_key(&payload.identity, &ctx, self.pinned_keys.as_ref())
            .map_err(|e| AdmissionError::Identity(e.to_string()))?;

        // Step 7: envelope signature.
        let digest = envelope_signing_digest(env)
            .map_err(|e| AdmissionError::InvalidEnvelope(e.to_string()))?;
        let sig = Signature::parse(&env.signature).map_err(|_| AdmissionError::InvalidSignature)?;
        key.key
            .verify_jcs(&Digest32::from_bytes(digest), &sig)
            .map_err(|_| AdmissionError::InvalidSignature)?;

        // Step 8: §3.2 steps 4–5.
        check_pinned_key_proof(&payload.identity, &ctx, &key)
            .map_err(|e| AdmissionError::Identity(e.to_string()))?;

        // Step 9: atomic consume.
        match self
            .nonces
            .consume(&nonce, &self.verifier_aid, now)
            .await
            .map_err(AdmissionError::Store)?
        {
            ConsumeOutcome::Consumed => {}
            ConsumeOutcome::Expired => {
                return Err(AdmissionError::Identity("challenge expired".into()))
            }
            _ => {
                return Err(AdmissionError::Identity(
                    "challenge unknown, already used, or for another verifier".into(),
                ))
            }
        }

        // Record until the timestamp leaves the window; past that, step 3
        // rejects a replay by itself. A concurrent twin that recorded
        // first makes this one the replay.
        let until = env.timestamp.saturating_add(self.tolerance);
        if !self
            .deny_list
            .insert(&env.message_id, until, now)
            .await
            .map_err(AdmissionError::DenyList)?
        {
            return Err(AdmissionError::Replay);
        }
        Ok(Admitted {
            key,
            subject: payload.identity.subject,
            message_id: env.message_id,
        })
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
    let proof = crate::crypto::sign_jcs(signer, &draft.proof_digest)?;
    let (envelope_digest, mut envelope) = draft.unsigned_envelope(proof)?;
    envelope.signature = crate::crypto::sign_jcs(signer, &envelope_digest)?.into_string();
    Ok(envelope)
}

/// As [`present_pinned`] through an async (KMS, HSM) signer.
pub async fn present_pinned_async(
    signer: &dyn DynAsyncAitpSigner,
    subject: &str,
    challenge: &AdmissionChallenge,
    now: Timestamp,
) -> Result<AitpEnvelope, AdmissionError> {
    let draft = Draft::new(signer.aid(), subject, challenge, now)?;
    let proof = crate::crypto::sign_jcs_async(signer, &draft.proof_digest).await?;
    let (envelope_digest, mut envelope) = draft.unsigned_envelope(proof)?;
    envelope.signature = crate::crypto::sign_jcs_async(signer, &envelope_digest)
        .await?
        .into_string();
    Ok(envelope)
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

    /// The presentation envelope with an empty `signature`, and the
    /// digest that signature covers (RFC-AITP-0001 §5.4: the whole
    /// envelope minus `signature`).
    fn unsigned_envelope(
        self,
        proof: Signature,
    ) -> Result<(Digest32, AitpEnvelope), AdmissionError> {
        let payload = serde_json::to_value(IdentityPresentationPayload {
            identity: IdentityDescriptor {
                kind: IdentityKind::PinnedKey,
                issuer: None,
                subject: self.subject.clone(),
                proof: proof.into_string(),
                public_key: Some(base64url::encode(&self.sender.pubkey_compressed_bytes())),
                extensions: None,
                svid_type: None,
                x5c: None,
            },
            pop_nonce: self.pop_nonce.clone(),
        })
        .map_err(|e| AdmissionError::InvalidEnvelope(e.to_string()))?;
        let envelope = AitpEnvelope {
            version: PROTOCOL_VERSION.to_owned(),
            message_type: MessageType::IdentityPresentation,
            message_id: self.message_id,
            timestamp: self.timestamp,
            sender: Sender {
                agent_id: self.sender,
            },
            payload,
            extensions: None,
            signature: String::new(),
        };
        let d = envelope_signing_digest(&envelope)
            .map_err(|e| AdmissionError::InvalidEnvelope(e.to_string()))?;
        Ok((Digest32::from_bytes(d), envelope))
    }
}
