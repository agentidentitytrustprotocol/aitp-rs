//! [`SessionTrustBundle`] builder (RFC-AITP-0010 §4).
//!
//! Coordinator-side: collect each participant's coordinator-issued TCT
//! (one per bilateral handshake), assemble the bundle body, JCS-sign.

use crate::error::SessionBundleError;
use crate::types::{ParticipantEntry, SessionTrustBundle};
use aitp_core::{jcs, Aid, Timestamp};
use aitp_crypto::AitpSigningKey;
use aitp_tct::TctClaims;
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// `version` constant for v0.2 bundles.
pub const DEFAULT_BUNDLE_VERSION: &str = "aitp/0.2";

/// Decode a participant TCT's claims without verification. Builder- and
/// invariant-level peeks only; full verification (signature, typ, alg
/// pin) happens in [`crate::verify_session_bundle`] via
/// [`aitp_tct::verify_tct`].
pub(crate) fn peek_tct_claims(token: &str) -> Result<TctClaims, SessionBundleError> {
    let payload = aitp_crypto::jws::decode_payload_unverified(token)
        .map_err(|e| SessionBundleError::Canonicalization(format!("participant tct: {e}")))?;
    serde_json::from_slice(&payload)
        .map_err(|e| SessionBundleError::Canonicalization(format!("participant tct claims: {e}")))
}

/// Fluent builder for issuing a [`SessionTrustBundle`] as the
/// coordinator.
pub struct SessionBundleBuilder<'a> {
    coordinator_key: &'a AitpSigningKey,
    session_id: Option<Uuid>,
    participants: Vec<ParticipantEntry>,
    issued_at: Option<Timestamp>,
}

impl<'a> SessionBundleBuilder<'a> {
    /// Begin a new bundle, signed by `coordinator_key`.
    pub fn new(coordinator_key: &'a AitpSigningKey) -> Self {
        Self {
            coordinator_key,
            session_id: None,
            participants: Vec::new(),
            issued_at: None,
        }
    }

    /// Set the session ID (UUIDv4). If unset, a fresh one is generated
    /// at `build()` time.
    pub fn session_id(mut self, id: Uuid) -> Self {
        self.session_id = Some(id);
        self
    }

    /// Override `issued_at`. Tests / fixtures only.
    pub fn issued_at(mut self, ts: Timestamp) -> Self {
        self.issued_at = Some(ts);
        self
    }

    /// Add a participant. The TCT (compact JWS, carried verbatim) MUST
    /// be coordinator-issued (`iss == coordinator_key.aid()`) with
    /// `aud == aid`. These invariants are checked in `build()`.
    pub fn participant(mut self, aid: Aid, tct: String) -> Self {
        self.participants.push(ParticipantEntry { aid, tct });
        self
    }

    /// Construct, sign, and return the bundle.
    pub fn build(self) -> Result<SessionTrustBundle, SessionBundleError> {
        if self.participants.is_empty() {
            return Err(SessionBundleError::EmptyParticipants);
        }

        let coordinator = self.coordinator_key.aid().clone();
        let session_id = self.session_id.unwrap_or_else(Uuid::new_v4);
        let issued_at = self.issued_at.unwrap_or_else(Timestamp::now);

        // Validate every participant entry up front so build() returns
        // a structurally-correct bundle. The coordinator minted these
        // tokens itself; the peek is for invariant enforcement, not
        // trust.
        let mut min_exp: Option<Timestamp> = None;
        for entry in &self.participants {
            let claims = peek_tct_claims(&entry.tct)?;
            if claims.iss != coordinator {
                return Err(SessionBundleError::CoordinatorIssuerMismatch);
            }
            if claims.aud != entry.aid {
                return Err(SessionBundleError::AudienceMismatch);
            }
            min_exp = Some(match min_exp {
                Some(m) if m.0 <= claims.exp.0 => m,
                _ => claims.exp,
            });
        }

        // expires_at = min(participant TCT expiries) per RFC §6.
        let expires_at = min_exp.ok_or(SessionBundleError::EmptyParticipants)?;

        let view = BundleSigningView {
            session_bundle: BundleSigningBody {
                version: DEFAULT_BUNDLE_VERSION,
                session_id: &session_id,
                coordinator: &coordinator,
                issued_at: &issued_at,
                expires_at: &expires_at,
                participants: &self.participants,
            },
        };
        let canonical = jcs::canonicalize_serializable(&view)
            .map_err(|e| SessionBundleError::Canonicalization(e.to_string()))?;
        let digest = Sha256::digest(&canonical);
        let signature = self.coordinator_key.sign(&digest);

        Ok(SessionTrustBundle {
            version: DEFAULT_BUNDLE_VERSION.to_string(),
            session_id,
            coordinator,
            issued_at,
            expires_at,
            participants: self.participants,
            signature: signature.into_string(),
        })
    }
}

/// Signing view: the wrapped `{"session_bundle": {...}}` form (the
/// envelope minus `signature`), per the v0.2 `kat-session-bundle-001`
/// vector — same convention as the revocation snapshot.
#[derive(Serialize)]
pub(crate) struct BundleSigningView<'a> {
    pub session_bundle: BundleSigningBody<'a>,
}

/// Inner body of [`BundleSigningView`] — every [`SessionTrustBundle`]
/// field except `signature`.
#[derive(Serialize)]
pub(crate) struct BundleSigningBody<'a> {
    pub version: &'a str,
    pub session_id: &'a Uuid,
    pub coordinator: &'a Aid,
    pub issued_at: &'a Timestamp,
    pub expires_at: &'a Timestamp,
    pub participants: &'a [ParticipantEntry],
}
