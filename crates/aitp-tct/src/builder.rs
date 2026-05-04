//! TCT builder.

use crate::types::{Tct, TctBinding};
use crate::TctError;
use aitp_core::{base64url, jcs, Aid, Timestamp};
use aitp_crypto::{AitpSigningKey, AitpVerifyingKey};
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Fluent builder for issuing a TCT.
///
/// ```ignore
/// let tct = TctBuilder::new(&issuer_key)
///     .subject(subject_aid.clone())
///     .audience(subject_aid.clone())          // v0.1: audience == subject
///     .grants(["demo.echo"])
///     .ttl_secs(3600)
///     .subject_pubkey(subject_verifying_key)
///     .build()?;
/// ```
pub struct TctBuilder<'a> {
    issuer_key: &'a AitpSigningKey,
    subject: Option<Aid>,
    audience: Option<Aid>,
    grants: Vec<String>,
    ttl_secs: i64,
    subject_pubkey: Option<AitpVerifyingKey>,
    /// Override `issued_at` for tests / fixed-clock scenarios.
    now_override: Option<Timestamp>,
    /// Override the generated JTI (tests, fixtures).
    jti_override: Option<Uuid>,
}

impl<'a> TctBuilder<'a> {
    /// Begin a new TCT, signed by `issuer_key`.
    pub fn new(issuer_key: &'a AitpSigningKey) -> Self {
        Self {
            issuer_key,
            subject: None,
            audience: None,
            grants: Vec::new(),
            ttl_secs: crate::DEFAULT_TCT_TTL_SECS,
            subject_pubkey: None,
            now_override: None,
            jti_override: None,
        }
    }

    /// Set the subject AID.
    pub fn subject(mut self, subject: Aid) -> Self {
        self.subject = Some(subject);
        self
    }

    /// Set the audience AID. In v0.1 audience MUST equal subject.
    pub fn audience(mut self, audience: Aid) -> Self {
        self.audience = Some(audience);
        self
    }

    /// Set the granted capabilities.
    pub fn grants<I, S>(mut self, grants: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.grants = grants.into_iter().map(Into::into).collect();
        self
    }

    /// Override the default TTL.
    pub fn ttl_secs(mut self, ttl: i64) -> Self {
        self.ttl_secs = ttl;
        self
    }

    /// Set the subject's verifying key, used to populate `binding.cnf`.
    pub fn subject_pubkey(mut self, pk: AitpVerifyingKey) -> Self {
        self.subject_pubkey = Some(pk);
        self
    }

    /// Override `issued_at`. Tests/fixtures only.
    pub fn issued_at(mut self, ts: Timestamp) -> Self {
        self.now_override = Some(ts);
        self
    }

    /// Override the generated `jti`. Tests/fixtures only.
    pub fn jti(mut self, jti: Uuid) -> Self {
        self.jti_override = Some(jti);
        self
    }

    /// Construct, sign, and return the TCT.
    pub fn build(self) -> Result<Tct, TctError> {
        let subject = self.subject.ok_or(TctError::MissingField("subject"))?;
        let audience = self.audience.ok_or(TctError::MissingField("audience"))?;
        let subject_pk = self
            .subject_pubkey
            .ok_or(TctError::MissingField("subject_pubkey"))?;
        if self.grants.is_empty() {
            return Err(TctError::EmptyGrants);
        }
        // RFC-AITP-0005 §4.2: "Grants MUST NOT contain whitespace."
        // Catch caller-supplied bad input here rather than letting a
        // malformed grant flow into the signed body.
        for g in &self.grants {
            if g.chars().any(char::is_whitespace) {
                return Err(TctError::GrantWhitespace(g.clone()));
            }
        }
        if subject != audience {
            // v0.1 invariant: audience must equal subject.
            return Err(TctError::AudienceMismatch);
        }

        let cnf = base64url::encode(&subject_pk.to_bytes());
        debug_assert_eq!(cnf.len(), 43);

        let jti = self.jti_override.unwrap_or_else(Uuid::new_v4);
        let issued_at = self.now_override.unwrap_or_else(Timestamp::now);
        let expires_at = issued_at.plus_secs(self.ttl_secs);
        let issuer = self.issuer_key.aid().clone();

        let binding = TctBinding { cnf };
        let view = TctSigningView {
            version: "aitp/0.1",
            jti: &jti,
            issuer: &issuer,
            subject: &subject,
            audience: &audience,
            issued_at: &issued_at,
            expires_at: &expires_at,
            grants: &self.grants,
            binding: &binding,
        };
        let canonical = jcs::canonicalize_serializable(&view)
            .map_err(|e| TctError::Canonicalization(e.to_string()))?;
        let digest = Sha256::digest(&canonical);
        let signature = self.issuer_key.sign(&digest);

        Ok(Tct {
            version: "aitp/0.1".into(),
            jti,
            issuer,
            subject,
            audience,
            issued_at,
            expires_at,
            grants: self.grants,
            binding,
            signature: signature.into_string(),
        })
    }
}

/// Serialization view for TCT signing — every field of [`Tct`] except
/// `signature`.
///
/// Field names mirror the schema; JCS produces deterministic bytes
/// regardless of struct field order, but the names and skip rules must
/// match exactly. There are no skip-when-empty rules on a TCT in v0.1
/// (every field is required).
#[derive(Serialize)]
pub(crate) struct TctSigningView<'a> {
    pub version: &'a str,
    pub jti: &'a Uuid,
    pub issuer: &'a Aid,
    pub subject: &'a Aid,
    pub audience: &'a Aid,
    pub issued_at: &'a Timestamp,
    pub expires_at: &'a Timestamp,
    pub grants: &'a [String],
    pub binding: &'a TctBinding,
}
