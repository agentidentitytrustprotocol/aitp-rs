//! Delegation token builder.
//!
//! `DelegationBuilder` produces a fully-signed [`DelegationToken`] from
//! a `held_tct` (B's source TCT issued by A) plus C's identity. Per
//! RFC-AITP-0006 §3.1 the `grant_proof` block is built by copying fields
//! out of `held_tct` so that A's original signature continues to
//! authenticate the underlying capability grant.

use crate::types::{DelegationStep, DelegationToken, GrantProof};
use crate::DelegationError;
use aitp_core::{base64url, jcs, Aid, Timestamp};
use aitp_crypto::{AitpSigningKey, AitpVerifyingKey};
use aitp_tct::Tct;
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Default delegation token TTL (1 hour).
pub const DEFAULT_DELEGATION_TTL_SECS: i64 = 3600;

/// Fluent builder for issuing a delegation token.
pub struct DelegationBuilder<'a> {
    issuer_key: &'a AitpSigningKey,
    held_tct: &'a Tct,
    delegatee: Option<Aid>,
    delegatee_pubkey: Option<AitpVerifyingKey>,
    scope: Vec<String>,
    ttl_secs: i64,
    now_override: Option<Timestamp>,
}

impl<'a> DelegationBuilder<'a> {
    /// Begin a new delegation, signed by `issuer_key` (B's key) using
    /// `held_tct` (A's TCT to B) as the grant proof source.
    pub fn new(issuer_key: &'a AitpSigningKey, held_tct: &'a Tct) -> Self {
        Self {
            issuer_key,
            held_tct,
            delegatee: None,
            delegatee_pubkey: None,
            scope: Vec::new(),
            ttl_secs: DEFAULT_DELEGATION_TTL_SECS,
            now_override: None,
        }
    }

    /// Set C's AID.
    pub fn delegatee(mut self, c_aid: Aid) -> Self {
        self.delegatee = Some(c_aid);
        self
    }

    /// Set C's verifying key (for `cnf`).
    pub fn delegatee_pubkey(mut self, pk: AitpVerifyingKey) -> Self {
        self.delegatee_pubkey = Some(pk);
        self
    }

    /// Set the scope of capabilities being delegated.
    pub fn scope<I, S>(mut self, scope: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.scope = scope.into_iter().map(Into::into).collect();
        self
    }

    /// Override default TTL (1h).
    pub fn ttl_secs(mut self, ttl: i64) -> Self {
        self.ttl_secs = ttl;
        self
    }

    /// Override `now`. Tests / fixtures only.
    pub fn now(mut self, ts: Timestamp) -> Self {
        self.now_override = Some(ts);
        self
    }

    /// Construct, sign, and return the delegation token.
    pub fn build(self) -> Result<DelegationToken, DelegationError> {
        let delegatee = self
            .delegatee
            .ok_or(DelegationError::MissingField("delegatee"))?;
        let delegatee_pk = self
            .delegatee_pubkey
            .ok_or(DelegationError::MissingField("delegatee_pubkey"))?;

        if self.scope.is_empty() {
            return Err(DelegationError::EmptyScope);
        }

        // Sanity-check scope ⊆ held_tct.grants at issuance time.
        for cap in &self.scope {
            if !self.held_tct.grants.contains(cap) {
                return Err(DelegationError::ScopeExceeded);
            }
        }

        // Reject self-delegation: B (issued_by) must not equal C (delegatee).
        let issued_by = self.issuer_key.aid().clone();
        if issued_by == delegatee {
            return Err(DelegationError::SelfDelegation);
        }

        // Compose grant_proof from the held TCT. Per RFC-AITP-0006 §3.1
        // (rc.2), `issued_at` is carried verbatim so the verifier can
        // reconstruct the source TCT signing input without TTL guessing.
        let grant_proof = GrantProof {
            issuer: self.held_tct.issuer.clone(),
            subject: self.held_tct.subject.clone(),
            capabilities: self.held_tct.grants.clone(),
            issued_at: self.held_tct.issued_at,
            expires_at: self.held_tct.expires_at,
            source_tct_jti: self.held_tct.jti,
            signature: self.held_tct.signature.clone(),
        };

        // Algorithm-agile cnf: matches `Aid::pubkey_compressed_bytes` for
        // the delegatee — 32 B Ed25519 raw → 43 b64u chars, or
        // 33 B P-256 SEC1-compressed → 44 b64u chars.
        let cnf = base64url::encode(&delegatee_pk.to_compressed());
        debug_assert!(matches!(cnf.len(), 43 | 44));

        let now = self.now_override.unwrap_or_else(Timestamp::now);
        let max_expiry = self.held_tct.expires_at;
        let proposed_expiry = now.plus_secs(self.ttl_secs);
        let expires_at = if proposed_expiry.0 < max_expiry.0 {
            proposed_expiry
        } else {
            max_expiry
        };

        let delegator = self.held_tct.issuer.clone(); // A
        let audience = delegator.clone();

        let view = DelegationSigningView {
            delegator: &delegator,
            delegatee: &delegatee,
            issued_by: &issued_by,
            audience: &audience,
            scope: &self.scope,
            expires_at: &expires_at,
            cnf: &cnf,
            grant_proof: &grant_proof,
            chain: None,
            chain_hash: None,
        };
        let canonical = jcs::canonicalize_serializable(&view)
            .map_err(|e| DelegationError::Canonicalization(e.to_string()))?;
        let digest = Sha256::digest(&canonical);
        let signature = self.issuer_key.sign(&digest);

        Ok(DelegationToken {
            delegator,
            delegatee,
            issued_by,
            audience,
            scope: self.scope,
            expires_at,
            cnf,
            grant_proof,
            chain: None,
            chain_hash: None,
            signature: signature.into_string(),
        })
    }
}

/// Serialization view of [`DelegationToken`] without `signature`.
///
/// `chain` and `chain_hash` use `skip_serializing_if = "Option::is_none"`
/// so single-hop tokens (the v0.1 case) produce JCS bytes byte-identical
/// to pre-rc.1 — this preserves signature compatibility for the
/// existing single-hop fixtures.
#[derive(Serialize)]
pub(crate) struct DelegationSigningView<'a> {
    pub delegator: &'a Aid,
    pub delegatee: &'a Aid,
    pub issued_by: &'a Aid,
    pub audience: &'a Aid,
    pub scope: &'a [String],
    pub expires_at: &'a Timestamp,
    pub cnf: &'a str,
    pub grant_proof: &'a GrantProof,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain: Option<&'a [DelegationStep]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_hash: Option<&'a str>,
}
