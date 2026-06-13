//! Delegation token builder (RFC-AITP-0006 §3; RFC-AITP-0011 §1).
//!
//! Two entry points:
//!
//! - [`DelegationBuilder::new`] — single-hop: B delegates against the
//!   grant voucher A minted alongside B's TCT. The voucher is embedded
//!   verbatim and its claims drive the audience, expiry cap, and
//!   scope-subset sanity checks.
//! - [`DelegationBuilder::extending`] — multi-hop (RFC-AITP-0011,
//!   opt-in): C extends a delegation it received, carrying the prior
//!   hops verbatim in `chain` with a digest-array `chain_hash` and a
//!   fresh per-hop `jti`. No voucher on the outer token — authority
//!   bottoms out in `chain[0]`'s voucher.

use crate::types::DelegationClaims;
use crate::DelegationError;
use aitp_core::{base64url, jcs, Aid, Timestamp, PROTOCOL_VERSION};
use aitp_crypto::{jws, AitpSigningKey, AitpVerifyingKey};
use aitp_tct::{Cnf, GrantVoucherClaims};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Default delegation token TTL (1 hour).
pub const DEFAULT_DELEGATION_TTL_SECS: i64 = 3600;

/// Compute the RFC-AITP-0011 §5 digest-array chain hash:
/// `base64url(sha256(JCS([base64url(sha256(ASCII(chain[i])))…])))`.
pub fn compute_chain_hash(chain: &[String]) -> Result<String, DelegationError> {
    let digests: Vec<String> = chain
        .iter()
        .map(|entry| base64url::encode(&Sha256::digest(entry.as_bytes())))
        .collect();
    let canonical = jcs::canonicalize_serializable(&digests)
        .map_err(|e| DelegationError::Canonicalization(e.to_string()))?;
    Ok(base64url::encode(&Sha256::digest(&canonical)))
}

enum Authority {
    /// Single-hop: A's voucher, embedded verbatim.
    Voucher {
        token: String,
        claims: GrantVoucherClaims,
    },
    /// Multi-hop: the prior delegation token being extended, plus its
    /// decoded claims (peeked unverified — the verifier re-checks every
    /// hop; the builder uses them only for caps and continuity).
    Prior {
        token: String,
        claims: DelegationClaims,
    },
}

/// Fluent builder for issuing a delegation token (compact JWS).
pub struct DelegationBuilder<'a> {
    issuer_key: &'a AitpSigningKey,
    authority: Authority,
    delegatee: Option<Aid>,
    scope: Vec<String>,
    ttl_secs: i64,
    now_override: Option<Timestamp>,
    jti_override: Option<Uuid>,
}

impl<'a> DelegationBuilder<'a> {
    /// Begin a single-hop delegation, signed by `issuer_key` (B's key),
    /// rooted in `voucher` — the grant voucher A delivered alongside
    /// B's TCT in the handshake commit payload.
    pub fn new(issuer_key: &'a AitpSigningKey, voucher: &str) -> Result<Self, DelegationError> {
        let payload = jws::decode_payload_unverified(voucher).map_err(DelegationError::Crypto)?;
        let claims: GrantVoucherClaims = serde_json::from_slice(&payload)
            .map_err(|e| DelegationError::ClaimsMalformed(format!("voucher: {e}")))?;
        // The voucher must actually entitle this signer to delegate.
        if &claims.sub != issuer_key.aid() {
            return Err(DelegationError::InvalidVoucher);
        }
        Ok(Self {
            issuer_key,
            authority: Authority::Voucher {
                token: voucher.to_string(),
                claims,
            },
            delegatee: None,
            scope: Vec::new(),
            ttl_secs: DEFAULT_DELEGATION_TTL_SECS,
            now_override: None,
            jti_override: None,
        })
    }

    /// Begin a multi-hop extension (RFC-AITP-0011), signed by
    /// `issuer_key` (the holder of `prior` — its `sub`). The new outer
    /// token carries `prior`'s chain plus `prior` itself, verbatim.
    pub fn extending(issuer_key: &'a AitpSigningKey, prior: &str) -> Result<Self, DelegationError> {
        let payload = jws::decode_payload_unverified(prior).map_err(DelegationError::Crypto)?;
        let claims: DelegationClaims = serde_json::from_slice(&payload)
            .map_err(|e| DelegationError::ClaimsMalformed(format!("prior hop: {e}")))?;
        if &claims.sub != issuer_key.aid() {
            return Err(DelegationError::InvalidVoucher);
        }
        if claims.jti.is_none() {
            // The prior hop was not minted as chain-extensible
            // (RFC-AITP-0011 §1.1: every hop of a chain carries `jti`).
            return Err(DelegationError::ClaimsMalformed(
                "prior hop lacks the per-hop jti required for chaining".into(),
            ));
        }
        Ok(Self {
            issuer_key,
            authority: Authority::Prior {
                token: prior.to_string(),
                claims,
            },
            delegatee: None,
            scope: Vec::new(),
            ttl_secs: DEFAULT_DELEGATION_TTL_SECS,
            now_override: None,
            jti_override: None,
        })
    }

    /// Set the delegatee's AID (C). Its key (encoded in the AID) drives
    /// `cnf.jkt`.
    pub fn delegatee(mut self, aid: Aid) -> Self {
        self.delegatee = Some(aid);
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

    /// Override default TTL (1h). The effective expiry is capped at the
    /// authority's expiry (voucher `exp`, or the prior hop's `exp`).
    pub fn ttl_secs(mut self, ttl: i64) -> Self {
        self.ttl_secs = ttl;
        self
    }

    /// Override `now`. Tests / fixtures only.
    pub fn now(mut self, ts: Timestamp) -> Self {
        self.now_override = Some(ts);
        self
    }

    /// Mint a per-hop `jti`, making a single-hop token extensible into
    /// a chain (RFC-AITP-0011 §1.1). Multi-hop tokens always carry one.
    /// Pass a fixed value for tests/fixtures.
    pub fn jti(mut self, jti: Uuid) -> Self {
        self.jti_override = Some(jti);
        self
    }

    /// Construct, sign, and return the delegation compact JWS.
    pub fn build(self) -> Result<String, DelegationError> {
        let delegatee = self
            .delegatee
            .ok_or(DelegationError::MissingField("delegatee"))?;
        if self.scope.is_empty() {
            return Err(DelegationError::EmptyScope);
        }
        let issued_by = self.issuer_key.aid().clone();
        if issued_by == delegatee {
            return Err(DelegationError::SelfDelegation);
        }

        // Authority-derived caps: audience, allowed scope, max expiry.
        let (aud, allowed_scope, max_expiry) = match &self.authority {
            Authority::Voucher { claims, .. } => (claims.iss.clone(), &claims.grants, claims.exp),
            Authority::Prior { claims, .. } => (claims.aud.clone(), &claims.scope, claims.exp),
        };
        for cap in &self.scope {
            if !allowed_scope.contains(cap) {
                return Err(DelegationError::ScopeExceeded);
            }
        }

        let now = self.now_override.unwrap_or_else(Timestamp::now);
        let proposed = now.plus_secs(self.ttl_secs);
        let exp = if proposed.0 < max_expiry.0 {
            proposed
        } else {
            max_expiry
        };

        let cnf_key = AitpVerifyingKey::from_aid(&delegatee).map_err(DelegationError::Crypto)?;
        let jkt = cnf_key
            .to_jwk_thumbprint()
            .map_err(DelegationError::Crypto)?;

        let (voucher, jti, chain, chain_hash) = match self.authority {
            Authority::Voucher { token, .. } => (Some(token), self.jti_override, None, None),
            Authority::Prior { token, claims } => {
                // chain = prior's chain (possibly empty) + the prior
                // token itself, all verbatim.
                let mut chain = claims.chain.unwrap_or_default();
                chain.push(token);
                let hash = compute_chain_hash(&chain)?;
                (
                    None,
                    Some(self.jti_override.unwrap_or_else(Uuid::new_v4)),
                    Some(chain),
                    Some(hash),
                )
            }
        };

        let claims = DelegationClaims {
            ver: PROTOCOL_VERSION.into(),
            iss: issued_by,
            sub: delegatee,
            aud,
            scope: self.scope,
            exp,
            cnf: Cnf { jkt },
            voucher,
            jti,
            chain,
            chain_hash,
            ext: None,
        };
        jws::sign_compact(self.issuer_key, jws::TYP_DELEGATION, &claims)
            .map_err(DelegationError::Crypto)
    }
}
