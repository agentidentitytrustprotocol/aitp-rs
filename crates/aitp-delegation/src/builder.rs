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
//!
//! With an async (KMS, HSM) signer, use [`DelegationBuilder::new_async`]
//! or [`DelegationBuilder::extending_async`] and finish with
//! [`DelegationBuilder::build_async`]. Validation and output are the same.

use crate::types::{DelegationClaims, DELEGATION_CLAIMS_MEMBERS};
use crate::DelegationError;
use aitp_core::{
    base64url, check_members, from_serde_error, jcs, reject_duplicate_keys, Aid, Timestamp,
    PROTOCOL_VERSION,
};
use aitp_crypto::{jws, AitpSigner, AitpVerifyingKey, DynAsyncAitpSigner};
use aitp_tct::{Cnf, GrantVoucherClaims, GRANT_VOUCHER_CLAIMS_MEMBERS};
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
///
/// The signer kind is a type parameter: [`DelegationBuilder::new`] /
/// [`DelegationBuilder::extending`] take an [`AitpSigner`] and finish with
/// [`DelegationBuilder::build`]; [`DelegationBuilder::new_async`] /
/// [`DelegationBuilder::extending_async`] take a [`DynAsyncAitpSigner`]
/// and finish with [`DelegationBuilder::build_async`]. The setters are
/// shared.
pub struct DelegationBuilder<'a, S: ?Sized + 'a = dyn AitpSigner + 'a> {
    issuer_key: &'a S,
    authority: Authority,
    delegatee: Option<Aid>,
    scope: Vec<String>,
    ttl_secs: i64,
    now_override: Option<Timestamp>,
    jti_override: Option<Uuid>,
}

impl<'a> DelegationBuilder<'a, dyn AitpSigner + 'a> {
    /// Begin a single-hop delegation, signed by `issuer_key` (B's key),
    /// rooted in `voucher` — the grant voucher A delivered alongside
    /// B's TCT in the handshake commit payload.
    ///
    /// Accepts any [`AitpSigner`] (in-process key, KMS, HSM); a backend
    /// failure surfaces from [`Self::build`] as
    /// `DelegationError::Crypto(CryptoError::Signer(_))`.
    pub fn new(issuer_key: &'a dyn AitpSigner, voucher: &str) -> Result<Self, DelegationError> {
        Self::rooted_in_voucher(issuer_key, voucher)
    }

    /// Begin a multi-hop extension (RFC-AITP-0011), signed by
    /// `issuer_key` (the holder of `prior` — its `sub`). The new outer
    /// token carries `prior`'s chain plus `prior` itself, verbatim.
    ///
    /// Accepts any [`AitpSigner`] (in-process key, KMS, HSM); a backend
    /// failure surfaces from [`Self::build`] as
    /// `DelegationError::Crypto(CryptoError::Signer(_))`.
    pub fn extending(issuer_key: &'a dyn AitpSigner, prior: &str) -> Result<Self, DelegationError> {
        Self::extending_prior(issuer_key, prior)
    }

    /// Construct, sign, and return the delegation compact JWS.
    pub fn build(self) -> Result<String, DelegationError> {
        let (claims, signer) = self.draft()?;
        jws::sign_compact(signer, jws::TYP_DELEGATION, &claims).map_err(DelegationError::Crypto)
    }
}

impl<'a> DelegationBuilder<'a, dyn DynAsyncAitpSigner + 'a> {
    /// As [`DelegationBuilder::new`], signed by an async backend, for
    /// example `DelegationBuilder::new_async(&*arc_kms_signer, voucher)`.
    /// The voucher is checked here, exactly as in the sync constructor.
    /// Finish with [`Self::build_async`].
    pub fn new_async(
        issuer_key: &'a dyn DynAsyncAitpSigner,
        voucher: &str,
    ) -> Result<Self, DelegationError> {
        Self::rooted_in_voucher(issuer_key, voucher)
    }

    /// As [`DelegationBuilder::extending`], signed by an async backend.
    /// The prior hop is checked here, exactly as in the sync constructor.
    /// Finish with [`Self::build_async`].
    pub fn extending_async(
        issuer_key: &'a dyn DynAsyncAitpSigner,
        prior: &str,
    ) -> Result<Self, DelegationError> {
        Self::extending_prior(issuer_key, prior)
    }

    /// As [`DelegationBuilder::build`], awaiting the backend. Validation
    /// and output are identical; the future is `Send`. A backend failure
    /// surfaces as `DelegationError::Crypto(CryptoError::Signer(_))`.
    pub async fn build_async(self) -> Result<String, DelegationError> {
        let (claims, signer) = self.draft()?;
        jws::sign_compact_async(signer, jws::TYP_DELEGATION, &claims)
            .await
            .map_err(DelegationError::Crypto)
    }
}

/// The issuer's AID, whichever signer kind holds it.
trait IssuerAid {
    fn issuer_aid(&self) -> &Aid;
}
impl IssuerAid for dyn AitpSigner + '_ {
    fn issuer_aid(&self) -> &Aid {
        self.aid()
    }
}
impl IssuerAid for dyn DynAsyncAitpSigner + '_ {
    fn issuer_aid(&self) -> &Aid {
        self.aid()
    }
}

#[allow(private_bounds)]
impl<'a, S: ?Sized + IssuerAid> DelegationBuilder<'a, S> {
    /// Single-hop constructor body, shared by `new` and `new_async`.
    fn rooted_in_voucher(issuer_key: &'a S, voucher: &str) -> Result<Self, DelegationError> {
        let payload = jws::decode_payload_unverified(voucher).map_err(DelegationError::Crypto)?;
        // Claim-set check (RFC-AITP-0001 §7) on the unverified peek,
        // ahead of anything else: an unknown claim on the embedded
        // voucher must surface as UNKNOWN_FIELD, not be swallowed into
        // DELEGATION_INVALID_VOUCHER by a later step.
        // RFC-AITP-0001 §5.4.5 / issue #140: raw-bytes duplicate-key guard
        // ahead of the `Value` conversion below (last-write-wins on a
        // duplicate key).
        reject_duplicate_keys(&payload).map_err(DelegationError::ClaimsMalformed)?;
        if let Ok(peek_value) = serde_json::from_slice::<serde_json::Value>(&payload) {
            check_members(
                "GrantVoucherClaims",
                &peek_value,
                GRANT_VOUCHER_CLAIMS_MEMBERS,
            )
            .map_err(|e| DelegationError::UnknownField(e.field))?;
        }
        let claims: GrantVoucherClaims = serde_json::from_slice(&payload).map_err(|e| {
            if let Some(field) = from_serde_error(&e) {
                DelegationError::UnknownField(field)
            } else {
                DelegationError::ClaimsMalformed(format!("voucher: {e}"))
            }
        })?;
        // The voucher must actually entitle this signer to delegate.
        if &claims.sub != issuer_key.issuer_aid() {
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

    /// Multi-hop constructor body, shared by `extending` and
    /// `extending_async`.
    fn extending_prior(issuer_key: &'a S, prior: &str) -> Result<Self, DelegationError> {
        let payload = jws::decode_payload_unverified(prior).map_err(DelegationError::Crypto)?;
        // Claim-set check (RFC-AITP-0001 §7) on the unverified peek of
        // the prior hop, same rationale as the voucher peek above.
        // RFC-AITP-0001 §5.4.5 / issue #140: same raw-bytes-first
        // rationale as the voucher peek above.
        reject_duplicate_keys(&payload).map_err(DelegationError::ClaimsMalformed)?;
        if let Ok(peek_value) = serde_json::from_slice::<serde_json::Value>(&payload) {
            check_members("DelegationClaims", &peek_value, DELEGATION_CLAIMS_MEMBERS)
                .map_err(|e| DelegationError::UnknownField(e.field))?;
        }
        let claims: DelegationClaims = serde_json::from_slice(&payload).map_err(|e| {
            if let Some(field) = from_serde_error(&e) {
                DelegationError::UnknownField(field)
            } else {
                DelegationError::ClaimsMalformed(format!("prior hop: {e}"))
            }
        })?;
        if &claims.sub != issuer_key.issuer_aid() {
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
    pub fn scope<I, C>(mut self, scope: I) -> Self
    where
        I: IntoIterator<Item = C>,
        C: Into<String>,
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

    /// Validate and assemble the claims; signing is the caller's.
    fn draft(self) -> Result<(DelegationClaims, &'a S), DelegationError> {
        let delegatee = self
            .delegatee
            .ok_or(DelegationError::MissingField("delegatee"))?;
        if self.scope.is_empty() {
            return Err(DelegationError::EmptyScope);
        }
        let issued_by = self.issuer_key.issuer_aid().clone();
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
        Ok((claims, self.issuer_key))
    }
}
