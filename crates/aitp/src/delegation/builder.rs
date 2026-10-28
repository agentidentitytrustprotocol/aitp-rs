//! Delegation token builder (RFC-AITP-0006 §3).
//!
//! B delegates against the grant voucher A minted alongside B's TCT
//! ([`DelegationBuilder::new`]). The voucher is embedded verbatim and its
//! claims drive the audience, expiry cap, and scope-subset sanity checks.
//!
//! With an async (KMS, HSM) signer, use [`DelegationBuilder::new_async`]
//! and finish with [`DelegationBuilder::build_async`]. Validation and
//! output are the same.

use crate::core::{
    check_members, from_serde_error, reject_duplicate_keys, Aid, Timestamp, PROTOCOL_VERSION,
};
use crate::crypto::{jws, AitpSigner, AitpVerifyingKey, DynAsyncAitpSigner};
use crate::delegation::types::{DelegationClaims, IssuedDelegation};
use crate::delegation::DelegationError;
use crate::tct::{Cnf, GrantVoucherClaims, GRANT_VOUCHER_CLAIMS_MEMBERS};

/// Default delegation token TTL (1 hour).
pub const DEFAULT_DELEGATION_TTL: std::time::Duration = std::time::Duration::from_secs(3600);

/// Fluent builder for issuing a delegation token (compact JWS).
///
/// The signer kind is a type parameter: [`DelegationBuilder::new`] takes
/// an [`AitpSigner`] and finishes with [`DelegationBuilder::build`];
/// [`DelegationBuilder::new_async`] takes a [`DynAsyncAitpSigner`] and
/// finishes with [`DelegationBuilder::build_async`]. The setters are
/// shared.
pub struct DelegationBuilder<'a, S: ?Sized + 'a = dyn AitpSigner + 'a> {
    issuer_key: &'a S,
    voucher_token: String,
    voucher: GrantVoucherClaims,
    delegatee: Option<Aid>,
    scope: Vec<String>,
    ttl: std::time::Duration,
    now_override: Option<Timestamp>,
}

impl<S: ?Sized> std::fmt::Debug for DelegationBuilder<'_, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DelegationBuilder")
            .field("delegatee", &self.delegatee)
            .field("scope", &self.scope)
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
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

    /// Construct and sign the delegation token, and return it with its
    /// claims.
    pub fn build(self) -> Result<IssuedDelegation, DelegationError> {
        let (claims, signer) = self.draft()?;
        let token = jws::sign_compact(signer, jws::TYP_DELEGATION, &claims)
            .map_err(DelegationError::Crypto)?;
        Ok(IssuedDelegation { token, claims })
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

    /// As [`DelegationBuilder::build`], awaiting the backend. Validation
    /// and output are identical; the future is `Send`. A backend failure
    /// surfaces as `DelegationError::Crypto(CryptoError::Signer(_))`.
    pub async fn build_async(self) -> Result<IssuedDelegation, DelegationError> {
        let (claims, signer) = self.draft()?;
        let token = jws::sign_compact_async(signer, jws::TYP_DELEGATION, &claims)
            .await
            .map_err(DelegationError::Crypto)?;
        Ok(IssuedDelegation { token, claims })
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
            voucher_token: voucher.to_string(),
            voucher: claims,
            delegatee: None,
            scope: Vec::new(),
            ttl: DEFAULT_DELEGATION_TTL,
            now_override: None,
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
    /// voucher's `exp`. The expiry counts whole seconds; a fraction of a
    /// second is dropped.
    pub fn ttl(mut self, ttl: std::time::Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Override `now`. Tests / fixtures only.
    pub fn now(mut self, ts: Timestamp) -> Self {
        self.now_override = Some(ts);
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

        // Voucher-derived caps: audience, allowed scope, max expiry.
        let aud = self.voucher.iss.clone();
        let max_expiry = self.voucher.exp;
        for cap in &self.scope {
            if !self.voucher.grants.contains(cap) {
                return Err(DelegationError::ScopeExceeded);
            }
        }

        let now = self.now_override.unwrap_or_else(Timestamp::now);
        let proposed = now.saturating_add(self.ttl);
        let exp = if proposed.0 < max_expiry.0 {
            proposed
        } else {
            max_expiry
        };

        let cnf_key = AitpVerifyingKey::from_aid(&delegatee).map_err(DelegationError::Crypto)?;
        let jkt = cnf_key
            .to_jwk_thumbprint_sha256()
            .map_err(DelegationError::Crypto)?;

        let claims = DelegationClaims {
            ver: PROTOCOL_VERSION.into(),
            iss: issued_by,
            sub: delegatee,
            aud,
            scope: self.scope,
            exp,
            cnf: Cnf { jkt },
            voucher: Some(self.voucher_token),
            ext: None,
        };
        Ok((claims, self.issuer_key))
    }
}
