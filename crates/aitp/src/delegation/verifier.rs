//! Delegation verification (RFC-AITP-0006 §4).
//!
//! No step reconstructs any byte sequence: both signatures — the token
//! and the embedded voucher — are verified over bytes exactly as
//! transmitted.

use crate::core::{
    check_members, from_serde_error, reject_duplicate_keys, Aid, Timestamp, PROTOCOL_VERSION,
};
use crate::crypto::{jws, AitpVerifyingKey};
use crate::delegation::types::{DelegationClaims, VerifiedDelegation, DELEGATION_CLAIMS_MEMBERS};
use crate::delegation::DelegationError;
use crate::manifest::{resolve_verified_manifest, ManifestResolver, VerifyManifestContext};
use crate::tct::revocation::{apply_revocation, RevocationQuery, RevocationRejection};
use crate::tct::{GrantVoucherClaims, RevocationSource};
use uuid::Uuid;

/// Inputs for verifying a delegation token.
///
/// `verifier` is A — the original grantor, voucher issuer, and the only
/// party a delegation is presentable to.
///
/// `#[non_exhaustive]`: construct with [`VerifyDelegationContext::new`] and
/// the builder methods rather than a struct literal, so a future
/// verification knob is an additive change instead of a breaking one for
/// every downstream crate.
#[non_exhaustive]
pub struct VerifyDelegationContext<'a> {
    /// The verifier's own AID (A). `aud` and `voucher.iss` MUST equal
    /// this.
    pub verifier: &'a Aid,
    /// Current time.
    pub now: Timestamp,
    /// Revocation source for the source TCT (`voucher.src_jti`), A's
    /// **own** deny list: the query's `issuer` is [`Self::verifier`]. The
    /// only stateful single-hop check; runs after all signature checks
    /// (RFC-AITP-0008 §3.3).
    pub revocation: RevocationSource<'a>,
    /// Source of each delegation issuer's Manifest (RFC-AITP-0006 §4
    /// step 1). The token is verified under the key its issuer's verified
    /// Manifest designates; with no source configured (or no usable
    /// Manifest for the issuer) the token is rejected with
    /// [`DelegationError::KeyResolutionFailed`].
    pub issuer_manifests: Option<&'a dyn ManifestResolver>,
}

impl std::fmt::Debug for VerifyDelegationContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifyDelegationContext")
            .field("verifier", self.verifier)
            .field("now", &self.now)
            .field("revocation", &self.revocation)
            .field("issuer_manifests", &self.issuer_manifests.is_some())
            .finish()
    }
}

impl<'a> VerifyDelegationContext<'a> {
    /// Context with the given source-TCT revocation choice.
    pub fn new(verifier: &'a Aid, now: Timestamp, revocation: RevocationSource<'a>) -> Self {
        Self {
            verifier,
            now,
            revocation,
            issuer_manifests: None,
        }
    }

    /// Where verification gets each delegation issuer's Manifest
    /// (RFC-AITP-0006 §4 step 1). Required for any delegation to verify.
    pub fn with_issuer_manifests(mut self, resolver: &'a dyn ManifestResolver) -> Self {
        self.issuer_manifests = Some(resolver);
        self
    }
}

/// Verify a delegation token presented to `ctx.verifier` (A).
///
/// RFC-AITP-0006 §4, in order: outer JWS
/// (typ / alg pin / signature under the key the issuer's verified
/// Manifest designates, from `ctx.issuer_manifests` / `ver`) → `aud` + `exp` → embedded
/// voucher (typ `aitp-grant+jwt`, `voucher.iss` == A, signature under
/// A's **own** key) → `voucher.sub` == outer `iss` → expiry
/// monotonicity → `scope ⊆ voucher.grants` → self-delegation +
/// `cnf.jkt` binding → revocation on `voucher.src_jti` (the only
/// stateful check, last per RFC-AITP-0008 §3.3).
///
/// A token carrying a `chain` claim (RFC-AITP-0011) is rejected with
/// [`DelegationError::MultihopNotSupported`] before any other claim check
/// (RFC-AITP-0006 §4 multi-hop guard); one carrying `jti` or `chain_hash`
/// is outside the RFC-AITP-0006 §2 claim set and is rejected with
/// [`DelegationError::ClaimsMalformed`].
///
/// The downstream PoP exchange (RFC-AITP-0006 §4 step 9) is a separate
/// challenge/response flow run by the caller against the presenting
/// agent, with the bound key taken from the **outer** `sub` AID
/// (`crate::tct::sign_pop_response` / `verify_pop_response`).
pub fn verify_delegation(
    token: &str,
    ctx: &VerifyDelegationContext<'_>,
) -> Result<VerifiedDelegation, DelegationError> {
    // Peek (unverified) to learn the claimed shape; everything is
    // re-established cryptographically below.
    peek_claims(token)?;
    verify_single_hop(token, ctx)
}

fn peek_claims(token: &str) -> Result<DelegationClaims, DelegationError> {
    // typ-first gate (RFC-AITP-0006 §4 step 1; D7 / issue #140 follow-up):
    // mirrors `crate::tct::verifier::peek_header_typ`'s pattern via the
    // shared `crate::crypto::jws::peek_typ` helper. Unlike TCT/voucher —
    // where a typ mismatch defers silently, letting the *next*
    // `jws::verify_compact` call make the authoritative call — this
    // function's own next step (below) is a strict `deny_unknown_fields`
    // deserialize, which would misdiagnose a TCT- or voucher-shaped
    // payload as `ClaimsMalformed`/`UnknownField` before
    // `verify_hop_jws`'s later `jws::verify_compact` ever gets a chance
    // to run. So a present-but-wrong `typ` is reported directly as
    // `TypMismatch` here, matching `aitp-verifier-py`'s ordering (typ
    // ahead of unknown-fields) and closing a real cross-impl divergence.
    // An absent `typ` falls through unchanged, exactly as TCT/voucher
    // treat it.
    if let Some(typ) = jws::peek_typ(token) {
        if typ != jws::TYP_DELEGATION {
            return Err(DelegationError::Crypto(
                crate::crypto::CryptoError::TypMismatch {
                    expected: jws::TYP_DELEGATION.to_string(),
                    got: typ,
                },
            ));
        }
    }

    let payload = jws::decode_payload_unverified(token).map_err(DelegationError::Crypto)?;
    // Claim-set check (RFC-AITP-0001 §7 / RFC-AITP-0005 §7.2 step 1) on
    // the still-unverified payload — structurally ahead of AID-pinned
    // `alg` checking and signature verification, same ordering rationale
    // as `crate::tct::verify_tct`. A reject decision drawn from unverified
    // bytes is sound: no trust is ever extended on the strength of it.
    // A payload that isn't valid JSON at this stage is left for the
    // strict deserialize below to diagnose.
    // RFC-AITP-0001 §5.4.5 / issue #140: the raw-bytes duplicate-key guard
    // must run before the `Value` conversion below, whose map
    // representation is last-write-wins on a duplicate key.
    reject_duplicate_keys(&payload).map_err(DelegationError::ClaimsMalformed)?;
    if let Ok(peek_value) = serde_json::from_slice::<serde_json::Value>(&payload) {
        check_members("DelegationClaims", &peek_value, DELEGATION_CLAIMS_MEMBERS)
            .map_err(|e| DelegationError::UnknownField(e.field))?;
        // Multi-hop guard (RFC-AITP-0006 §4): a `chain` claim, whatever
        // its value, is a structural rejection ahead of every other
        // claim check.
        if peek_value.get("chain").is_some() {
            return Err(DelegationError::MultihopNotSupported);
        }
        // `jti` and `chain_hash` are RFC-AITP-0011 claims outside the
        // RFC-AITP-0006 §2 claim set (RFC-AITP-0011 §1.1).
        for member in ["jti", "chain_hash"] {
            if peek_value.get(member).is_some() {
                return Err(DelegationError::ClaimsMalformed(format!(
                    "{member} is not a single-hop delegation claim"
                )));
            }
        }
    }
    serde_json::from_slice(&payload).map_err(|e| {
        if let Some(field) = from_serde_error(&e) {
            DelegationError::UnknownField(field)
        } else {
            DelegationError::ClaimsMalformed(e.to_string())
        }
    })
}

/// Strictly verify the delegation JWS under its claimed `iss` and return
/// its claims. The verification key is the one the claimed issuer's
/// verified Manifest designates (RFC-AITP-0006 §4 step 1), from `ctx.issuer_manifests`; no source, or no usable
/// Manifest for the issuer, is [`DelegationError::KeyResolutionFailed`].
/// A forged `iss` fails the signature check — only the claimed issuer's
/// key is tried — and the AID-derived alg pin forecloses algorithm
/// confusion (RFC-AITP-0001 §5.4.5).
fn verify_hop_jws(
    token: &str,
    ctx: &VerifyDelegationContext<'_>,
) -> Result<DelegationClaims, DelegationError> {
    let claimed = peek_claims(token)?;
    let signer = ctx
        .issuer_manifests
        .ok_or(crate::manifest::ManifestError::NotFound)
        .and_then(|r| {
            resolve_verified_manifest(r, &claimed.iss, &VerifyManifestContext::at(ctx.now))
        })
        .map_err(|source| DelegationError::KeyResolutionFailed {
            issuer: claimed.iss.clone(),
            source,
        })?
        .aid;
    let payload =
        jws::verify_compact(&signer, jws::TYP_DELEGATION, token).map_err(|e| match e {
            crate::crypto::CryptoError::SignatureInvalid => DelegationError::InvalidSignature,
            other => DelegationError::Crypto(other),
        })?;
    let claims: DelegationClaims = serde_json::from_slice(&payload).map_err(|e| {
        if let Some(field) = from_serde_error(&e) {
            DelegationError::UnknownField(field)
        } else {
            DelegationError::ClaimsMalformed(e.to_string())
        }
    })?;
    if claims.ver != PROTOCOL_VERSION {
        return Err(DelegationError::VersionUnknown);
    }
    Ok(claims)
}

/// Claim checks on the verified token (RFC-AITP-0006 §4).
fn check_hop_claims(
    claims: &DelegationClaims,
    ctx: &VerifyDelegationContext<'_>,
) -> Result<(), DelegationError> {
    if &claims.aud != ctx.verifier {
        return Err(DelegationError::AudienceMismatch);
    }
    if claims.iss == claims.sub {
        return Err(DelegationError::SelfDelegation);
    }
    if claims.scope.is_empty() {
        return Err(DelegationError::EmptyScope);
    }
    // cnf.jkt MUST match the key encoded in `sub` (RFC-AITP-0001 §5.4.4).
    let sub_key = AitpVerifyingKey::from_aid(&claims.sub).map_err(DelegationError::Crypto)?;
    let expected_jkt = sub_key
        .to_jwk_thumbprint()
        .map_err(DelegationError::Crypto)?;
    if claims.cnf.jkt != expected_jkt {
        return Err(DelegationError::CnfMalformed);
    }
    Ok(())
}

/// Verify the embedded root voucher: typ `aitp-grant+jwt`, issued and
/// signed by the verifier itself ("A is verifying its own past
/// signature; no key resolution is needed" — RFC-AITP-0006 §4 step 3),
/// entitling `expected_delegator` (step 4), still live (step 5, first
/// half).
fn verify_root_voucher(
    voucher_token: &str,
    expected_delegator: &Aid,
    ctx: &VerifyDelegationContext<'_>,
) -> Result<GrantVoucherClaims, DelegationError> {
    let voucher = crate::tct::verify_voucher(voucher_token, ctx.verifier).map_err(|e| match e {
        crate::tct::TctError::Crypto(c) => DelegationError::Crypto(c),
        crate::tct::TctError::VersionUnknown => DelegationError::VersionUnknown,
        // RFC-AITP-0001 §7: the embedded voucher's claim-set violation
        // must surface as UNKNOWN_FIELD, not be swallowed into
        // DELEGATION_INVALID_VOUCHER by this catch-all.
        crate::tct::TctError::UnknownField(f) => DelegationError::UnknownField(f),
        _ => DelegationError::InvalidVoucher,
    })?;
    if &voucher.sub != expected_delegator {
        return Err(DelegationError::InvalidVoucher);
    }
    if voucher.exp.is_in_the_past(ctx.now) {
        return Err(DelegationError::Expired);
    }
    Ok(voucher)
}

fn verify_single_hop(
    token: &str,
    ctx: &VerifyDelegationContext<'_>,
) -> Result<VerifiedDelegation, DelegationError> {
    // Step 1: outer JWS — strict parse, typ, alg pin, signature under
    // the key B's verified Manifest designates, ver.
    let claims = verify_hop_jws(token, ctx)?;
    // Step 2: addressing and freshness.
    if &claims.aud != ctx.verifier {
        return Err(DelegationError::AudienceMismatch);
    }
    if claims.exp.is_in_the_past(ctx.now) {
        return Err(DelegationError::Expired);
    }
    // Steps 3–4: embedded voucher.
    let voucher_token = claims
        .voucher
        .as_deref()
        .ok_or(DelegationError::InvalidVoucher)?;
    let voucher = verify_root_voucher(voucher_token, &claims.iss, ctx)?;
    // Step 5 (second half): a delegated grant cannot outlive its source.
    if claims.exp.0 > voucher.exp.0 {
        return Err(DelegationError::Expired);
    }
    // Step 6: scope constraint.
    for cap in &claims.scope {
        if !voucher.grants.contains(cap) {
            return Err(DelegationError::ScopeExceeded);
        }
    }
    // Step 8 + cnf binding (everything stateless before the lookup).
    check_hop_claims(&claims, ctx)?;
    // Step 7: source-TCT revocation — the only stateful check, last
    // (RFC-AITP-0008 §3.3).
    let effective_grants = check_source_revocation(ctx, &voucher.src_jti, &claims.scope)?;

    Ok(VerifiedDelegation {
        token: token.to_string(),
        claims,
        voucher,
        effective_grants,
    })
}

/// Source-TCT revocation (RFC-AITP-0008 §3.3), after every signature
/// check: the verifier's own list, keyed by `src_jti`. Returns `scope`,
/// narrowed under a soft-fail safe subset.
fn check_source_revocation(
    ctx: &VerifyDelegationContext<'_>,
    src_jti: &Uuid,
    scope: &[String],
) -> Result<Vec<String>, DelegationError> {
    delegation_revocation(
        &ctx.revocation,
        &RevocationQuery::new(ctx.verifier, src_jti, ctx.now),
        scope,
    )
}

/// Run `source` for one delegation artifact and map the outcome onto
/// [`DelegationError`]. Shared with the multi-hop verifier.
pub(crate) fn delegation_revocation(
    source: &RevocationSource<'_>,
    query: &RevocationQuery<'_>,
    scope: &[String],
) -> Result<Vec<String>, DelegationError> {
    apply_revocation(source, query, scope).map_err(|r| match r {
        RevocationRejection::Revoked => DelegationError::SourceTctRevoked,
        RevocationRejection::Unavailable(e) => DelegationError::RevocationUnavailable(e),
        RevocationRejection::SafeSubsetEmpty => DelegationError::SafeSubsetEmpty,
    })
}
