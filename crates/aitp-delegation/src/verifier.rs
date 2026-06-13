//! Delegation verification (RFC-AITP-0006 §4 single-hop;
//! RFC-AITP-0011 §2–§6 multi-hop).
//!
//! No step of either algorithm reconstructs any byte sequence: every
//! signature — outer token, every chain entry, the embedded voucher —
//! is verified over bytes exactly as transmitted. (The v0.1
//! `grant_proof` source-TCT reconstruction is gone.)

use crate::builder::compute_chain_hash;
use crate::types::{DelegationClaims, VerifiedDelegation};
use crate::DelegationError;
use aitp_core::{Aid, Timestamp, PROTOCOL_VERSION};
use aitp_crypto::{jws, AitpVerifyingKey};
use aitp_tct::GrantVoucherClaims;
use uuid::Uuid;

/// Default `max_delegation_hops` once multi-hop is enabled
/// (RFC-AITP-0011 §2): covers orchestrator → planner → executor.
pub const DEFAULT_MAX_HOPS: usize = 3;

/// Per-hop revocation lookup (RFC-AITP-0011 §6): `(hop issuer, hop
/// jti) → revoked?`, resolved against the hop issuer's deny list.
pub type HopRevocationCheck<'a> = &'a dyn Fn(&Aid, &Uuid) -> bool;

/// Inputs for verifying a delegation token.
///
/// `verifier` is A — the original grantor, voucher issuer, and the only
/// party a delegation is presentable to.
pub struct VerifyDelegationContext<'a> {
    /// The verifier's own AID (A). `aud` at every hop and `voucher.iss`
    /// MUST equal this.
    pub verifier: &'a Aid,
    /// Current time.
    pub now: Timestamp,
    /// Hop budget. `0` (the v0.2 default) means single-hop only: any
    /// token carrying a `chain` claim is structurally rejected with
    /// [`DelegationError::MultihopNotSupported`] before per-hop
    /// processing (RFC-AITP-0006 §4 multi-hop guard). A non-zero value
    /// opts into RFC-AITP-0011 with `total_hops = chain.len() + 2`
    /// bounded by this cap.
    pub max_hops: usize,
    /// A's **own** deny list: returns `true` if a source-TCT `jti`
    /// (`voucher.src_jti`) is revoked. The only stateful single-hop
    /// check; runs after all signature checks (RFC-AITP-0008 §3.3).
    pub revocation_check: Option<&'a dyn Fn(&Uuid) -> bool>,
    /// Multi-hop per-hop revocation (RFC-AITP-0011 §6): returns `true`
    /// if a hop's `jti` is revoked according to the deny list of the
    /// hop's issuer (first argument). Consulted for every chain entry
    /// and the outer token, after all signature checks.
    pub hop_revocation_check: Option<HopRevocationCheck<'a>>,
}

impl<'a> VerifyDelegationContext<'a> {
    /// Single-hop-only context (the v0.2 default posture) with no
    /// revocation sources.
    pub fn new(verifier: &'a Aid, now: Timestamp) -> Self {
        Self {
            verifier,
            now,
            max_hops: 0,
            revocation_check: None,
            hop_revocation_check: None,
        }
    }

    /// Opt into multi-hop verification (RFC-AITP-0011) with the given
    /// hop budget — use [`DEFAULT_MAX_HOPS`] unless the deployment
    /// explicitly needs longer chains.
    pub fn with_max_hops(mut self, max_hops: usize) -> Self {
        self.max_hops = max_hops;
        self
    }
}

/// Verify a delegation token presented to `ctx.verifier` (A).
///
/// Single-hop (RFC-AITP-0006 §4, in order): outer JWS
/// (typ / alg pin / signature / `ver`) → `aud` + `exp` → embedded
/// voucher (typ `aitp-grant+jwt`, `voucher.iss` == A, signature under
/// A's **own** key) → `voucher.sub` == outer `iss` → expiry
/// monotonicity → `scope ⊆ voucher.grants` → self-delegation +
/// `cnf.jkt` binding → revocation on `voucher.src_jti` (the only
/// stateful check, last per RFC-AITP-0008 §3.3).
///
/// Multi-hop (RFC-AITP-0011, only when `ctx.max_hops > 0`): hop limit →
/// chain-hash recomputation → per-hop JWS + claims + continuity +
/// expiry monotonicity + transitive scope subsetting + nested-chain
/// prefix consistency → per-hop revocation.
///
/// The downstream PoP exchange (RFC-AITP-0006 §4 step 9) is a separate
/// challenge/response flow run by the caller against the presenting
/// agent, with the bound key taken from the **outer** `sub` AID
/// (`aitp_tct::sign_pop_response` / `verify_pop_response`).
pub fn verify_delegation(
    token: &str,
    ctx: &VerifyDelegationContext<'_>,
) -> Result<VerifiedDelegation, DelegationError> {
    // Peek (unverified) to learn the claimed shape; everything is
    // re-established cryptographically below.
    let peeked = peek_claims(token)?;

    let chain_len = peeked.chain.as_ref().map_or(0, |c| c.len());
    if ctx.max_hops == 0 {
        if chain_len > 0 || peeked.chain.is_some() {
            // Multi-hop guard: structural rejection before any per-hop
            // processing (RFC-AITP-0006 §4).
            return Err(DelegationError::MultihopNotSupported);
        }
        if peeked.jti.is_some() {
            // RFC-AITP-0011 §1.1: `jti` is not part of the single-hop
            // claims set; non-opted-in verifiers reject it under the
            // strict-claims rule.
            return Err(DelegationError::ClaimsMalformed(
                "jti claim requires multi-hop opt-in".into(),
            ));
        }
    }

    if chain_len == 0 {
        verify_single_hop(token, ctx)
    } else {
        verify_multi_hop(token, &peeked, ctx)
    }
}

fn peek_claims(token: &str) -> Result<DelegationClaims, DelegationError> {
    let payload = jws::decode_payload_unverified(token).map_err(DelegationError::Crypto)?;
    serde_json::from_slice(&payload).map_err(|e| DelegationError::ClaimsMalformed(e.to_string()))
}

/// Strictly verify one delegation JWS under its own `iss` and return
/// its claims. A forged `iss` fails the signature check — the claimed
/// issuer's key is the only one tried, and the AID-derived alg pin
/// forecloses algorithm confusion (RFC-AITP-0001 §5.4.5).
fn verify_hop_jws(token: &str) -> Result<DelegationClaims, DelegationError> {
    let claimed = peek_claims(token)?;
    let payload =
        jws::verify_compact(&claimed.iss, jws::TYP_DELEGATION, token).map_err(|e| match e {
            aitp_crypto::CryptoError::SignatureInvalid => DelegationError::InvalidSignature,
            other => DelegationError::Crypto(other),
        })?;
    let claims: DelegationClaims = serde_json::from_slice(&payload)
        .map_err(|e| DelegationError::ClaimsMalformed(e.to_string()))?;
    if claims.ver != PROTOCOL_VERSION {
        return Err(DelegationError::VersionUnknown);
    }
    Ok(claims)
}

/// Common per-hop claim checks (RFC-AITP-0011 §3 step 2; the same
/// invariants hold for the single-hop token).
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
    let voucher = aitp_tct::verify_voucher(voucher_token, ctx.verifier).map_err(|e| match e {
        aitp_tct::TctError::Crypto(c) => DelegationError::Crypto(c),
        aitp_tct::TctError::VersionUnknown => DelegationError::VersionUnknown,
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
    // Step 1: outer JWS — strict parse, typ, alg pin, signature, ver.
    let claims = verify_hop_jws(token)?;
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
    if let Some(check) = ctx.revocation_check {
        if check(&voucher.src_jti) {
            return Err(DelegationError::SourceTctRevoked);
        }
    }

    Ok(VerifiedDelegation {
        token: token.to_string(),
        claims,
        voucher,
    })
}

fn verify_multi_hop(
    token: &str,
    peeked: &DelegationClaims,
    ctx: &VerifyDelegationContext<'_>,
) -> Result<VerifiedDelegation, DelegationError> {
    let chain: Vec<String> = peeked.chain.clone().unwrap_or_default();

    // §2: hop limit, before any signature work.
    let total_hops = chain.len() + 2;
    if total_hops > ctx.max_hops {
        return Err(DelegationError::HopLimitExceeded);
    }

    // §5: chain-hash recomputation, before per-hop verification. (The
    // peeked chain/chain_hash become trusted once the outer signature
    // — which covers both claims — verifies below.)
    let expected_hash = peeked
        .chain_hash
        .as_deref()
        .ok_or(DelegationError::ChainHashMismatch)?;
    if compute_chain_hash(&chain)? != expected_hash {
        return Err(DelegationError::ChainHashMismatch);
    }

    // §3: verify every hop, oldest first; the outer token is last.
    let mut voucher: Option<GrantVoucherClaims> = None;
    let mut prev: Option<DelegationClaims> = None;
    let mut hop_records: Vec<(Aid, Uuid)> = Vec::new();

    let hop_count = chain.len() + 1;
    for (i, hop_token) in chain
        .iter()
        .map(String::as_str)
        .chain(std::iter::once(token))
        .enumerate()
    {
        // Step 1: standard JWS verification (+ ver).
        let hop = verify_hop_jws(hop_token)?;
        // Step 2: common claims + per-hop jti (present, unique).
        check_hop_claims(&hop, ctx)?;
        let jti = hop.jti.ok_or(DelegationError::InvalidVoucher)?;
        if hop_records.iter().any(|(_, seen)| *seen == jti) {
            return Err(DelegationError::InvalidVoucher);
        }
        hop_records.push((hop.iss.clone(), jti));

        if hop.exp.is_in_the_past(ctx.now) {
            return Err(DelegationError::Expired);
        }

        if i == 0 {
            // Step 3: root authority — chain[0] carries the voucher.
            let voucher_token = hop
                .voucher
                .as_deref()
                .ok_or(DelegationError::InvalidVoucher)?;
            let v = verify_root_voucher(voucher_token, &hop.iss, ctx)?;
            if hop.exp.0 > v.exp.0 {
                return Err(DelegationError::Expired);
            }
            // §4: scope rooted in the voucher.
            for cap in &hop.scope {
                if !v.grants.contains(cap) {
                    return Err(DelegationError::ScopeExceeded);
                }
            }
            voucher = Some(v);
        } else {
            let prev_hop = prev.as_ref().expect("set after first iteration");
            // Step 4: continuity — exactly one root of authority.
            if hop.voucher.is_some() {
                return Err(DelegationError::InvalidVoucher);
            }
            if hop.iss != prev_hop.sub {
                return Err(DelegationError::InvalidVoucher);
            }
            // Step 5: expiry monotonically non-increasing.
            if hop.exp.0 > prev_hop.exp.0 {
                return Err(DelegationError::Expired);
            }
            // §4: adjacent-pair scope subsetting.
            for cap in &hop.scope {
                if !prev_hop.scope.contains(cap) {
                    return Err(DelegationError::ScopeExceeded);
                }
            }
        }

        // Step 7 (§1.1): nested-chain prefix consistency for chain
        // entries that were themselves minted as multi-hop tokens.
        if i < hop_count - 1 {
            if let Some(inner_chain) = &hop.chain {
                if inner_chain.as_slice() != &chain[..i] {
                    return Err(DelegationError::InvalidVoucher);
                }
                let inner_hash = hop
                    .chain_hash
                    .as_deref()
                    .ok_or(DelegationError::InvalidVoucher)?;
                if compute_chain_hash(inner_chain)? != inner_hash {
                    return Err(DelegationError::InvalidVoucher);
                }
            }
        }

        prev = Some(hop);
    }

    let voucher = voucher.expect("first hop sets the voucher");
    let outer = prev.expect("loop ran for every hop");

    // §6: per-hop revocation, only after every signature check.
    if let Some(check) = ctx.revocation_check {
        if check(&voucher.src_jti) {
            return Err(DelegationError::SourceTctRevoked);
        }
    }
    if let Some(check) = ctx.hop_revocation_check {
        for (issuer, jti) in &hop_records {
            if check(issuer, jti) {
                return Err(DelegationError::SourceTctRevoked);
            }
        }
    }

    Ok(VerifiedDelegation {
        token: token.to_string(),
        claims: outer,
        voucher,
    })
}
