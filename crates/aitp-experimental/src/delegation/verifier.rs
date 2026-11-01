//! Delegation verification (RFC-AITP-0006 §4 single-hop;
//! RFC-AITP-0011 §2–§6 multi-hop).
//!
//! No step of either algorithm reconstructs any byte sequence: every
//! signature — outer token, every chain entry, the embedded voucher —
//! is verified over bytes exactly as transmitted. (The v0.1
//! `grant_proof` source-TCT reconstruction is gone.)

use crate::delegation::compute_chain_hash;
use crate::delegation::{
    ChainedDelegationClaims, ChainedDelegationError, VerifiedChainedDelegation,
};
use aitp::__private::{
    check_members, delegation_revocation, from_serde_error, reject_duplicate_keys,
};
use aitp::core::{Aid, Timestamp, PROTOCOL_VERSION};
use aitp::crypto::{jws, AitpVerifyingKey};
use aitp::delegation::{DelegationError, DELEGATION_CLAIMS_MEMBERS};
use aitp::manifest::{resolve_verified_manifest, ManifestResolver, ManifestVerifyContext};
use aitp::tct::{
    GrantVoucherClaims, RevocationCheckFn, RevocationQuery, RevocationSource, RevocationUnavailable,
};
use uuid::Uuid;

/// Default `max_delegation_hops` once multi-hop is enabled
/// (RFC-AITP-0011 §2): covers orchestrator → planner → executor.
pub const DEFAULT_MAX_DELEGATION_HOPS: usize = 3;

/// Per-hop revocation lookup (RFC-AITP-0011 §6): queried with the hop
/// issuer and the hop `jti`, resolved against that issuer's deny list.
/// Same contract as a [`RevocationSource::Check`] function.
pub type HopRevocationCheck<'a> = &'a RevocationCheckFn<'a>;

/// Inputs for verifying a delegation token.
///
/// `verifier` is A — the original grantor, voucher issuer, and the only
/// party a delegation is presentable to.
///
/// `#[non_exhaustive]`: construct with [`ChainVerifyContext::new`] and
/// the builder methods rather than a struct literal, so a future
/// verification knob is an additive change instead of a breaking one for
/// every downstream crate.
#[non_exhaustive]
pub struct ChainVerifyContext<'a> {
    /// The verifier's own AID (A). `aud` at every hop and `voucher.iss`
    /// MUST equal this.
    pub verifier: &'a Aid,
    /// Current time.
    pub now: Timestamp,
    /// Hop budget: `total_hops = chain.len() + 2` must not exceed it
    /// (RFC-AITP-0011 §2). [`ChainVerifyContext::new`] sets
    /// [`DEFAULT_MAX_DELEGATION_HOPS`]. `0` means single-hop only: any
    /// token carrying a `chain` claim is rejected with
    /// [`DelegationError::MultihopNotSupported`] and any `jti` with
    /// [`DelegationError::ClaimsMalformed`], as
    /// [`aitp::delegation::verify_delegation`] does.
    pub max_delegation_hops: usize,
    /// Revocation source for the source TCT (`voucher.src_jti`), A's
    /// **own** deny list. The only stateful single-hop check; runs after
    /// all signature checks (RFC-AITP-0008 §3.3).
    pub revocation: RevocationSource<'a>,
    /// Multi-hop per-hop revocation (RFC-AITP-0011 §6): the status of a
    /// hop's `jti` according to the deny list of the hop's issuer
    /// ([`RevocationQuery::issuer`]). Consulted for every chain entry and
    /// the outer token, after all signature checks. Required for
    /// multi-hop chains under [`RevocationSource::Check`].
    pub hop_revocation_check: Option<HopRevocationCheck<'a>>,
    /// Source of each delegation issuer's Manifest (RFC-AITP-0006 §4
    /// step 1; RFC-AITP-0011 §3 step 1). Every delegation JWS — the
    /// single-hop token, and each chain entry plus the outer token of a
    /// multi-hop chain — is verified under the key its issuer's verified
    /// Manifest designates; with no source configured (or no usable
    /// Manifest for an issuer) the token is rejected with
    /// [`DelegationError::KeyResolutionFailed`].
    pub issuer_manifests: Option<&'a dyn ManifestResolver>,
    /// Set by [`Self::with_insecure_localhost_dangerous`].
    insecure_localhost: bool,
}

impl<'a> ChainVerifyContext<'a> {
    /// Context with the given source-TCT revocation choice and a hop
    /// budget of [`DEFAULT_MAX_DELEGATION_HOPS`].
    pub fn new(verifier: &'a Aid, now: Timestamp, revocation: RevocationSource<'a>) -> Self {
        Self {
            verifier,
            now,
            max_delegation_hops: DEFAULT_MAX_DELEGATION_HOPS,
            revocation,
            hop_revocation_check: None,
            issuer_manifests: None,
            insecure_localhost: false,
        }
    }

    /// Set the hop budget. See [`ChainVerifyContext::max_delegation_hops`].
    pub fn with_max_delegation_hops(mut self, max_delegation_hops: usize) -> Self {
        self.max_delegation_hops = max_delegation_hops;
        self
    }

    /// Per-hop revocation for multi-hop chains (RFC-AITP-0011 §6),
    /// queried with each hop's issuer and `jti`.
    pub fn with_hop_revocation_check(mut self, check: HopRevocationCheck<'a>) -> Self {
        self.hop_revocation_check = Some(check);
        self
    }

    /// Where verification gets each delegation issuer's Manifest
    /// (RFC-AITP-0006 §4 step 1; RFC-AITP-0011 §3 step 1). Required for
    /// any delegation — single-hop or multi-hop — to verify.
    pub fn with_issuer_manifests(mut self, resolver: &'a dyn ManifestResolver) -> Self {
        self.issuer_manifests = Some(resolver);
        self
    }

    /// Accept an issuer Manifest whose `handshake_endpoint` is plain
    /// `http://localhost` or `http://127.0.0.1`. Local development only;
    /// see [`aitp::manifest::ManifestVerifyContext::with_insecure_localhost_dangerous`].
    pub fn with_insecure_localhost_dangerous(mut self) -> Self {
        self.insecure_localhost = true;
        self
    }
}

/// Verify a delegation token presented to `ctx.verifier` (A).
///
/// Single-hop (RFC-AITP-0006 §4, in order): outer JWS
/// (typ / alg pin / signature under the key the issuer's verified
/// Manifest designates, from `ctx.issuer_manifests` / `ver`) → `aud` + `exp` → embedded
/// voucher (typ `aitp-grant+jwt`, `voucher.iss` == A, signature under
/// A's **own** key) → `voucher.sub` == outer `iss` → expiry
/// monotonicity → `scope ⊆ voucher.grants` → self-delegation +
/// `cnf.jkt` binding → revocation on `voucher.src_jti` (the only
/// stateful check, last per RFC-AITP-0008 §3.3).
///
/// Multi-hop (RFC-AITP-0011, only when `ctx.max_delegation_hops > 0`): hop limit →
/// chain-hash recomputation → per-hop JWS (signature under the key the
/// issuer's verified Manifest designates, from `ctx.issuer_manifests`) +
/// claims + continuity +
/// expiry monotonicity + transitive scope subsetting + nested-chain
/// prefix consistency → per-hop revocation.
///
/// The downstream PoP exchange (RFC-AITP-0006 §4 step 9) is a separate
/// challenge/response flow run by the caller against the presenting
/// agent, with the bound key taken from the **outer** `sub` AID
/// (`aitp::tct::sign_pop_response` / `verify_pop_response`).
pub fn verify_chained_delegation(
    token: &str,
    ctx: &ChainVerifyContext<'_>,
) -> Result<VerifiedChainedDelegation, ChainedDelegationError> {
    // Peek (unverified) to learn the claimed shape; everything is
    // re-established cryptographically below.
    let peeked = peek_claims(token)?;

    let chain_len = peeked.chain.as_ref().map_or(0, |c| c.len());
    if ctx.max_delegation_hops == 0 {
        if chain_len > 0 || peeked.chain.is_some() {
            // Multi-hop guard: structural rejection before any per-hop
            // processing (RFC-AITP-0006 §4).
            return Err(DelegationError::MultihopNotSupported.into());
        }
        if peeked.jti.is_some() {
            // RFC-AITP-0011 §1.1: `jti` is not part of the single-hop
            // claims set; non-opted-in verifiers reject it under the
            // strict-claims rule.
            return Err(DelegationError::ClaimsMalformed(
                "jti claim requires multi-hop opt-in".into(),
            )
            .into());
        }
    }

    if chain_len == 0 {
        verify_single_hop(token, ctx)
    } else {
        verify_multi_hop(token, &peeked, ctx)
    }
}

fn peek_claims(token: &str) -> Result<ChainedDelegationClaims, ChainedDelegationError> {
    // typ-first gate (RFC-AITP-0006 §4 step 1; D7 / issue #140 follow-up):
    // mirrors `aitp::tct::peek_header_typ`'s pattern via the
    // shared `aitp::__private::peek_typ` helper. Unlike TCT/voucher —
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
    if let Some(typ) = aitp::__private::peek_typ(token) {
        if typ != jws::TYP_DELEGATION {
            return Err(
                DelegationError::Crypto(aitp::crypto::CryptoError::TypMismatch {
                    expected: jws::TYP_DELEGATION.to_string(),
                    got: typ,
                })
                .into(),
            );
        }
    }

    let payload = jws::decode_payload_unverified(token).map_err(DelegationError::Crypto)?;
    // Claim-set check (RFC-AITP-0001 §7 / RFC-AITP-0005 §7.2 step 1) on
    // the still-unverified payload — structurally ahead of AID-pinned
    // `alg` checking and signature verification, same ordering rationale
    // as `aitp::tct::verify_tct`. A reject decision drawn from unverified
    // bytes is sound: no trust is ever extended on the strength of it.
    // A payload that isn't valid JSON at this stage is left for the
    // strict deserialize below to diagnose.
    // RFC-AITP-0001 §5.4.5 / issue #140: the raw-bytes duplicate-key guard
    // must run before the `Value` conversion below, whose map
    // representation is last-write-wins on a duplicate key.
    reject_duplicate_keys(&payload).map_err(DelegationError::ClaimsMalformed)?;
    if let Ok(peek_value) = serde_json::from_slice::<serde_json::Value>(&payload) {
        check_members(
            "ChainedDelegationClaims",
            &peek_value,
            DELEGATION_CLAIMS_MEMBERS,
        )
        .map_err(|e| DelegationError::UnknownField(e.field))?;
        // Hop `jti` layout (RFC-AITP-0011 §1.1 / RFC-AITP-0005 §2), on
        // the raw string: `Uuid`'s deserializer also takes uppercase,
        // braced and URN forms. A non-string is left to serde below.
        if let Some(jti) = peek_value.get("jti").and_then(|v| v.as_str()) {
            aitp::core::ids::parse_v4(jti).map_err(ChainedDelegationError::JtiNotV4)?;
        }
    }
    Ok(serde_json::from_slice(&payload).map_err(|e| {
        if let Some(field) = from_serde_error(&e) {
            DelegationError::UnknownField(field)
        } else {
            DelegationError::ClaimsMalformed(e.to_string())
        }
    })?)
}

/// Strictly verify one delegation JWS under its claimed `iss` and return
/// its claims. The verification key is the one the claimed issuer's
/// verified Manifest designates (RFC-AITP-0006 §4 step 1; RFC-AITP-0011
/// §3 step 1), from `ctx.issuer_manifests`; no source, or no usable
/// Manifest for the issuer, is [`DelegationError::KeyResolutionFailed`].
/// A forged `iss` fails the signature check — only the claimed issuer's
/// key is tried — and the AID-derived alg pin forecloses algorithm
/// confusion (RFC-AITP-0001 §5.4.5).
fn verify_hop_jws(
    token: &str,
    ctx: &ChainVerifyContext<'_>,
) -> Result<ChainedDelegationClaims, ChainedDelegationError> {
    let claimed = peek_claims(token)?;
    let mut manifest_ctx = ManifestVerifyContext::at(ctx.now);
    if ctx.insecure_localhost {
        manifest_ctx = manifest_ctx.with_insecure_localhost_dangerous();
    }
    let signer = ctx
        .issuer_manifests
        .ok_or(aitp::manifest::ManifestError::NotFound)
        .and_then(|r| resolve_verified_manifest(r, &claimed.iss, &manifest_ctx))
        .map_err(|source| DelegationError::KeyResolutionFailed {
            issuer: claimed.iss.clone(),
            source,
        })?
        .aid;
    let payload =
        jws::verify_compact(&signer, jws::TYP_DELEGATION, token).map_err(|e| match e {
            aitp::crypto::CryptoError::SignatureInvalid => DelegationError::InvalidSignature,
            other => DelegationError::Crypto(other),
        })?;
    let claims: ChainedDelegationClaims = serde_json::from_slice(&payload).map_err(|e| {
        if let Some(field) = from_serde_error(&e) {
            DelegationError::UnknownField(field)
        } else {
            DelegationError::ClaimsMalformed(e.to_string())
        }
    })?;
    if claims.ver != PROTOCOL_VERSION {
        return Err(DelegationError::VersionUnknown.into());
    }
    Ok(claims)
}

/// Common per-hop claim checks (RFC-AITP-0011 §3 step 2; the same
/// invariants hold for the single-hop token).
fn check_hop_claims(
    claims: &ChainedDelegationClaims,
    ctx: &ChainVerifyContext<'_>,
) -> Result<(), ChainedDelegationError> {
    if &claims.aud != ctx.verifier {
        return Err(DelegationError::AudienceMismatch.into());
    }
    if claims.iss == claims.sub {
        return Err(DelegationError::SelfDelegation.into());
    }
    if claims.scope.is_empty() {
        return Err(DelegationError::EmptyScope.into());
    }
    // cnf.jkt MUST match the key encoded in `sub` (RFC-AITP-0001 §5.4.4).
    let sub_key = AitpVerifyingKey::from_aid(&claims.sub).map_err(DelegationError::Crypto)?;
    let expected_jkt = sub_key
        .to_jwk_thumbprint_sha256()
        .map_err(DelegationError::Crypto)?;
    if claims.cnf.jkt != expected_jkt {
        return Err(DelegationError::CnfMalformed.into());
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
    ctx: &ChainVerifyContext<'_>,
) -> Result<GrantVoucherClaims, ChainedDelegationError> {
    let voucher = aitp::tct::verify_voucher(voucher_token, ctx.verifier).map_err(|e| match e {
        aitp::tct::TctError::Crypto(c) => DelegationError::Crypto(c),
        aitp::tct::TctError::VersionUnknown => DelegationError::VersionUnknown,
        // RFC-AITP-0001 §7: the embedded voucher's claim-set violation
        // must surface as UNKNOWN_FIELD, not be swallowed into
        // DELEGATION_INVALID_VOUCHER by this catch-all.
        aitp::tct::TctError::UnknownField(f) => DelegationError::UnknownField(f),
        _ => DelegationError::InvalidVoucher,
    })?;
    if &voucher.sub != expected_delegator {
        return Err(DelegationError::InvalidVoucher.into());
    }
    if voucher.exp.is_in_the_past(ctx.now) {
        return Err(DelegationError::Expired.into());
    }
    Ok(voucher)
}

fn verify_single_hop(
    token: &str,
    ctx: &ChainVerifyContext<'_>,
) -> Result<VerifiedChainedDelegation, ChainedDelegationError> {
    // Step 1: outer JWS — strict parse, typ, alg pin, signature under
    // the key B's verified Manifest designates, ver.
    let claims = verify_hop_jws(token, ctx)?;
    // Step 2: addressing and freshness.
    if &claims.aud != ctx.verifier {
        return Err(DelegationError::AudienceMismatch.into());
    }
    if claims.exp.is_in_the_past(ctx.now) {
        return Err(DelegationError::Expired.into());
    }
    // Steps 3–4: embedded voucher.
    let voucher_token = claims
        .voucher
        .as_deref()
        .ok_or(DelegationError::InvalidVoucher)?;
    let voucher = verify_root_voucher(voucher_token, &claims.iss, ctx)?;
    // Step 5 (second half): a delegated grant cannot outlive its source.
    if claims.exp.0 > voucher.exp.0 {
        return Err(DelegationError::Expired.into());
    }
    // Step 6: scope constraint.
    for cap in &claims.scope {
        if !voucher.grants.contains(cap) {
            return Err(DelegationError::ScopeExceeded.into());
        }
    }
    // Step 8 + cnf binding (everything stateless before the lookup).
    check_hop_claims(&claims, ctx)?;
    // Step 7: source-TCT revocation — the only stateful check, last
    // (RFC-AITP-0008 §3.3).
    let effective_grants = check_source_revocation(ctx, &voucher.src_jti, &claims.scope)?;

    Ok(VerifiedChainedDelegation {
        token: token.to_string(),
        claims,
        voucher,
        effective_grants,
    })
}

fn verify_multi_hop(
    token: &str,
    peeked: &ChainedDelegationClaims,
    ctx: &ChainVerifyContext<'_>,
) -> Result<VerifiedChainedDelegation, ChainedDelegationError> {
    let chain: Vec<String> = peeked.chain.clone().unwrap_or_default();

    // §2: hop limit, before any signature work.
    let total_hops = chain.len() + 2;
    if total_hops > ctx.max_delegation_hops {
        return Err(ChainedDelegationError::HopLimitExceeded);
    }

    // §5: chain-hash recomputation, before per-hop verification. (The
    // peeked chain/chain_hash become trusted once the outer signature
    // — which covers both claims — verifies below.)
    let expected_hash = peeked
        .chain_hash
        .as_deref()
        .ok_or(ChainedDelegationError::ChainHashMismatch)?;
    if compute_chain_hash(&chain)? != expected_hash {
        return Err(ChainedDelegationError::ChainHashMismatch);
    }

    // §3: verify every hop, oldest first; the outer token is last.
    let mut voucher: Option<GrantVoucherClaims> = None;
    let mut prev: Option<ChainedDelegationClaims> = None;
    let mut hop_records: Vec<(Aid, Uuid)> = Vec::new();

    let hop_count = chain.len() + 1;
    for (i, hop_token) in chain
        .iter()
        .map(String::as_str)
        .chain(std::iter::once(token))
        .enumerate()
    {
        // Step 1: standard JWS verification (+ ver), under the key the
        // hop issuer's verified Manifest designates.
        let hop = verify_hop_jws(hop_token, ctx)?;
        // Step 2: common claims + per-hop jti (present, unique).
        check_hop_claims(&hop, ctx)?;
        let jti = hop.jti.ok_or(DelegationError::InvalidVoucher)?;
        if hop_records.iter().any(|(_, seen)| *seen == jti) {
            return Err(DelegationError::InvalidVoucher.into());
        }
        hop_records.push((hop.iss.clone(), jti));

        if hop.exp.is_in_the_past(ctx.now) {
            return Err(DelegationError::Expired.into());
        }

        if i == 0 {
            // Step 3: root authority — chain[0] carries the voucher.
            let voucher_token = hop
                .voucher
                .as_deref()
                .ok_or(DelegationError::InvalidVoucher)?;
            let v = verify_root_voucher(voucher_token, &hop.iss, ctx)?;
            if hop.exp.0 > v.exp.0 {
                return Err(DelegationError::Expired.into());
            }
            // §4: scope rooted in the voucher.
            for cap in &hop.scope {
                if !v.grants.contains(cap) {
                    return Err(DelegationError::ScopeExceeded.into());
                }
            }
            voucher = Some(v);
        } else {
            let prev_hop = prev.as_ref().expect("set after first iteration");
            // Step 4: continuity — exactly one root of authority.
            if hop.voucher.is_some() {
                return Err(DelegationError::InvalidVoucher.into());
            }
            if hop.iss != prev_hop.sub {
                return Err(DelegationError::InvalidVoucher.into());
            }
            // Step 5: expiry monotonically non-increasing.
            if hop.exp.0 > prev_hop.exp.0 {
                return Err(DelegationError::Expired.into());
            }
            // §4: adjacent-pair scope subsetting.
            for cap in &hop.scope {
                if !prev_hop.scope.contains(cap) {
                    return Err(DelegationError::ScopeExceeded.into());
                }
            }
        }

        // Step 7 (§1.1): nested-chain prefix consistency for chain
        // entries that were themselves minted as multi-hop tokens.
        if i < hop_count - 1 {
            if let Some(inner_chain) = &hop.chain {
                if inner_chain.as_slice() != &chain[..i] {
                    return Err(DelegationError::InvalidVoucher.into());
                }
                let inner_hash = hop
                    .chain_hash
                    .as_deref()
                    .ok_or(DelegationError::InvalidVoucher)?;
                if compute_chain_hash(inner_chain)? != inner_hash {
                    return Err(DelegationError::InvalidVoucher.into());
                }
            }
        }

        prev = Some(hop);
    }

    let voucher = voucher.expect("first hop sets the voucher");
    let outer = prev.expect("loop ran for every hop");

    // §6: per-hop revocation, only after every signature check.
    let mut effective_grants = check_source_revocation(ctx, &voucher.src_jti, &outer.scope)?;
    if let RevocationSource::Check(_) = ctx.revocation {
        let check = ctx.hop_revocation_check.ok_or_else(|| {
            DelegationError::RevocationUnavailable(RevocationUnavailable::new(
                "no per-hop revocation source configured",
            ))
        })?;
        let hops = RevocationSource::Check(check);
        for (issuer, jti) in &hop_records {
            effective_grants = delegation_revocation(
                &hops,
                &RevocationQuery::new(issuer, jti, ctx.now),
                &effective_grants,
            )?;
        }
    }

    Ok(VerifiedChainedDelegation {
        token: token.to_string(),
        claims: outer,
        voucher,
        effective_grants,
    })
}

/// Source-TCT revocation (RFC-AITP-0008 §3.3), after every signature
/// check: the verifier's own list, keyed by `src_jti`. Returns `scope`,
/// narrowed under a soft-fail safe subset.
fn check_source_revocation(
    ctx: &ChainVerifyContext<'_>,
    src_jti: &Uuid,
    scope: &[String],
) -> Result<Vec<String>, ChainedDelegationError> {
    Ok(delegation_revocation(
        &ctx.revocation,
        &RevocationQuery::new(ctx.verifier, src_jti, ctx.now),
        scope,
    )?)
}
