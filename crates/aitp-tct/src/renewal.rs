//! TCT renewal (RFC-AITP-0013).
//!
//! A holder asks the issuer for a fresh TCT before the existing one
//! expires. The renewal flow does NOT replay the full Mutual Handshake:
//! identity has already been established and is encoded in the existing
//! TCT's `sub` / `cnf`. The holder presents the existing TCT (opaque
//! compact JWS) plus a PoP signature to prove it still controls the
//! subject key.
//!
//! Wire shape of the renewal request:
//!
//! ```json
//! {
//!   "current_tct":   "<compact JWS, typ aitp-tct+jwt>",
//!   "pop_nonce":     "<22-char base64url, fresh>",
//!   "pop_signature": "<sign(holder_key, sha256(decoded(pop_nonce)))>"
//! }
//! ```
//!
//! Successful renewal returns a fresh [`IssuedTct`] with:
//! - new random `jti`
//! - `iat = now`
//! - `exp = min(now + ttl, manifest.expires_at)` — same bound as the
//!   original handshake (RFC-AITP-0004 §4.3)
//! - grants re-evaluated against the issuer's current policy, not copied
//!   (RFC-AITP-0004 §8.1).
//!
//! The issuer re-checks revocation of the presented TCT and records each
//! `pop_nonce` in a [`NonceStore`](aitp_core::nonce_store::NonceStore) so a captured request cannot be
//! replayed (see [`process_renewal_request`]).

use crate::types::{IssuedTct, TctRenewalPayload, TCT_CLAIMS_MEMBERS};
use crate::{verify_tct, TctBuilder, TctError, TctVerifyContext};
use aitp_core::nonce_store::{IssuedNonce, Nonce, NonceStore, NonceStoreError, NONCE_LEN};
use aitp_core::{
    base64url, check_members, from_serde_error, reject_duplicate_keys, Aid, Timestamp,
};
use aitp_crypto::{AitpSigner, AitpVerifyingKey, CryptoError, Signature};
use uuid::Uuid;

/// Build a [`TctRenewalPayload`] on the holder side.
///
/// The holder signs over `sha256(base64url_decode(pop_nonce))` with
/// its long-term key — same construction as the handshake's PoP.
///
/// Accepts any [`AitpSigner`] (in-process key, KMS, HSM); a backend
/// failure returns `TctError::Crypto(CryptoError::Signer(_))`.
pub fn build_renewal_request(
    holder_key: &dyn AitpSigner,
    current_tct: String,
    pop_nonce: String,
) -> Result<TctRenewalPayload, TctError> {
    let nonce_bytes = base64url::decode_strict(&pop_nonce)
        .map_err(|e| TctError::ClaimsMalformed(format!("pop_nonce: {e}")))?;
    let digest = aitp_crypto::Digest32::sha256(&nonce_bytes);
    let pop_signature = aitp_crypto::sign_jcs(holder_key, &digest)
        .map_err(CryptoError::Signer)?
        .into_string();
    Ok(TctRenewalPayload {
        current_tct,
        pop_nonce,
        pop_signature,
    })
}

/// Issuer grant-policy hook re-run at renewal: given the holder AID and
/// the grants that survive the Manifest re-intersection, return the
/// grants to issue. The renewal counterpart of the handshake's grant
/// policy, keyed by AID because a renewal request carries no identity
/// descriptor.
pub type RenewalGrantPolicyFn = dyn Fn(&Aid, &[String]) -> Vec<String> + Send + Sync;

/// The issuer's current state, re-evaluated on every renewal
/// (RFC-AITP-0004 §8.1: renewal is not a bypass for revocation, Manifest
/// rotation or grant policy).
///
/// Every input that decides whether a renewal is safe is a required
/// argument of [`RenewalContext::new`]; there is no permissive default.
#[non_exhaustive]
pub struct RenewalContext<'a> {
    /// `expires_at` of the issuer's current Manifest. Caps both the
    /// presented TCT (RFC-AITP-0005 §9) and the renewed one
    /// (RFC-AITP-0004 §4.3).
    pub manifest_expires_at: Timestamp,
    /// The issuer Manifest's current `offered_capabilities`. The renewed
    /// grants are the presented TCT's grants intersected with these, so
    /// a capability the issuer has withdrawn does not carry over.
    pub offered_grants: &'a [String],
    /// Revocation lookup over the issuer's own deny list (`true` means
    /// revoked). A revoked TCT is refused with [`TctError::Revoked`].
    pub revocation_check: &'a (dyn Fn(&Uuid) -> bool + Send + Sync),
    /// Replay guard: every accepted `pop_nonce` is recorded here until
    /// the presented TCT's `exp`, and a nonce already present is refused
    /// with [`TctError::RenewalReplayed`]. Share one store across
    /// replicas, or the guard holds per replica only.
    pub nonce_store: &'a dyn NonceStore,
    /// Optional grant-policy hook, applied after the Manifest
    /// intersection. `None` keeps the intersection.
    pub grant_policy: Option<&'a RenewalGrantPolicyFn>,
    /// Requested lifetime of the renewed TCT, capped by
    /// [`Self::manifest_expires_at`]. Default
    /// [`crate::DEFAULT_TCT_TTL_SECS`].
    pub ttl_secs: i64,
    /// Whether to mint a fresh companion grant voucher (re-minted "per
    /// issuer policy", RFC-AITP-0004 §8.1). Default `true`.
    pub mint_voucher: bool,
    /// Verification clock.
    pub now: Timestamp,
}

impl<'a> RenewalContext<'a> {
    /// A context with every safety decision supplied, the default TTL,
    /// no extra grant policy, and voucher re-minting on.
    pub fn new(
        manifest_expires_at: Timestamp,
        offered_grants: &'a [String],
        revocation_check: &'a (dyn Fn(&Uuid) -> bool + Send + Sync),
        nonce_store: &'a dyn NonceStore,
        now: Timestamp,
    ) -> Self {
        Self {
            manifest_expires_at,
            offered_grants,
            revocation_check,
            nonce_store,
            grant_policy: None,
            ttl_secs: crate::DEFAULT_TCT_TTL_SECS,
            mint_voucher: true,
            now,
        }
    }

    /// Set the requested TTL (still capped by the Manifest window).
    pub fn ttl_secs(mut self, ttl_secs: i64) -> Self {
        self.ttl_secs = ttl_secs;
        self
    }

    /// Install a grant-policy hook.
    pub fn grant_policy(mut self, policy: &'a RenewalGrantPolicyFn) -> Self {
        self.grant_policy = Some(policy);
        self
    }

    /// Do not re-mint the companion grant voucher.
    pub fn without_voucher(mut self) -> Self {
        self.mint_voucher = false;
        self
    }
}

/// Issuer-side: verify a renewal request and mint a fresh TCT.
///
/// Checks performed (in order):
///
/// 1. `pop_nonce` is 22 unpadded base64url characters decoding to 16
///    bytes (RFC-AITP-0004 §8.1) → else
///    [`TctError::RenewalNonceMalformed`].
/// 2. `current_tct` verifies under the issuer's own AID with the full
///    RFC-AITP-0005 §7.2 verification — typ, alg pin, signature, claims,
///    `exp > now` ([`TctError::Expired`]), the issuer Manifest cap
///    ([`TctError::ExpiresAfterManifest`]) and the issuer's revocation
///    list ([`TctError::Revoked`]).
/// 3. `pop_signature` verifies under the key encoded in the TCT's `sub`
///    AID (proves the request comes from the holder the TCT is bound to)
///    → else [`TctError::PopFailed`].
/// 4. The issuer's Manifest is still in its valid window (the holder
///    cannot renew across an issuer key-rotation boundary) → else
///    [`TctError::Expired`].
/// 5. `pop_nonce` is recorded in [`RenewalContext::nonce_store`] until
///    the presented TCT's `exp`; a nonce already recorded is a replay →
///    [`TctError::RenewalReplayed`]. Only a request whose PoP verified
///    reaches the store, so an observer cannot burn a holder's nonce or
///    fill the store with garbage. A store failure is
///    [`TctError::RenewalNonceStore`].
/// 6. Grants are re-evaluated: the presented grants ∩ the Manifest's
///    current `offered_capabilities`, then the optional grant policy.
///    None left → [`TctError::RenewalGrantsWithdrawn`].
///
/// Returns a fresh [`IssuedTct`] with the re-evaluated grants, the same
/// subject / audience / key binding, a new `jti`, and `exp` bounded by
/// the Manifest. Vouchers bound to the old `jti` do not carry over.
///
/// Accepts any [`AitpSigner`] (in-process key, KMS, HSM); a backend
/// failure returns `TctError::Crypto(CryptoError::Signer(_))`.
pub async fn process_renewal_request(
    request: &TctRenewalPayload,
    issuer_key: &dyn AitpSigner,
    ctx: &RenewalContext<'_>,
) -> Result<IssuedTct, TctError> {
    let now = ctx.now;
    let nonce = decode_renewal_nonce(&request.pop_nonce)?;
    let issuer_aid = issuer_key.aid();

    let claims = {
        // Decode unverified only to learn which holder this claims to be
        // for; every field is re-checked by verify_tct + PoP below. The
        // claim-set check applies here too (RFC-AITP-0005 §7.2's
        // strict-parse step is unconditional on verification state) so an
        // unknown claim on a still-unverified token is rejected before it
        // is used for anything, including this audience peek. Gated on the
        // peeked `typ` matching, same as `verify_tct` / `verify_voucher`
        // (tct-010's ordering: typ-confusion is diagnosed by
        // `verify_tct`'s own authoritative check below, not misreported as
        // an unrelated unknown claim here).
        let peek = aitp_crypto::jws::decode_payload_unverified(&request.current_tct)
            .map_err(TctError::Crypto)?;
        // RFC-AITP-0001 §5.4.5 / issue #140: run the raw-bytes duplicate-key
        // guard on `peek` BEFORE the `Value` conversion below, which would
        // otherwise silently collapse a duplicate key to its last occurrence.
        reject_duplicate_keys(&peek).map_err(TctError::ClaimsMalformed)?;
        let peek_value: serde_json::Value =
            serde_json::from_slice(&peek).map_err(|e| TctError::ClaimsMalformed(e.to_string()))?;
        if crate::verifier::peek_header_typ(&request.current_tct).as_deref()
            == Some(aitp_crypto::jws::TYP_TCT)
        {
            check_members("TctClaims", &peek_value, TCT_CLAIMS_MEMBERS)
                .map_err(|e| TctError::UnknownField(e.field))?;
        }
        let peek_claims: crate::types::TctClaims =
            serde_json::from_value(peek_value).map_err(|e| {
                if let Some(field) = from_serde_error(&e) {
                    TctError::UnknownField(field)
                } else {
                    TctError::ClaimsMalformed(e.to_string())
                }
            })?;

        // RFC-AITP-0004 §8.1: renewal is not a bypass for revocation or
        // Manifest rotation, so the presented TCT gets the full check.
        let verify_ctx = TctVerifyContext::builder(&peek_claims.aud, issuer_aid, now)
            .revocation_check(ctx.revocation_check)
            .issuer_manifest_expires_at(ctx.manifest_expires_at)
            .build()
            .expect("both decisions are made");
        verify_tct(&request.current_tct, &verify_ctx)?.claims
    };

    // PoP: the holder key is the one the sub AID encodes (verify_tct
    // already cross-checked cnf.jkt against it).
    let holder_pk = AitpVerifyingKey::from_aid(&claims.sub).map_err(TctError::Crypto)?;
    let digest = aitp_crypto::Digest32::sha256(&nonce);
    let sig = Signature::parse(&request.pop_signature).map_err(|_| TctError::PopFailed)?;
    holder_pk
        .verify_jcs(&digest, &sig)
        .map_err(|_| TctError::PopFailed)?;

    if ctx.manifest_expires_at.0 <= now.0 {
        return Err(TctError::Expired);
    }
    let effective_ttl = ctx.ttl_secs.min(ctx.manifest_expires_at.0 - now.0);
    if effective_ttl <= 0 {
        return Err(TctError::Expired);
    }

    // Replay guard. The record lives until the presented TCT expires:
    // after that the TCT cannot be renewed anyway, so the nonce can go.
    let record = IssuedNonce::new(
        nonce,
        issuer_aid.clone(),
        claims.sub.as_str(),
        now,
        claims.exp,
    );
    match ctx.nonce_store.issue(&record).await {
        Ok(()) => {}
        Err(NonceStoreError::Duplicate) => return Err(TctError::RenewalReplayed),
        Err(e) => return Err(TctError::RenewalNonceStore(e)),
    }

    let mut grants: Vec<String> = claims
        .grants
        .iter()
        .filter(|g| ctx.offered_grants.contains(g))
        .cloned()
        .collect();
    if let Some(policy) = ctx.grant_policy {
        grants = policy(&claims.sub, &grants);
    }
    if grants.is_empty() {
        return Err(TctError::RenewalGrantsWithdrawn);
    }

    let mut builder = TctBuilder::new(issuer_key)
        .subject(claims.sub.clone())
        .audience(claims.aud.clone())
        .grants(grants)
        .ttl_secs(effective_ttl)
        .subject_pubkey(holder_pk)
        .issued_at(now)
        .jti(Uuid::new_v4());
    if !ctx.mint_voucher {
        builder = builder.without_voucher();
    }
    builder.build()
}

/// Strict `pop_nonce` decode: 22 unpadded base64url characters, 16 bytes.
fn decode_renewal_nonce(pop_nonce: &str) -> Result<Nonce, TctError> {
    let bytes = base64url::decode_strict(pop_nonce)
        .map_err(|e| TctError::RenewalNonceMalformed(e.to_string()))?;
    bytes.try_into().map_err(|b: Vec<u8>| {
        TctError::RenewalNonceMalformed(format!(
            "must decode to exactly {NONCE_LEN} bytes, got {}",
            b.len()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aitp_core::nonce_store::InMemoryNonceStore;
    use aitp_crypto::AitpSigningKey;

    const GRANTS: &[&str] = &["demo.echo", "demo.write"];

    fn offered() -> Vec<String> {
        GRANTS.iter().map(|s| s.to_string()).collect()
    }

    fn not_revoked(_: &Uuid) -> bool {
        false
    }

    fn issue(
        issuer: &AitpSigningKey,
        holder: &AitpSigningKey,
        now: Timestamp,
        ttl: i64,
    ) -> IssuedTct {
        TctBuilder::new(issuer)
            .subject(holder.aid().clone())
            .audience(holder.aid().clone())
            .grants(GRANTS.iter().copied())
            .ttl_secs(ttl)
            .subject_pubkey(holder.verifying_key())
            .issued_at(now)
            .build()
            .unwrap()
    }

    /// Run `process_renewal_request` with a fresh store and the given
    /// Manifest expiry, no revocation, every grant still offered.
    async fn renew(
        request: &TctRenewalPayload,
        issuer: &AitpSigningKey,
        manifest_exp: Timestamp,
        now: Timestamp,
        ttl: i64,
    ) -> Result<IssuedTct, TctError> {
        let store = InMemoryNonceStore::new(16);
        let offered = offered();
        let ctx =
            RenewalContext::new(manifest_exp, &offered, &not_revoked, &store, now).ttl_secs(ttl);
        process_renewal_request(request, issuer, &ctx).await
    }

    #[tokio::test]
    async fn round_trip_renewal_succeeds() {
        let issuer = AitpSigningKey::from_seed(&[0x01; 32]);
        let holder = AitpSigningKey::from_seed(&[0x02; 32]);
        let now = Timestamp(1_700_000_000);
        let manifest_exp = Timestamp(now.0 + 86_400);

        let original = issue(&issuer, &holder, now, 60);
        let request = build_renewal_request(
            &holder,
            original.token.clone(),
            base64url::encode(&[0x33; 16]),
        )
        .unwrap();

        let renewed = renew(&request, &issuer, manifest_exp, now, 3600)
            .await
            .unwrap();
        assert_ne!(renewed.claims.jti, original.claims.jti);
        assert_eq!(renewed.claims.sub, original.claims.sub);
        assert_eq!(renewed.claims.grants, original.claims.grants);
        assert_eq!(renewed.claims.exp.0, now.0 + 3600);
        assert!(renewed.voucher.is_some(), "renewal mints a fresh voucher");
    }

    #[tokio::test]
    async fn renewal_with_wrong_holder_key_rejected() {
        let issuer = AitpSigningKey::from_seed(&[0x10; 32]);
        let holder = AitpSigningKey::from_seed(&[0x11; 32]);
        let attacker = AitpSigningKey::from_seed(&[0x12; 32]);
        let now = Timestamp(1_700_000_000);
        let original = issue(&issuer, &holder, now, 60);
        let request = build_renewal_request(
            &attacker, // attacker signs with its own key
            original.token,
            base64url::encode(&[0x44; 16]),
        )
        .unwrap();
        let err = renew(&request, &issuer, Timestamp(now.0 + 86_400), now, 3600)
            .await
            .unwrap_err();
        assert!(matches!(err, TctError::PopFailed), "got {err:?}");
    }

    #[tokio::test]
    async fn renewal_bounded_by_manifest_expiry() {
        let issuer = AitpSigningKey::from_seed(&[0x20; 32]);
        let holder = AitpSigningKey::from_seed(&[0x21; 32]);
        let now = Timestamp(1_700_000_000);
        let manifest_exp = Timestamp(now.0 + 600); // 10 min left
        let original = issue(&issuer, &holder, now, 60);
        let request =
            build_renewal_request(&holder, original.token, base64url::encode(&[0x55; 16])).unwrap();
        // Caller asks for 1 hour TTL, manifest only allows 10 min.
        let renewed = renew(&request, &issuer, manifest_exp, now, 3600)
            .await
            .unwrap();
        assert_eq!(
            renewed.claims.exp.0, manifest_exp.0,
            "TTL must be capped by manifest expiry"
        );
    }

    #[tokio::test]
    async fn renewal_after_manifest_expired_rejected() {
        let issuer = AitpSigningKey::from_seed(&[0x30; 32]);
        let holder = AitpSigningKey::from_seed(&[0x31; 32]);
        let now = Timestamp(1_700_000_000);
        let original = issue(&issuer, &holder, now, 60);
        let request =
            build_renewal_request(&holder, original.token, base64url::encode(&[0x66; 16])).unwrap();
        // Manifest already expired: the presented TCT now outlives it.
        let err = renew(&request, &issuer, Timestamp(now.0 - 1), now, 3600)
            .await
            .unwrap_err();
        assert!(
            matches!(err, TctError::ExpiresAfterManifest | TctError::Expired),
            "got {err:?}"
        );
    }

    /// RFC-AITP-0004 §8.1: renewal is not a bypass for Manifest rotation.
    /// A TCT whose `exp` exceeds the issuer's current Manifest is refused,
    /// where the old `skip_manifest_expiry_cap_dangerous` waiver let it in.
    #[tokio::test]
    async fn renewal_of_tct_outliving_rotated_manifest_rejected() {
        let issuer = AitpSigningKey::from_seed(&[0x32; 32]);
        let holder = AitpSigningKey::from_seed(&[0x33; 32]);
        let now = Timestamp(1_700_000_000);
        let original = issue(&issuer, &holder, now, 3600);
        let request =
            build_renewal_request(&holder, original.token, base64url::encode(&[0x67; 16])).unwrap();
        let err = renew(&request, &issuer, Timestamp(now.0 + 600), now, 3600)
            .await
            .unwrap_err();
        assert!(matches!(err, TctError::ExpiresAfterManifest), "got {err:?}");
    }

    #[tokio::test]
    async fn renewal_of_expired_tct_rejected() {
        let issuer = AitpSigningKey::from_seed(&[0x34; 32]);
        let holder = AitpSigningKey::from_seed(&[0x35; 32]);
        let now = Timestamp(1_700_000_000);
        let original = issue(&issuer, &holder, now, 60);
        let request =
            build_renewal_request(&holder, original.token, base64url::encode(&[0x68; 16])).unwrap();
        let later = Timestamp(now.0 + 3600);
        let err = renew(&request, &issuer, Timestamp(now.0 + 86_400), later, 3600)
            .await
            .unwrap_err();
        assert!(matches!(err, TctError::Expired), "got {err:?}");
    }

    #[tokio::test]
    async fn renewal_of_foreign_issuer_token_rejected() {
        let issuer = AitpSigningKey::from_seed(&[0x40; 32]);
        let other_issuer = AitpSigningKey::from_seed(&[0x41; 32]);
        let holder = AitpSigningKey::from_seed(&[0x42; 32]);
        let now = Timestamp(1_700_000_000);
        let foreign = issue(&other_issuer, &holder, now, 60);
        let request =
            build_renewal_request(&holder, foreign.token, base64url::encode(&[0x77; 16])).unwrap();
        // `issuer` cannot renew a TCT signed by `other_issuer`.
        assert!(
            renew(&request, &issuer, Timestamp(now.0 + 86_400), now, 3600)
                .await
                .is_err()
        );
    }

    /// RFC-AITP-0001 §5.4.5 / issue #140: a `current_tct` whose (unverified)
    /// payload carries a duplicate top-level key must be rejected with
    /// `ClaimsMalformed`, not silently accepted with the key's last
    /// occurrence winning. Deliberately raw-text tampering of an
    /// otherwise-validly-signed token's payload segment — a defect no
    /// `serde_json::Value` can even represent.
    #[tokio::test]
    async fn renewal_of_token_with_duplicate_claim_is_rejected() {
        let issuer = AitpSigningKey::from_seed(&[0x50; 32]);
        let holder = AitpSigningKey::from_seed(&[0x51; 32]);
        let now = Timestamp(1_700_000_000);
        let original = issue(&issuer, &holder, now, 60);

        let parts: Vec<&str> = original.token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let payload_bytes = base64url::decode_strict(parts[1]).unwrap();
        let payload_str = std::str::from_utf8(&payload_bytes).unwrap();
        assert!(payload_str.starts_with('{'));
        let dup_payload = format!("{{\"ver\":\"aitp/0.2\",{}", &payload_str[1..]);
        let dup_token = format!(
            "{}.{}.{}",
            parts[0],
            base64url::encode(dup_payload.as_bytes()),
            parts[2]
        );

        let request =
            build_renewal_request(&holder, dup_token, base64url::encode(&[0x88; 16])).unwrap();
        let err = renew(&request, &issuer, Timestamp(now.0 + 86_400), now, 3600)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, TctError::ClaimsMalformed(m) if m.contains("duplicate field `ver`")),
            "got {err:?}"
        );
    }

    /// #196: the same signed request presented twice mints only once.
    #[tokio::test]
    async fn replayed_pop_nonce_rejected() {
        let issuer = AitpSigningKey::from_seed(&[0x60; 32]);
        let holder = AitpSigningKey::from_seed(&[0x61; 32]);
        let now = Timestamp(1_700_000_000);
        let original = issue(&issuer, &holder, now, 600);
        let request =
            build_renewal_request(&holder, original.token, base64url::encode(&[0x99; 16])).unwrap();
        let store = InMemoryNonceStore::new(16);
        let offered = offered();
        let ctx = RenewalContext::new(
            Timestamp(now.0 + 86_400),
            &offered,
            &not_revoked,
            &store,
            now,
        );
        process_renewal_request(&request, &issuer, &ctx)
            .await
            .expect("first presentation renews");
        let err = process_renewal_request(&request, &issuer, &ctx)
            .await
            .unwrap_err();
        assert!(matches!(err, TctError::RenewalReplayed), "got {err:?}");
        assert_eq!(store.len(), 1);
    }

    /// A request whose PoP fails never reaches the store, so it cannot
    /// burn the holder's nonce.
    #[tokio::test]
    async fn failed_pop_does_not_record_nonce() {
        let issuer = AitpSigningKey::from_seed(&[0x62; 32]);
        let holder = AitpSigningKey::from_seed(&[0x63; 32]);
        let attacker = AitpSigningKey::from_seed(&[0x64; 32]);
        let now = Timestamp(1_700_000_000);
        let original = issue(&issuer, &holder, now, 600);
        let nonce = base64url::encode(&[0x9a; 16]);
        let forged =
            build_renewal_request(&attacker, original.token.clone(), nonce.clone()).unwrap();
        let store = InMemoryNonceStore::new(16);
        let offered = offered();
        let ctx = RenewalContext::new(
            Timestamp(now.0 + 86_400),
            &offered,
            &not_revoked,
            &store,
            now,
        );
        let err = process_renewal_request(&forged, &issuer, &ctx)
            .await
            .unwrap_err();
        assert!(matches!(err, TctError::PopFailed), "got {err:?}");
        assert!(store.is_empty());
        let genuine = build_renewal_request(&holder, original.token, nonce).unwrap();
        process_renewal_request(&genuine, &issuer, &ctx)
            .await
            .expect("holder's nonce is still usable");
    }

    #[tokio::test]
    async fn pop_nonce_of_wrong_length_rejected() {
        let issuer = AitpSigningKey::from_seed(&[0x65; 32]);
        let holder = AitpSigningKey::from_seed(&[0x66; 32]);
        let now = Timestamp(1_700_000_000);
        let original = issue(&issuer, &holder, now, 600);
        for len in [0usize, 8, 15, 17, 32] {
            let request = build_renewal_request(
                &holder,
                original.token.clone(),
                base64url::encode(&vec![1; len]),
            )
            .unwrap();
            let err = renew(&request, &issuer, Timestamp(now.0 + 86_400), now, 3600)
                .await
                .unwrap_err();
            assert!(
                matches!(err, TctError::RenewalNonceMalformed(_)),
                "len {len}: got {err:?}"
            );
        }
        // Not base64url at all.
        let mut request =
            build_renewal_request(&holder, original.token, base64url::encode(&[1; 16])).unwrap();
        request.pop_nonce = "not base64url!".into();
        let err = renew(&request, &issuer, Timestamp(now.0 + 86_400), now, 3600)
            .await
            .unwrap_err();
        assert!(
            matches!(err, TctError::RenewalNonceMalformed(_)),
            "got {err:?}"
        );
    }

    /// #196: the old `accept_unchecked_revocation_dangerous` waiver let a
    /// revoked-but-unexpired TCT renew. It must not.
    #[tokio::test]
    async fn renewal_of_revoked_tct_rejected() {
        let issuer = AitpSigningKey::from_seed(&[0x70; 32]);
        let holder = AitpSigningKey::from_seed(&[0x71; 32]);
        let now = Timestamp(1_700_000_000);
        let original = issue(&issuer, &holder, now, 600);
        let revoked_jti = original.claims.jti;
        let revoked = move |j: &Uuid| *j == revoked_jti;
        let request =
            build_renewal_request(&holder, original.token, base64url::encode(&[0xaa; 16])).unwrap();
        let store = InMemoryNonceStore::new(16);
        let offered = offered();
        let ctx = RenewalContext::new(Timestamp(now.0 + 86_400), &offered, &revoked, &store, now);
        let err = process_renewal_request(&request, &issuer, &ctx)
            .await
            .unwrap_err();
        assert!(matches!(err, TctError::Revoked), "got {err:?}");
        assert!(store.is_empty(), "a refused request records no nonce");
    }

    /// A grant the issuer's Manifest no longer offers is dropped.
    #[tokio::test]
    async fn withdrawn_grant_is_dropped() {
        let issuer = AitpSigningKey::from_seed(&[0x72; 32]);
        let holder = AitpSigningKey::from_seed(&[0x73; 32]);
        let now = Timestamp(1_700_000_000);
        let original = issue(&issuer, &holder, now, 600);
        let request =
            build_renewal_request(&holder, original.token, base64url::encode(&[0xab; 16])).unwrap();
        let store = InMemoryNonceStore::new(16);
        let offered = vec!["demo.echo".to_string()];
        let ctx = RenewalContext::new(
            Timestamp(now.0 + 86_400),
            &offered,
            &not_revoked,
            &store,
            now,
        );
        let renewed = process_renewal_request(&request, &issuer, &ctx)
            .await
            .unwrap();
        assert_eq!(renewed.claims.grants, vec!["demo.echo".to_string()]);
    }

    /// Every grant withdrawn (by the Manifest or by policy): refused.
    #[tokio::test]
    async fn all_grants_withdrawn_refused() {
        let issuer = AitpSigningKey::from_seed(&[0x74; 32]);
        let holder = AitpSigningKey::from_seed(&[0x75; 32]);
        let now = Timestamp(1_700_000_000);
        let original = issue(&issuer, &holder, now, 600);
        let store = InMemoryNonceStore::new(16);
        let manifest_exp = Timestamp(now.0 + 86_400);

        let request = build_renewal_request(
            &holder,
            original.token.clone(),
            base64url::encode(&[0xac; 16]),
        )
        .unwrap();
        let none_offered: Vec<String> = vec!["other.cap".into()];
        let ctx = RenewalContext::new(manifest_exp, &none_offered, &not_revoked, &store, now);
        let err = process_renewal_request(&request, &issuer, &ctx)
            .await
            .unwrap_err();
        assert!(
            matches!(err, TctError::RenewalGrantsWithdrawn),
            "got {err:?}"
        );

        let request =
            build_renewal_request(&holder, original.token, base64url::encode(&[0xad; 16])).unwrap();
        let offered = offered();
        let deny_all = |_: &Aid, _: &[String]| Vec::new();
        let ctx = RenewalContext::new(manifest_exp, &offered, &not_revoked, &store, now)
            .grant_policy(&deny_all);
        let err = process_renewal_request(&request, &issuer, &ctx)
            .await
            .unwrap_err();
        assert!(
            matches!(err, TctError::RenewalGrantsWithdrawn),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn grant_policy_narrows_and_voucher_is_optional() {
        let issuer = AitpSigningKey::from_seed(&[0x76; 32]);
        let holder = AitpSigningKey::from_seed(&[0x77; 32]);
        let now = Timestamp(1_700_000_000);
        let original = issue(&issuer, &holder, now, 600);
        let request =
            build_renewal_request(&holder, original.token, base64url::encode(&[0xae; 16])).unwrap();
        let store = InMemoryNonceStore::new(16);
        let offered = offered();
        let policy = |_: &Aid, g: &[String]| {
            g.iter()
                .filter(|c| c.as_str() == "demo.write")
                .cloned()
                .collect()
        };
        let ctx = RenewalContext::new(
            Timestamp(now.0 + 86_400),
            &offered,
            &not_revoked,
            &store,
            now,
        )
        .grant_policy(&policy)
        .without_voucher();
        let renewed = process_renewal_request(&request, &issuer, &ctx)
            .await
            .unwrap();
        assert_eq!(renewed.claims.grants, vec!["demo.write".to_string()]);
        assert!(renewed.voucher.is_none());
    }

    #[tokio::test]
    async fn nonce_store_at_capacity_is_a_local_error() {
        let issuer = AitpSigningKey::from_seed(&[0x78; 32]);
        let holder = AitpSigningKey::from_seed(&[0x79; 32]);
        let now = Timestamp(1_700_000_000);
        let original = issue(&issuer, &holder, now, 600);
        let store = InMemoryNonceStore::new(1);
        let offered = offered();
        let ctx = RenewalContext::new(
            Timestamp(now.0 + 86_400),
            &offered,
            &not_revoked,
            &store,
            now,
        );
        let first = build_renewal_request(
            &holder,
            original.token.clone(),
            base64url::encode(&[0xb0; 16]),
        )
        .unwrap();
        process_renewal_request(&first, &issuer, &ctx)
            .await
            .unwrap();
        let second =
            build_renewal_request(&holder, original.token, base64url::encode(&[0xb1; 16])).unwrap();
        let err = process_renewal_request(&second, &issuer, &ctx)
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                TctError::RenewalNonceStore(NonceStoreError::AtCapacity { .. })
            ),
            "got {err:?}"
        );
    }

    /// The renewal future is `Send`, so a multi-threaded server can await it.
    #[test]
    fn renewal_future_is_send() {
        fn assert_send<T: Send>(_: &T) {}
        let issuer = AitpSigningKey::from_seed(&[0x7a; 32]);
        let store = InMemoryNonceStore::new(1);
        let offered = offered();
        let ctx = RenewalContext::new(Timestamp(1), &offered, &not_revoked, &store, Timestamp(0));
        let req = TctRenewalPayload {
            current_tct: String::new(),
            pop_nonce: String::new(),
            pop_signature: String::new(),
        };
        let fut = process_renewal_request(&req, &issuer, &ctx);
        assert_send(&fut);
    }
}
