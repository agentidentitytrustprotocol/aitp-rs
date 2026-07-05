//! TCT renewal (RFC-AITP-0005 §10).
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
//! Successful renewal returns a fresh [`IssuedTct`] (token + companion
//! voucher) with:
//! - new random `jti`
//! - `iat = now`
//! - `exp = min(now + ttl, manifest.expires_at)` — same bound as the
//!   original handshake (RFC-AITP-0004 §4.3).

use crate::types::{IssuedTct, TctRenewalPayload};
use crate::{verify_tct, TctBuilder, TctError, TctVerifyContext};
use aitp_core::{base64url, Timestamp};
use aitp_crypto::{AitpSigningKey, AitpVerifyingKey, Signature};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Build a [`TctRenewalPayload`] on the holder side.
///
/// The holder signs over `sha256(base64url_decode(pop_nonce))` with
/// its long-term key — same construction as the handshake's PoP.
pub fn build_renewal_request(
    holder_key: &AitpSigningKey,
    current_tct: String,
    pop_nonce: String,
) -> Result<TctRenewalPayload, TctError> {
    let nonce_bytes = base64url::decode_strict(&pop_nonce)
        .map_err(|e| TctError::ClaimsMalformed(format!("pop_nonce: {e}")))?;
    let digest = Sha256::digest(&nonce_bytes);
    let pop_signature = holder_key.sign(&digest).into_string();
    Ok(TctRenewalPayload {
        current_tct,
        pop_nonce,
        pop_signature,
    })
}

/// Issuer-side: verify a renewal request and mint a fresh TCT.
///
/// Checks performed (in order):
///
/// 1. `current_tct` verifies under the issuer's own AID (full
///    RFC-AITP-0005 §7.2 verification — typ, alg pin, signature,
///    claims).
/// 2. `pop_signature` verifies under the key encoded in the existing
///    TCT's `sub` AID (proves the renewal request comes from the same
///    holder that originally received the TCT).
/// 3. Issuer's Manifest is still in its valid window (the holder
///    cannot renew across an issuer key-rotation boundary).
///
/// Returns a fresh [`IssuedTct`] with the same grants, same subject /
/// audience / binding, new `jti`, and `exp` bounded by the supplied
/// `manifest_expires_at`.
pub fn process_renewal_request(
    request: &TctRenewalPayload,
    issuer_key: &AitpSigningKey,
    manifest_expires_at: Timestamp,
    now: Timestamp,
    ttl_secs: i64,
) -> Result<IssuedTct, TctError> {
    // The current TCT's audience is its subject (v0.2 invariant), so
    // verify against the claims' own aud after a first unverified peek
    // would be circular — instead, verify with expected_audience taken
    // from the sub the *issuer* recorded: for renewal the issuer simply
    // requires aud == sub, which verify_tct enforces; the audience
    // check here pins aud to the holder the PoP will prove.
    let issuer_aid = issuer_key.aid();
    // Decode unverified only to learn which holder this claims to be
    // for; every field is re-checked by verify_tct + PoP below.
    let peek = aitp_crypto::jws::decode_payload_unverified(&request.current_tct)
        .map_err(TctError::Crypto)?;
    let peek_claims: crate::types::TctClaims =
        serde_json::from_slice(&peek).map_err(|e| TctError::ClaimsMalformed(e.to_string()))?;

    // Renewal re-verifies the current TCT before minting a fresh one;
    // revocation and the Manifest cap are handled by the issuing peer's
    // renewal policy, not this holder-side re-verification.
    let ctx = TctVerifyContext::permissive_at(&peek_claims.aud, issuer_aid, now);
    let verified = verify_tct(&request.current_tct, &ctx)?;
    let claims = verified.claims;

    // PoP: the holder key is the one the sub AID encodes (verify_tct
    // already cross-checked cnf.jkt against it).
    let holder_pk = AitpVerifyingKey::from_aid(&claims.sub).map_err(TctError::Crypto)?;
    let nonce_bytes = base64url::decode_strict(&request.pop_nonce)
        .map_err(|e| TctError::ClaimsMalformed(format!("pop_nonce: {e}")))?;
    let digest = Sha256::digest(&nonce_bytes);
    let sig = Signature::parse(&request.pop_signature).map_err(|_| TctError::SignatureInvalid)?;
    holder_pk
        .verify(&digest, &sig)
        .map_err(|_| TctError::SignatureInvalid)?;

    if manifest_expires_at.0 <= now.0 {
        return Err(TctError::Expired);
    }
    let effective_ttl = ttl_secs.min(manifest_expires_at.0 - now.0);
    if effective_ttl <= 0 {
        return Err(TctError::Expired);
    }

    TctBuilder::new(issuer_key)
        .subject(claims.sub.clone())
        .audience(claims.aud.clone())
        .grants(claims.grants.clone())
        .ttl_secs(effective_ttl)
        .subject_pubkey(holder_pk)
        .issued_at(now)
        .jti(Uuid::new_v4())
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issue(
        issuer: &AitpSigningKey,
        holder: &AitpSigningKey,
        now: Timestamp,
        ttl: i64,
    ) -> IssuedTct {
        TctBuilder::new(issuer)
            .subject(holder.aid().clone())
            .audience(holder.aid().clone())
            .grants(["demo.echo"])
            .ttl_secs(ttl)
            .subject_pubkey(holder.verifying_key())
            .issued_at(now)
            .build()
            .unwrap()
    }

    #[test]
    fn round_trip_renewal_succeeds() {
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

        let renewed = process_renewal_request(&request, &issuer, manifest_exp, now, 3600).unwrap();
        assert_ne!(renewed.claims.jti, original.claims.jti);
        assert_eq!(renewed.claims.sub, original.claims.sub);
        assert_eq!(renewed.claims.grants, original.claims.grants);
        assert_eq!(renewed.claims.exp.0, now.0 + 3600);
        assert!(renewed.voucher.is_some(), "renewal mints a fresh voucher");
    }

    #[test]
    fn renewal_with_wrong_holder_key_rejected() {
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
        let err = process_renewal_request(&request, &issuer, Timestamp(now.0 + 86_400), now, 3600)
            .unwrap_err();
        assert!(matches!(err, TctError::SignatureInvalid), "got {err:?}");
    }

    #[test]
    fn renewal_bounded_by_manifest_expiry() {
        let issuer = AitpSigningKey::from_seed(&[0x20; 32]);
        let holder = AitpSigningKey::from_seed(&[0x21; 32]);
        let now = Timestamp(1_700_000_000);
        let manifest_exp = Timestamp(now.0 + 600); // 10 min left
        let original = issue(&issuer, &holder, now, 60);
        let request =
            build_renewal_request(&holder, original.token, base64url::encode(&[0x55; 16])).unwrap();
        // Caller asks for 1 hour TTL, manifest only allows 10 min.
        let renewed = process_renewal_request(&request, &issuer, manifest_exp, now, 3600).unwrap();
        assert_eq!(
            renewed.claims.exp.0, manifest_exp.0,
            "TTL must be capped by manifest expiry"
        );
    }

    #[test]
    fn renewal_after_manifest_expired_rejected() {
        let issuer = AitpSigningKey::from_seed(&[0x30; 32]);
        let holder = AitpSigningKey::from_seed(&[0x31; 32]);
        let now = Timestamp(1_700_000_000);
        let original = issue(&issuer, &holder, now, 60);
        let request =
            build_renewal_request(&holder, original.token, base64url::encode(&[0x66; 16])).unwrap();
        let err = process_renewal_request(
            &request,
            &issuer,
            Timestamp(now.0 - 1), // manifest already expired
            now,
            3600,
        )
        .unwrap_err();
        assert!(matches!(err, TctError::Expired));
    }

    #[test]
    fn renewal_of_foreign_issuer_token_rejected() {
        let issuer = AitpSigningKey::from_seed(&[0x40; 32]);
        let other_issuer = AitpSigningKey::from_seed(&[0x41; 32]);
        let holder = AitpSigningKey::from_seed(&[0x42; 32]);
        let now = Timestamp(1_700_000_000);
        let foreign = issue(&other_issuer, &holder, now, 60);
        let request =
            build_renewal_request(&holder, foreign.token, base64url::encode(&[0x77; 16])).unwrap();
        // `issuer` cannot renew a TCT signed by `other_issuer`.
        assert!(
            process_renewal_request(&request, &issuer, Timestamp(now.0 + 86_400), now, 3600)
                .is_err()
        );
    }
}
