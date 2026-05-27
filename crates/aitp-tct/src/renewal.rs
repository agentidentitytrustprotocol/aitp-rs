//! TCT renewal (RFC-AITP-0005 §10).
//!
//! A holder asks the issuer for a fresh TCT before the existing one
//! expires. The renewal flow does NOT replay the full Mutual Handshake:
//! identity has already been established and is encoded in the existing
//! TCT's `subject` + `binding.cnf`. The holder presents the existing
//! TCT plus a PoP signature to prove it still controls the subject key.
//!
//! Wire shape of the renewal request:
//!
//! ```json
//! {
//!   "current_tct": { "tct": { /* the TCT being renewed */ } },
//!   "pop_nonce":     "<22-char base64url, fresh>",
//!   "pop_signature": "<sign(holder_key, sha256(decoded(pop_nonce)))>"
//! }
//! ```
//!
//! Successful renewal returns a fresh `TctEnvelope` with:
//! - new random `jti`
//! - `issued_at = now`
//! - `expires_at = min(now + ttl, manifest.expires_at)` — same bound as
//!   the original handshake (RFC-AITP-0004 §4.3).

use crate::types::{Tct, TctEnvelope, TctRenewalPayload};
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
    current_tct: TctEnvelope,
    pop_nonce: String,
) -> Result<TctRenewalPayload, TctError> {
    let nonce_bytes = base64url::decode_strict(&pop_nonce)
        .map_err(|e| TctError::Canonicalization(format!("pop_nonce: {e}")))?;
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
/// 1. `current_tct` verifies under issuer's own AID.
/// 2. `pop_signature` verifies under the existing TCT's
///    `binding.cnf` key (proves the renewal request comes from the
///    same holder that originally received the TCT).
/// 3. Issuer's Manifest is still in its valid window (the holder
///    cannot renew across an issuer key-rotation boundary).
///
/// Returns a fresh `Tct` with the same grants, same subject /
/// audience / cnf, new `jti`, and `expires_at` bounded by the
/// supplied `manifest_expires_at`.
pub fn process_renewal_request(
    request: &TctRenewalPayload,
    issuer_key: &AitpSigningKey,
    manifest_expires_at: Timestamp,
    now: Timestamp,
    ttl_secs: i64,
) -> Result<Tct, TctError> {
    let issuer_pubkey = AitpVerifyingKey::from_aid(issuer_key.aid()).map_err(TctError::Crypto)?;

    let ctx = TctVerifyContext {
        expected_audience: &request.current_tct.tct.audience,
        issuer_pubkey: &issuer_pubkey,
        now,
        issuer_manifest_expires_at: None,
        revocation_check: None,
    };
    verify_tct(&request.current_tct.tct, &ctx)?;

    // Algorithm-agile cnf decode: handles Ed25519 raw (32 B) and
    // P-256 SEC1-compressed (33 B). `verify_tct` above already
    // cross-checked `cnf` against the subject AID, so we trust the
    // length dispatch here without re-comparing to the subject.
    let cnf_bytes = base64url::decode_strict(&request.current_tct.tct.binding.cnf)
        .map_err(|_| TctError::CnfMalformed)?;
    let holder_pk = AitpVerifyingKey::from_compressed(&cnf_bytes).map_err(TctError::Crypto)?;

    let nonce_bytes = base64url::decode_strict(&request.pop_nonce)
        .map_err(|e| TctError::Canonicalization(format!("pop_nonce: {e}")))?;
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
        .subject(request.current_tct.tct.subject.clone())
        .audience(request.current_tct.tct.audience.clone())
        .grants(request.current_tct.tct.grants.clone())
        .ttl_secs(effective_ttl)
        .subject_pubkey(holder_pk)
        .issued_at(now)
        .jti(Uuid::new_v4())
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TctEnvelope;

    #[test]
    fn round_trip_renewal_succeeds() {
        let issuer = AitpSigningKey::from_seed(&[0x01; 32]);
        let holder = AitpSigningKey::from_seed(&[0x02; 32]);
        let now = Timestamp(1_700_000_000);
        let manifest_exp = Timestamp(now.0 + 86_400);

        let original = TctBuilder::new(&issuer)
            .subject(holder.aid().clone())
            .audience(holder.aid().clone())
            .grants(["demo.echo"])
            .ttl_secs(60)
            .subject_pubkey(holder.verifying_key())
            .issued_at(now)
            .build()
            .unwrap();
        let request = build_renewal_request(
            &holder,
            TctEnvelope {
                tct: original.clone(),
            },
            base64url::encode(&[0x33; 16]),
        )
        .unwrap();

        let renewed = process_renewal_request(&request, &issuer, manifest_exp, now, 3600).unwrap();
        assert_ne!(renewed.jti, original.jti);
        assert_eq!(renewed.subject, original.subject);
        assert_eq!(renewed.grants, original.grants);
        assert_eq!(renewed.expires_at.0, now.0 + 3600);
    }

    #[test]
    fn renewal_with_wrong_holder_key_rejected() {
        let issuer = AitpSigningKey::from_seed(&[0x10; 32]);
        let holder = AitpSigningKey::from_seed(&[0x11; 32]);
        let attacker = AitpSigningKey::from_seed(&[0x12; 32]);
        let now = Timestamp(1_700_000_000);
        let original = TctBuilder::new(&issuer)
            .subject(holder.aid().clone())
            .audience(holder.aid().clone())
            .grants(["demo.echo"])
            .ttl_secs(60)
            .subject_pubkey(holder.verifying_key())
            .issued_at(now)
            .build()
            .unwrap();
        let request = build_renewal_request(
            &attacker, // attacker signs with its own key
            TctEnvelope { tct: original },
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
        let original = TctBuilder::new(&issuer)
            .subject(holder.aid().clone())
            .audience(holder.aid().clone())
            .grants(["demo.echo"])
            .ttl_secs(60)
            .subject_pubkey(holder.verifying_key())
            .issued_at(now)
            .build()
            .unwrap();
        let request = build_renewal_request(
            &holder,
            TctEnvelope { tct: original },
            base64url::encode(&[0x55; 16]),
        )
        .unwrap();
        // Caller asks for 1 hour TTL, manifest only allows 10 min.
        let renewed = process_renewal_request(&request, &issuer, manifest_exp, now, 3600).unwrap();
        assert_eq!(
            renewed.expires_at.0, manifest_exp.0,
            "TTL must be capped by manifest expiry"
        );
    }

    #[test]
    fn renewal_after_manifest_expired_rejected() {
        let issuer = AitpSigningKey::from_seed(&[0x30; 32]);
        let holder = AitpSigningKey::from_seed(&[0x31; 32]);
        let now = Timestamp(1_700_000_000);
        let original = TctBuilder::new(&issuer)
            .subject(holder.aid().clone())
            .audience(holder.aid().clone())
            .grants(["demo.echo"])
            .ttl_secs(60)
            .subject_pubkey(holder.verifying_key())
            .issued_at(now)
            .build()
            .unwrap();
        let request = build_renewal_request(
            &holder,
            TctEnvelope { tct: original },
            base64url::encode(&[0x66; 16]),
        )
        .unwrap();
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
}
