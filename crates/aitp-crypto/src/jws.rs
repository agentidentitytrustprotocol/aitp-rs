//! Compact JWS profile for portable trust artifacts
//! (RFC-AITP-0001 §5.4.5).
//!
//! The TCT, the grant voucher, and the delegation token are RFC 7515
//! compact JWS strings. The signature covers the **exact transmitted
//! bytes** (`ASCII(b64(header) || '.' || b64(payload))`) — verifiers
//! never re-serialize, re-canonicalize, or reconstruct any byte
//! sequence. This module owns the profile mechanics shared by every
//! artifact:
//!
//! - **Algorithm pinning.** There is no algorithm negotiation: the sole
//!   acceptable `alg` is derived from the signer's AID (`EdDSA` for
//!   Ed25519 AIDs, `ES256` for P-256 AIDs). Any other value — including
//!   `none` in any capitalization — is rejected with
//!   [`CryptoError::AlgMismatch`] (wire code `TOKEN_ALG_MISMATCH`).
//! - **Explicit typing.** Every AITP JWS carries `typ` (RFC 8725
//!   §3.11), checked exactly against the verification context
//!   ([`CryptoError::TypMismatch`], wire code `TOKEN_TYP_MISMATCH`).
//! - **Strict parsing.** Exactly three non-empty unpadded-base64url
//!   segments; the protected header contains exactly `alg` and `typ`
//!   and nothing else (no `crit`, `kid`, `jku`, `jwk`, `x5u`, `x5c` —
//!   key resolution is by AID and Manifest, never header material).
//!
//! Signing serializes the claims as RFC 8785 (JCS) canonical JSON and a
//! fixed two-member header — this makes mints byte-stable so the spec's
//! known-answer vectors are reproducible, but it is a *minting*
//! convention only: verification operates on transmitted bytes and
//! succeeds for any JOSE-conformant producer.

use crate::{AitpSigningKey, AitpVerifyingKey, CryptoError};
use aitp_core::{base64url, jcs, Aid, AidAlgorithm};
use serde::Deserialize;

/// `typ` header value for the Trust Context Token (RFC-AITP-0005).
pub const TYP_TCT: &str = "aitp-tct+jwt";
/// `typ` header value for the grant voucher (RFC-AITP-0005 §8).
pub const TYP_GRANT_VOUCHER: &str = "aitp-grant+jwt";
/// `typ` header value for the delegation token (RFC-AITP-0006).
pub const TYP_DELEGATION: &str = "aitp-delegation+jwt";

/// The sole acceptable JOSE `alg` value for an AID algorithm
/// (RFC-AITP-0001 §5.4.5): `EdDSA` for Ed25519, `ES256` for P-256.
pub fn jose_alg(algorithm: AidAlgorithm) -> Result<&'static str, CryptoError> {
    match algorithm {
        AidAlgorithm::Ed25519 => Ok("EdDSA"),
        AidAlgorithm::P256 => Ok("ES256"),
        // `AidAlgorithm` is #[non_exhaustive]; fail fast rather than
        // letting an unmapped suite verify under the wrong alg.
        other => Err(CryptoError::KeyParseFailed(format!(
            "AID algorithm {other:?} has no registered JOSE alg in this build"
        ))),
    }
}

/// Protected header. Deserialization is the strictness gate:
/// `deny_unknown_fields` rejects any extra parameter (`crit`, `kid`,
/// `jku`, …) and serde's derive rejects duplicate members.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JwsHeader {
    alg: String,
    typ: String,
}

/// Sign `claims` as a compact JWS with the given `typ`.
///
/// The protected header is exactly `{"alg":"<alg>","typ":"<typ>"}` in
/// that member order, and the payload is the JCS canonicalization of
/// `claims` — the spec's byte-stable minting convention, so fixed
/// inputs reproduce the pinned known-answer vectors exactly.
pub fn sign_compact<T: serde::Serialize>(
    key: &AitpSigningKey,
    typ: &str,
    claims: &T,
) -> Result<String, CryptoError> {
    if typ.bytes().any(|b| b == b'"' || b == b'\\' || b < 0x20) {
        return Err(CryptoError::JwsMalformed(
            "typ must not require JSON escaping".into(),
        ));
    }
    let alg = jose_alg(key.algorithm())?;
    let header = format!("{{\"alg\":\"{alg}\",\"typ\":\"{typ}\"}}");
    let payload = jcs::canonicalize_serializable(claims)
        .map_err(|e| CryptoError::JwsMalformed(format!("claims canonicalization: {e}")))?;
    let signing_input = format!(
        "{}.{}",
        base64url::encode(header.as_bytes()),
        base64url::encode(&payload)
    );
    let sig = key.sign_raw(signing_input.as_bytes());
    Ok(format!("{signing_input}.{}", base64url::encode(&sig)))
}

/// Verify a compact JWS against the key encoded in `signer` and return
/// the decoded payload bytes.
///
/// Order per RFC-AITP-0005 §7.2 / RFC-AITP-0001 §5.4.5: strict parse →
/// `typ` → `alg` pin → signature. The returned bytes are guaranteed to
/// be a JSON object; claim-level validation (including duplicate-claim
/// rejection via typed `deny_unknown_fields` structs) belongs to the
/// artifact crates.
pub fn verify_compact(
    signer: &Aid,
    expected_typ: &str,
    token: &str,
) -> Result<Vec<u8>, CryptoError> {
    let (header_b64, payload_b64, sig_b64) = split_strict(token)?;

    let header_bytes = base64url::decode_strict(header_b64)
        .map_err(|e| CryptoError::JwsMalformed(format!("header segment: {e}")))?;
    let payload = base64url::decode_strict(payload_b64)
        .map_err(|e| CryptoError::JwsMalformed(format!("payload segment: {e}")))?;
    let sig_bytes = base64url::decode_strict(sig_b64)
        .map_err(|e| CryptoError::JwsMalformed(format!("signature segment: {e}")))?;

    let header: JwsHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| CryptoError::JwsMalformed(format!("protected header: {e}")))?;

    if header.typ != expected_typ {
        return Err(CryptoError::TypMismatch {
            expected: expected_typ.to_string(),
            got: header.typ,
        });
    }
    let expected_alg = jose_alg(signer.algorithm())?;
    if header.alg != expected_alg {
        return Err(CryptoError::AlgMismatch(format!(
            "expected {expected_alg} for this AID, got {}",
            header.alg
        )));
    }

    let vk = AitpVerifyingKey::from_aid(signer)?;
    let signing_input = &token.as_bytes()[..header_b64.len() + 1 + payload_b64.len()];
    vk.verify_raw(signing_input, &sig_bytes)?;

    // §5.4.5: the payload must be a JSON object. Object-ness is checked
    // here; duplicate-key and unknown-claim rejection happens at the
    // artifact crates' typed deserialization.
    match serde_json::from_slice::<serde_json::Value>(&payload) {
        Ok(serde_json::Value::Object(_)) => {}
        _ => {
            return Err(CryptoError::JwsMalformed(
                "payload is not a JSON object".into(),
            ))
        }
    }

    Ok(payload)
}

/// Decode the payload segment of a compact JWS **without verifying
/// anything** — no signature, no `typ`, no `alg` check.
///
/// The only legitimate use is bootstrapping verification itself:
/// extracting the `iss` claim to resolve the signer's key, then calling
/// [`verify_compact`]. Treat the returned bytes as attacker-controlled.
pub fn decode_payload_unverified(token: &str) -> Result<Vec<u8>, CryptoError> {
    let (_, payload_b64, _) = split_strict(token)?;
    base64url::decode_strict(payload_b64)
        .map_err(|e| CryptoError::JwsMalformed(format!("payload segment: {e}")))
}

/// Exactly three non-empty `.`-separated segments (no unsecured JWS, no
/// detached payload, no JSON serialization).
fn split_strict(token: &str) -> Result<(&str, &str, &str), CryptoError> {
    let mut parts = token.split('.');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s), None) if !h.is_empty() && !p.is_empty() && !s.is_empty() => {
            Ok((h, p, s))
        }
        _ => Err(CryptoError::JwsMalformed(
            "expected exactly three non-empty segments".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn claims() -> serde_json::Value {
        json!({
            "ver": "aitp/0.2",
            "iss": "aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik",
            "grants": ["demo.echo"],
        })
    }

    #[test]
    fn sign_verify_round_trip_ed25519() {
        let key = AitpSigningKey::from_seed(&[1u8; 32]);
        let token = sign_compact(&key, TYP_TCT, &claims()).unwrap();
        let payload = verify_compact(key.aid(), TYP_TCT, &token).unwrap();
        let back: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(back, claims());
    }

    #[test]
    fn sign_verify_round_trip_p256() {
        let key = AitpSigningKey::from_p256_seed(&[5u8; 32]).unwrap();
        let token = sign_compact(&key, TYP_DELEGATION, &claims()).unwrap();
        assert!(token.starts_with(&base64url::encode(
            b"{\"alg\":\"ES256\",\"typ\":\"aitp-delegation+jwt\"}"
        )));
        verify_compact(key.aid(), TYP_DELEGATION, &token).unwrap();
    }

    #[test]
    fn header_bytes_are_exact_two_member_form() {
        let key = AitpSigningKey::from_seed(&[2u8; 32]);
        let token = sign_compact(&key, TYP_GRANT_VOUCHER, &claims()).unwrap();
        let header_b64 = token.split('.').next().unwrap();
        let header = base64url::decode_strict(header_b64).unwrap();
        assert_eq!(header, b"{\"alg\":\"EdDSA\",\"typ\":\"aitp-grant+jwt\"}");
    }

    #[test]
    fn rejects_typ_mismatch() {
        let key = AitpSigningKey::from_seed(&[3u8; 32]);
        let token = sign_compact(&key, TYP_GRANT_VOUCHER, &claims()).unwrap();
        assert!(matches!(
            verify_compact(key.aid(), TYP_TCT, &token),
            Err(CryptoError::TypMismatch { .. })
        ));
    }

    #[test]
    fn rejects_alg_none_and_wrong_alg() {
        let key = AitpSigningKey::from_seed(&[4u8; 32]);
        let token = sign_compact(&key, TYP_TCT, &claims()).unwrap();
        let (_, rest) = token.split_once('.').unwrap();
        for evil_alg in ["none", "None", "NONE", "ES256", "HS256", "RS256"] {
            let evil_header = base64url::encode(
                format!("{{\"alg\":\"{evil_alg}\",\"typ\":\"aitp-tct+jwt\"}}").as_bytes(),
            );
            let evil = format!("{evil_header}.{rest}");
            assert!(
                matches!(
                    verify_compact(key.aid(), TYP_TCT, &evil),
                    Err(CryptoError::AlgMismatch(_))
                ),
                "alg {evil_alg} must be rejected before signature checking"
            );
        }
    }

    #[test]
    fn rejects_extra_header_params() {
        let key = AitpSigningKey::from_seed(&[6u8; 32]);
        let token = sign_compact(&key, TYP_TCT, &claims()).unwrap();
        let (_, rest) = token.split_once('.').unwrap();
        for evil in [
            r#"{"alg":"EdDSA","typ":"aitp-tct+jwt","crit":["exp"]}"#,
            r#"{"alg":"EdDSA","typ":"aitp-tct+jwt","kid":"x"}"#,
            r#"{"alg":"EdDSA","typ":"aitp-tct+jwt","jwk":{}}"#,
            r#"{"alg":"EdDSA"}"#,
            r#"{"typ":"aitp-tct+jwt"}"#,
            r#"{"alg":"EdDSA","alg":"none","typ":"aitp-tct+jwt"}"#,
        ] {
            let evil_token = format!("{}.{rest}", base64url::encode(evil.as_bytes()));
            assert!(
                matches!(
                    verify_compact(key.aid(), TYP_TCT, &evil_token),
                    Err(CryptoError::JwsMalformed(_))
                ),
                "header {evil} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_wrong_segment_shapes() {
        let key = AitpSigningKey::from_seed(&[7u8; 32]);
        let token = sign_compact(&key, TYP_TCT, &claims()).unwrap();
        let (h, rest) = token.split_once('.').unwrap();
        let (p, s) = rest.split_once('.').unwrap();
        for evil in [
            format!("{h}.{p}"),                        // two segments
            format!("{h}.{p}.{s}.x"),                  // four segments
            format!("{h}..{s}"),                       // empty payload (unsecured-ish)
            format!("{h}.{p}."),                       // empty signature
            format!("{h}.{p}.{s}="),                   // padding
            format!("{h}.{p}.{}!", &s[..s.len() - 1]), // bad alphabet
        ] {
            assert!(
                verify_compact(key.aid(), TYP_TCT, &evil).is_err(),
                "shape {evil:?} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_tampered_payload_and_cross_key() {
        let key = AitpSigningKey::from_seed(&[8u8; 32]);
        let other = AitpSigningKey::from_seed(&[9u8; 32]);
        let token = sign_compact(&key, TYP_TCT, &claims()).unwrap();

        // Cross-key: same token, different AID.
        assert!(matches!(
            verify_compact(other.aid(), TYP_TCT, &token),
            Err(CryptoError::SignatureInvalid)
        ));

        // Single-byte payload tamper.
        let (h, rest) = token.split_once('.').unwrap();
        let (_, s) = rest.split_once('.').unwrap();
        let tampered_payload = base64url::encode(
            &jcs::canonicalize_serializable(&json!({"ver": "aitp/0.2"})).unwrap(),
        );
        let tampered = format!("{h}.{tampered_payload}.{s}");
        assert!(matches!(
            verify_compact(key.aid(), TYP_TCT, &tampered),
            Err(CryptoError::SignatureInvalid)
        ));
    }

    #[test]
    fn rejects_non_object_payload() {
        let key = AitpSigningKey::from_seed(&[10u8; 32]);
        let token = sign_compact(&key, TYP_TCT, &json!(["not", "an", "object"])).unwrap();
        assert!(matches!(
            verify_compact(key.aid(), TYP_TCT, &token),
            Err(CryptoError::JwsMalformed(_))
        ));
    }

    #[test]
    fn p256_key_rejects_eddsa_alg_header() {
        // A P-256 AID pins ES256; a (validly signed, by an Ed25519 key)
        // EdDSA token presented against it dies on the alg pin.
        let p256 = AitpSigningKey::from_p256_seed(&[11u8; 32]).unwrap();
        let ed = AitpSigningKey::from_seed(&[12u8; 32]);
        let token = sign_compact(&ed, TYP_TCT, &claims()).unwrap();
        assert!(matches!(
            verify_compact(p256.aid(), TYP_TCT, &token),
            Err(CryptoError::AlgMismatch(_))
        ));
    }

    #[test]
    fn decode_payload_unverified_returns_claims() {
        let key = AitpSigningKey::from_seed(&[13u8; 32]);
        let token = sign_compact(&key, TYP_TCT, &claims()).unwrap();
        let payload = decode_payload_unverified(&token).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(v["iss"], claims()["iss"]);
    }
}
