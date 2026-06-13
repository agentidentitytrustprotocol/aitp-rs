//! Signed revocation snapshots (RFC-AITP-0008 §1.5).
//!
//! An issuing peer publishes a periodically-refreshed signed snapshot
//! of every TCT JTI it has revoked. Consuming peers cache the snapshot
//! per `expires_at` and consult it before honoring a TCT. An empty
//! `entries` array is itself a meaningful signed assertion that nothing
//! has been revoked since the previous snapshot — this defends against
//! a network attacker that suppresses fresher snapshots to roll back
//! revocations.

use aitp_core::{jcs, Aid, Timestamp};
use aitp_crypto::{AitpSigningKey, AitpVerifyingKey, Signature};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::TctError;

/// Inner body of a signed revocation snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RevocationList {
    /// MUST be `"aitp/0.2"`.
    pub version: String,
    /// The issuing peer's AID. MUST equal the `issuer` of every TCT
    /// covered by `entries`.
    pub issuer: Aid,
    /// Unix timestamp when this snapshot was signed.
    pub published_at: Timestamp,
    /// Unix timestamp after which this snapshot MUST NOT be cached.
    pub expires_at: Timestamp,
    /// Revoked-entry records. MAY be empty.
    pub entries: Vec<RevocationEntry>,
}

/// A single revoked-TCT record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RevocationEntry {
    /// JTI of the revoked TCT.
    pub jti: Uuid,
    /// Unix timestamp when the issuing peer revoked the TCT.
    pub revoked_at: Timestamp,
    /// Optional human-readable reason. Not used in trust decisions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// On-wire envelope: `{"revocation_list": {...}, "signature": "..."}`.
///
/// Per RFC-AITP-0008 §1.5, both `revocation_list` and `signature` are
/// REQUIRED. `signature` is base64url over
/// `sha256(JCS({"revocation_list": {...}}))` — the envelope minus the
/// signature field — per the v0.2 `kat-revocation-001` vector.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RevocationListEnvelope {
    /// The signed inner snapshot.
    pub revocation_list: RevocationList,
    /// Issuer's base64url signature over JCS-canonical bytes of
    /// `{"revocation_list": {...}}`.
    pub signature: String,
}

/// Signing view: the wrapped `{"revocation_list": {...}}` form (the
/// envelope minus `signature`), per the v0.2 `kat-revocation-001`
/// vector.
#[derive(Serialize)]
struct RevocationListSigningView<'a> {
    revocation_list: &'a RevocationList,
}

/// Sign a [`RevocationList`] body with the issuer's signing key.
///
/// Returns the on-wire [`RevocationListEnvelope`] with `signature`
/// populated. The signing input is `sha256(JCS({"revocation_list": {...}}))`
/// per the v0.2 `kat-revocation-001` vector.
pub fn sign_revocation_list(
    body: RevocationList,
    issuer_key: &AitpSigningKey,
) -> Result<RevocationListEnvelope, TctError> {
    let view = RevocationListSigningView {
        revocation_list: &body,
    };
    let canonical = jcs::canonicalize_serializable(&view)
        .map_err(|e| TctError::Canonicalization(e.to_string()))?;
    let digest = Sha256::digest(&canonical);
    let sig = issuer_key.sign(&digest);
    Ok(RevocationListEnvelope {
        revocation_list: body,
        signature: sig.into_string(),
    })
}

/// Verify a [`RevocationListEnvelope`].
///
/// 1. `revocation_list.expires_at >= ctx.now` — else `TctError::Expired`.
/// 2. `revocation_list.issuer` resolves to a public key matching
///    `ctx.expected_issuer` (else `TctError::CnfMalformed` — chosen
///    rather than introducing a new error variant for v0.1).
/// 3. `signature` is present and verifies under that public key over
///    `sha256(JCS(envelope without signature))`.
pub fn verify_revocation_list(
    envelope: &RevocationListEnvelope,
    ctx: &VerifyRevocationListContext<'_>,
) -> Result<(), TctError> {
    if envelope.revocation_list.version != aitp_core::PROTOCOL_VERSION {
        return Err(TctError::VersionUnknown);
    }
    if envelope.revocation_list.expires_at.is_in_the_past(ctx.now) {
        return Err(TctError::Expired);
    }
    if &envelope.revocation_list.issuer != ctx.expected_issuer {
        return Err(TctError::CnfMalformed);
    }

    let pubkey =
        AitpVerifyingKey::from_aid(&envelope.revocation_list.issuer).map_err(TctError::Crypto)?;
    let sig = Signature::parse(&envelope.signature).map_err(|_| TctError::SignatureInvalid)?;

    let view = RevocationListSigningView {
        revocation_list: &envelope.revocation_list,
    };
    let canonical = jcs::canonicalize_serializable(&view)
        .map_err(|e| TctError::Canonicalization(e.to_string()))?;
    pubkey
        .verify(&Sha256::digest(&canonical), &sig)
        .map_err(|_| TctError::SignatureInvalid)?;
    Ok(())
}

/// Context for [`verify_revocation_list`].
pub struct VerifyRevocationListContext<'a> {
    /// The AID the verifier expects this snapshot to be from.
    pub expected_issuer: &'a Aid,
    /// Verifier's clock for `expires_at` check.
    pub now: Timestamp,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issuer_key() -> AitpSigningKey {
        AitpSigningKey::from_seed(&[0xA0; 32])
    }

    fn sample_body(issuer: Aid) -> RevocationList {
        RevocationList {
            version: "aitp/0.2".into(),
            issuer,
            published_at: Timestamp(1_700_000_000),
            expires_at: Timestamp(1_700_003_600),
            entries: vec![RevocationEntry {
                jti: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
                revoked_at: Timestamp(1_700_001_000),
                reason: None,
            }],
        }
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let key = issuer_key();
        let env = sign_revocation_list(sample_body(key.aid().clone()), &key).unwrap();
        let ctx = VerifyRevocationListContext {
            expected_issuer: key.aid(),
            now: Timestamp(1_700_001_000),
        };
        verify_revocation_list(&env, &ctx).expect("fresh snapshot verifies");
    }

    #[test]
    fn expired_is_rejected() {
        let key = issuer_key();
        let env = sign_revocation_list(sample_body(key.aid().clone()), &key).unwrap();
        let ctx = VerifyRevocationListContext {
            expected_issuer: key.aid(),
            now: Timestamp(1_700_999_999),
        };
        assert!(matches!(
            verify_revocation_list(&env, &ctx),
            Err(TctError::Expired)
        ));
    }

    #[test]
    fn wrong_issuer_is_rejected() {
        let key = issuer_key();
        let env = sign_revocation_list(sample_body(key.aid().clone()), &key).unwrap();
        let other = AitpSigningKey::from_seed(&[0xB0; 32]);
        let ctx = VerifyRevocationListContext {
            expected_issuer: other.aid(),
            now: Timestamp(1_700_001_000),
        };
        assert!(matches!(
            verify_revocation_list(&env, &ctx),
            Err(TctError::CnfMalformed)
        ));
    }

    #[test]
    fn empty_entries_round_trips() {
        let key = issuer_key();
        let mut body = sample_body(key.aid().clone());
        body.entries.clear();
        let env = sign_revocation_list(body, &key).unwrap();
        let ctx = VerifyRevocationListContext {
            expected_issuer: key.aid(),
            now: Timestamp(1_700_001_000),
        };
        verify_revocation_list(&env, &ctx).expect("empty list still verifies");
    }

    #[test]
    fn rfc_kat_canonical_bytes_match() {
        // Vector kat-revocation-001 from the v0.2 spec
        // schemas/conformance/known-answer/jcs-sha256.json: signed view
        // is the wrapped `{"revocation_list": {...}}` form, version
        // literal `aitp/0.2`.
        let body = RevocationList {
            version: "aitp/0.2".into(),
            issuer: Aid::parse("aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik").unwrap(),
            published_at: Timestamp(1_711_900_000),
            expires_at: Timestamp(1_711_903_600),
            entries: vec![RevocationEntry {
                jti: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
                revoked_at: Timestamp(1_711_901_000),
                reason: None,
            }],
        };
        let view = RevocationListSigningView {
            revocation_list: &body,
        };
        let canonical = jcs::canonicalize_serializable(&view).unwrap();
        let expected_hex = "7b227265766f636174696f6e5f6c697374223a7b22656e7472696573223a5b7b226a7469223a2235353065383430302d653239622d343164342d613731362d343436363535343430303030222c227265766f6b65645f6174223a313731313930313030307d5d2c22657870697265735f6174223a313731313930333630302c22697373756572223a226169643a7075626b65793a4f326f6e764d3632704331696f366a514b6d384e6332557946586364346b4f6d4f7342496f59745a32696b222c227075626c69736865645f6174223a313731313930303030302c2276657273696f6e223a22616974702f302e32227d7d";
        assert_eq!(
            hex::encode(&canonical),
            expected_hex,
            "canonical bytes diverge from spec v0.2 kat-revocation-001"
        );
        let digest = Sha256::digest(&canonical);
        assert_eq!(
            hex::encode(digest),
            "739feb36cc2530ad3188f6c3a9ee7459820533382ee24387a8c261787397e0d9"
        );
    }

    #[test]
    fn spec_signed_example_snapshot_verifies() {
        // signed-examples/revocation/kat-keypair-001-snapshot.json:
        // re-mint from the pinned seed and verify byte-stable signature.
        let key = AitpSigningKey::from_seed(&[0u8; 32]); // kat-keypair-001
        let body = RevocationList {
            version: "aitp/0.2".into(),
            issuer: key.aid().clone(),
            published_at: Timestamp(1_711_900_000),
            expires_at: Timestamp(1_711_903_600),
            entries: vec![RevocationEntry {
                jti: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440099").unwrap(),
                revoked_at: Timestamp(1_711_900_060),
                reason: Some("key_compromised".into()),
            }],
        };
        let env = sign_revocation_list(body, &key).unwrap();
        assert_eq!(
            env.signature,
            "2OYmur9NnrFsrz4Qeso_fGj2Bk0g2y6yNf4H7dqrqEvKZ-YfndY3GavquOIodWGs4EFdgmaHoer0NWc7sPF1DQ",
            "signature diverges from the spec signed-example vector"
        );
        let ctx = VerifyRevocationListContext {
            expected_issuer: key.aid(),
            now: Timestamp(1_711_900_100),
        };
        verify_revocation_list(&env, &ctx).expect("spec vector verifies");
    }
}
