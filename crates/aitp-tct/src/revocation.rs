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

    /// Locate a file inside the vendored spec tree (`tests/schemas/`),
    /// which `scripts/sync-schemas.sh` keeps byte-identical to the spec
    /// commit pinned in `tests/schemas/SPEC_VERSION`.
    fn vendored(rel: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .expect("repo root")
            .join("tests/schemas")
            .join(rel)
    }

    fn kat_vector(id: &str) -> serde_json::Value {
        let kat: serde_json::Value = serde_json::from_slice(
            &std::fs::read(vendored("known-answer/jcs-sha256.json")).unwrap(),
        )
        .unwrap();
        kat["vectors"]
            .as_array()
            .expect("vectors array")
            .iter()
            .find(|v| v["id"].as_str() == Some(id))
            .unwrap_or_else(|| panic!("vector {id} missing from jcs-sha256.json"))
            .clone()
    }

    /// `kat-revocation-001`, driven entirely from the vendored vector.
    ///
    /// Every expected value is read from the spec's file at runtime — none
    /// is hard-coded here, and none may ever be copied from this
    /// implementation's own output. Updating an expectation to match the
    /// code is precisely how the wrapped-vs-inner divergence was created
    /// and then survived a full release.
    #[test]
    fn rfc_kat_canonical_bytes_match() {
        let v = kat_vector("kat-revocation-001");

        // The vector must declare its signing input. A vector that pins
        // canonical bytes without saying what they are the canonicalization
        // *of* is unfalsifiable — fail loudly rather than guessing.
        assert_eq!(
            v["signing_input"].as_str(),
            Some("body"),
            "kat-revocation-001 must declare signing_input=body (RFC-AITP-0008 §1.5)"
        );
        let object = v["object"].clone();
        assert!(
            object.get("revocation_list").is_none(),
            "signing_input=body means `object` is the inner body, not the wrapper"
        );

        // Round-trip the spec's own object through our type, then through
        // the implementation's signing path.
        let body: RevocationList = serde_json::from_value(object).expect("vector deserializes");
        let view = RevocationListSigningView {
            revocation_list: &body,
        };
        let canonical = jcs::canonicalize_serializable(&view).unwrap();

        assert_eq!(
            canonical.len(),
            v["jcs_canonical_len_bytes"].as_u64().unwrap() as usize,
            "canonical byte length diverges from spec kat-revocation-001"
        );
        assert_eq!(
            hex::encode(&canonical),
            v["jcs_canonical_hex"].as_str().unwrap(),
            "canonical bytes diverge from spec kat-revocation-001 — the implementation \
             is canonicalizing a different JSON shape than the spec signs"
        );
        assert_eq!(
            hex::encode(Sha256::digest(&canonical)),
            v["sha256_hex"].as_str().unwrap(),
            "digest diverges from spec kat-revocation-001"
        );
    }

    /// The committed, Python-reference-minted signed example must verify
    /// **as committed**.
    ///
    /// This deliberately does not re-mint. A test that signs an artifact
    /// and then verifies its own output proves only that the
    /// implementation agrees with itself, which is exactly why an
    /// `aitp-rs` issuer and an `aitp-verifier-py` consumer could disagree
    /// on the wire while both suites stayed green.
    #[test]
    fn spec_signed_example_snapshot_verifies() {
        let raw = std::fs::read(vendored(
            "known-answer/signed-examples/revocation/kat-keypair-001-snapshot.json",
        ))
        .expect("read committed signed example");
        let mut value: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        // `_kat_input` is a minting companion, never part of the wire object.
        value.as_object_mut().unwrap().remove("_kat_input");

        let env: RevocationListEnvelope =
            serde_json::from_value(value).expect("signed example deserializes");
        let issuer = env.revocation_list.issuer.clone();
        let ctx = VerifyRevocationListContext {
            expected_issuer: &issuer,
            now: Timestamp(1_711_900_100),
        };
        verify_revocation_list(&env, &ctx)
            .expect("committed spec signed example must verify as committed");
    }
}
