//! Signed revocation snapshots (RFC-AITP-0008 §1.5).
//!
//! An issuing peer publishes a periodically-refreshed signed snapshot
//! of every TCT JTI it has revoked. Consuming peers cache the snapshot
//! per `expires_at` and consult it before honoring a TCT. An empty
//! `entries` array is itself a meaningful signed assertion that nothing
//! has been revoked since the previous snapshot — this defends against
//! a network attacker that suppresses fresher snapshots to roll back
//! revocations.

use aitp_core::{check_members, from_serde_error, jcs, Aid, ExtensionsMap, Timestamp};
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
    /// Forward-compatible extensions (RFC-AITP-0001 §7, RFC-AITP-0012).
    ///
    /// **Presence-sensitive**, deliberately modeled as `Option<ExtensionsMap>`
    /// rather than a defaulted empty map with `skip_serializing_if =
    /// "is_empty"`. Under RFC 8785 canonicalization, absent (`None`) emits
    /// no `extensions` key at all, while present-but-empty
    /// (`Some(ExtensionsMap::new())`) emits `"extensions":{}` — different
    /// bytes, different digest, different signature. Unlike the envelope
    /// (`AitpEnvelope`), this body IS JCS-canonicalized for the signature
    /// (see [`revocation_signing_bytes`]), so conflating the two shapes
    /// here would be a live signature bug, not a cosmetic one: a snapshot
    /// signed with a literal `"extensions":{}` on the wire would fail to
    /// verify if this were silently normalized to absent, or vice versa.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<ExtensionsMap>,
}

/// Full set of top-level members `aitp-revocation-list.schema.json`'s inner
/// `revocation_list` object declares, including the `extensions` namespace
/// key itself. Used by [`parse_revocation_snapshot_wire`]'s member-set
/// check (RFC-AITP-0001 §7).
///
/// Anchored to the vendored schema by `crates/aitp-tct/tests/schema.rs`,
/// which asserts this list equals `properties.revocation_list.properties`'s
/// keys — so this cannot silently drift from the spec.
pub const REVOCATION_LIST_MEMBERS: &[&str] = &[
    "version",
    "issuer",
    "published_at",
    "expires_at",
    "entries",
    "extensions",
];

/// Full set of top-level members of the on-wire revocation snapshot
/// envelope (`{"revocation_list": {...}, "signature": "..."}`). Used by
/// [`parse_revocation_snapshot_wire`]'s member-set check.
pub const REVOCATION_ENVELOPE_MEMBERS: &[&str] = &["revocation_list", "signature"];

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
/// REQUIRED. `signature` is base64url over `sha256(JCS(revocation_list))`
/// — the **inner** body. The `revocation_list` key is transport routing
/// metadata and is never part of the signing bytes
/// (RFC-AITP-0001 §5.4.1).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RevocationListEnvelope {
    /// The signed inner snapshot — this, alone, is what is signed.
    pub revocation_list: RevocationList,
    /// Issuer's base64url signature over the JCS-canonical bytes of the
    /// inner [`RevocationList`] body. Note this is a **sibling** of that
    /// body, never a member of it, so there is nothing to strip before
    /// canonicalizing.
    pub signature: String,
}

/// The canonical signing input for a revocation snapshot.
///
/// **The single definition of what gets signed.** `sign_revocation_list`,
/// `verify_revocation_list` and the known-answer test all route through
/// this, so signer, verifier and test cannot drift apart — a divergence
/// between them is exactly what shipped before spec commit `5f8e588`.
///
/// The input is the **inner** [`RevocationList`] body, canonicalized as-is.
/// The `{"revocation_list": …}` wrapper is the HTTP transport shape and is
/// NOT signed (RFC-AITP-0001 §5.4.1, RFC-AITP-0008 §1.5). The envelope's
/// `signature` is a sibling of the body rather than a member of it, so —
/// unlike the manifest, where `signature` is stripped from within — there
/// is nothing to remove here.
///
/// Exposed publicly so a caller that needs the exact signing bytes — an
/// independent verifier, an HSM signing path, a debugging tool — can obtain
/// them instead of reconstructing the shape at the call site. Reconstructing
/// it is how the signer, the verifier and the conformance fixture minter
/// drifted apart in the first place.
pub fn revocation_signing_bytes(body: &RevocationList) -> Result<Vec<u8>, TctError> {
    jcs::canonicalize_serializable(body).map_err(|e| TctError::Canonicalization(e.to_string()))
}

/// Sign a [`RevocationList`] body with the issuer's signing key.
///
/// Returns the on-wire [`RevocationListEnvelope`] with `signature`
/// populated. The signing input is `sha256(JCS(revocation_list))` — the
/// inner body; see [`revocation_signing_bytes`].
pub fn sign_revocation_list(
    body: RevocationList,
    issuer_key: &AitpSigningKey,
) -> Result<RevocationListEnvelope, TctError> {
    let canonical = revocation_signing_bytes(&body)?;
    let digest = Sha256::digest(&canonical);
    let sig = issuer_key.sign(&digest);
    Ok(RevocationListEnvelope {
        revocation_list: body,
        signature: sig.into_string(),
    })
}

/// Parse an on-wire revocation snapshot with RFC-AITP-0001 §7's
/// unknown-member rejection applied.
///
/// Per RFC-AITP-0008 §1.5 (as amended), `UNKNOWN_FIELD` applies to **both**
/// levels of this artifact — the envelope and the inner `revocation_list`
/// body — unlike the session bundle, whose wrapper- and body-level
/// violations report distinct error classes. There is deliberately no
/// wrapper/body split here.
///
/// Order of operations:
/// 1. [`check_members`] the envelope against
///    [`REVOCATION_ENVELOPE_MEMBERS`] (`{revocation_list, signature}`).
/// 2. If a `revocation_list` member is present, [`check_members`] it
///    against [`REVOCATION_LIST_MEMBERS`].
/// 3. `serde_json::from_value` into [`RevocationListEnvelope`]. A residual
///    serde error — which, now that both top-level member sets have
///    already passed, can only come from a nested closed object (a member
///    of `entries[]`) — is recovered via [`from_serde_error`] so it, too,
///    reports [`TctError::UnknownField`] rather than a generic parse
///    failure.
pub fn parse_revocation_snapshot_wire(
    value: &serde_json::Value,
) -> Result<RevocationListEnvelope, TctError> {
    check_members("RevocationListEnvelope", value, REVOCATION_ENVELOPE_MEMBERS)
        .map_err(|e| TctError::UnknownField(e.field))?;

    if let Some(body) = value.get("revocation_list") {
        check_members("RevocationList", body, REVOCATION_LIST_MEMBERS)
            .map_err(|e| TctError::UnknownField(e.field))?;
    }

    serde_json::from_value(value.clone()).map_err(|e| {
        if let Some(field) = from_serde_error(&e) {
            TctError::UnknownField(field)
        } else {
            TctError::ClaimsMalformed(e.to_string())
        }
    })
}

/// Verify a [`RevocationListEnvelope`].
///
/// 1. `revocation_list.version` equals the supported protocol version, else
///    [`TctError::VersionUnknown`]. Checked first, so an unsupported snapshot
///    reports its version rather than a downstream signature failure.
/// 2. `revocation_list.expires_at >= ctx.now` — else `TctError::Expired`.
/// 3. `revocation_list.issuer` equals `ctx.expected_issuer`, else
///    [`TctError::IssuerMismatch`]. This previously returned `CnfMalformed`
///    "rather than introducing a new error variant for v0.1" — but
///    `IssuerMismatch` was added later for TCTs and documents exactly this
///    case (RFC-AITP-0008 §3.3's issuer-key binding). Reporting it as
///    `CnfMalformed` conflated "this snapshot is from the wrong issuer" with
///    "this snapshot is malformed", which a caller cannot separate and which
///    a binding cannot surface as distinct causes.
/// 4. `signature` is present and verifies under that public key over
///    `sha256(JCS(revocation_list))` — the inner body; see
///    [`revocation_signing_bytes`].
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
        return Err(TctError::IssuerMismatch);
    }

    let pubkey =
        AitpVerifyingKey::from_aid(&envelope.revocation_list.issuer).map_err(TctError::Crypto)?;
    let sig = Signature::parse(&envelope.signature).map_err(|_| TctError::SignatureInvalid)?;

    let canonical = revocation_signing_bytes(&envelope.revocation_list)?;
    pubkey
        .verify(&Sha256::digest(&canonical), &sig)
        .map_err(|_| TctError::SignatureInvalid)?;
    Ok(())
}

/// Context for [`verify_revocation_list`].
///
/// `#[non_exhaustive]`: construct with [`VerifyRevocationListContext::new`]
/// rather than a struct literal. Without it, every future verification
/// knob — a policy, a clock-skew allowance, a trust-anchor set — would be
/// a breaking change for every downstream crate. Adding it costs one
/// migration now instead of a dedicated breaking release later.
#[non_exhaustive]
pub struct VerifyRevocationListContext<'a> {
    /// The AID the verifier expects this snapshot to be from.
    pub expected_issuer: &'a Aid,
    /// Verifier's clock for `expires_at` check.
    pub now: Timestamp,
}

impl<'a> VerifyRevocationListContext<'a> {
    /// A context pinning the expected issuer and the verifier's clock.
    pub fn new(expected_issuer: &'a Aid, now: Timestamp) -> Self {
        Self {
            expected_issuer,
            now,
        }
    }
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
            extensions: None,
        }
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let key = issuer_key();
        let env = sign_revocation_list(sample_body(key.aid().clone()), &key).unwrap();
        let ctx = VerifyRevocationListContext::new(key.aid(), Timestamp(1_700_001_000));
        verify_revocation_list(&env, &ctx).expect("fresh snapshot verifies");
    }

    #[test]
    fn expired_is_rejected() {
        let key = issuer_key();
        let env = sign_revocation_list(sample_body(key.aid().clone()), &key).unwrap();
        let ctx = VerifyRevocationListContext::new(key.aid(), Timestamp(1_700_999_999));
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
        let ctx = VerifyRevocationListContext::new(other.aid(), Timestamp(1_700_001_000));
        assert!(matches!(
            verify_revocation_list(&env, &ctx),
            Err(TctError::IssuerMismatch)
        ));
    }

    /// The snapshot is internally valid — correctly self-signed, unexpired,
    /// right version — and is rejected *only* because it is not from the
    /// issuer this verifier pinned. That has to be distinguishable from a
    /// malformed snapshot: a caller reporting "wrong issuer" and "garbage"
    /// as one cause cannot tell an attacker substituting their own signed
    /// list from a corrupt fetch. It reported `CnfMalformed` until 0.6.0.
    #[test]
    fn wrong_issuer_is_distinguishable_from_malformed() {
        let key = issuer_key();
        let env = sign_revocation_list(sample_body(key.aid().clone()), &key).unwrap();
        let other = AitpSigningKey::from_seed(&[0xB0; 32]);
        let ctx = VerifyRevocationListContext::new(other.aid(), Timestamp(1_700_001_000));

        // Self-consistent: it verifies against its own issuer.
        let own_ctx = VerifyRevocationListContext::new(key.aid(), Timestamp(1_700_001_000));
        verify_revocation_list(&env, &own_ctx).expect("snapshot is internally valid");

        match verify_revocation_list(&env, &ctx) {
            Err(TctError::IssuerMismatch) => {}
            other => panic!("expected IssuerMismatch, got {other:?}"),
        }
    }

    #[test]
    fn empty_entries_round_trips() {
        let key = issuer_key();
        let mut body = sample_body(key.aid().clone());
        body.entries.clear();
        let env = sign_revocation_list(body, &key).unwrap();
        let ctx = VerifyRevocationListContext::new(key.aid(), Timestamp(1_700_001_000));
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

    /// The AID pinned for a KAT keypair, read from the vendored
    /// `keypairs.json` rather than derived from the artifact under test.
    fn kat_keypair_aid(id: &str) -> Aid {
        let kp: serde_json::Value =
            serde_json::from_slice(&std::fs::read(vendored("known-answer/keypairs.json")).unwrap())
                .unwrap();
        let aid = kp["vectors"]
            .as_array()
            .expect("vectors array")
            .iter()
            .find(|v| v["id"].as_str() == Some(id))
            .unwrap_or_else(|| panic!("keypair {id} missing from keypairs.json"))["aid"]
            .as_str()
            .unwrap_or_else(|| panic!("keypair {id} has no `aid`"))
            .to_owned();
        Aid::parse(&aid).expect("pinned AID parses")
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
        // Drive the SHARED signing-input helper, not a local reconstruction:
        // this test must not be able to go green while the production
        // sign/verify path canonicalizes something else.
        let canonical = revocation_signing_bytes(&body).unwrap();

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

        // Take the expected issuer from the KAT keypair vector, NOT from the
        // envelope being verified. Deriving it from `env` would make the
        // issuer-binding half of `verify_revocation_list` tautological: a
        // snapshot whose `issuer` had been swapped (with a matching
        // signature) would still pass.
        let issuer = kat_keypair_aid("kat-keypair-001");
        let ctx = VerifyRevocationListContext::new(&issuer, Timestamp(1_711_900_100));
        verify_revocation_list(&env, &ctx)
            .expect("committed spec signed example must verify as committed");
    }

    /// The committed signature must NOT verify over the wrapped form.
    ///
    /// The positive test alone pins nothing: a signature valid over both
    /// shapes would satisfy it while leaving the convention undetermined.
    /// This is the assertion that fails if `revocation_signing_bytes` ever
    /// starts canonicalizing `{"revocation_list": …}` again.
    #[test]
    fn spec_signed_example_rejects_the_wrapped_form() {
        let raw = std::fs::read(vendored(
            "known-answer/signed-examples/revocation/kat-keypair-001-snapshot.json",
        ))
        .expect("read committed signed example");
        let mut value: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        value.as_object_mut().unwrap().remove("_kat_input");
        let env: RevocationListEnvelope = serde_json::from_value(value).unwrap();

        let wrapped = serde_json::json!({ "revocation_list": &env.revocation_list });
        let canonical = jcs::canonicalize(&wrapped).expect("canonicalize wrapped");
        let pubkey = AitpVerifyingKey::from_aid(&env.revocation_list.issuer).unwrap();
        let sig = Signature::parse(&env.signature).unwrap();

        assert!(
            pubkey.verify(&Sha256::digest(&canonical), &sig).is_err(),
            "signature verified over the WRAPPED form — the transport wrapper \
             is being signed (RFC-AITP-0001 §5.4.1, RFC-AITP-0008 §1.5)"
        );
    }

    /// A snapshot signed over the wrapped form must be rejected outright.
    ///
    /// Per DECISIONS.md D1 there is no dual-accept: RFC-AITP-0008 §1.5
    /// permits a transition window, but RFC-AITP-0010 grants none for the
    /// session bundle, so a half-measure would leave the two artifacts
    /// inconsistent. This locks the strict posture in place.
    #[test]
    fn wrapped_signed_snapshot_is_rejected() {
        let key = issuer_key();
        let body = sample_body(key.aid().clone());

        // Sign the legacy wrapped form deliberately.
        let wrapped = serde_json::json!({ "revocation_list": &body });
        let canonical = jcs::canonicalize(&wrapped).unwrap();
        let legacy_sig = key.sign(&Sha256::digest(&canonical)).into_string();

        let env = RevocationListEnvelope {
            revocation_list: body,
            signature: legacy_sig,
        };
        let ctx = VerifyRevocationListContext::new(key.aid(), Timestamp(1_700_001_000));
        assert!(
            matches!(
                verify_revocation_list(&env, &ctx),
                Err(TctError::SignatureInvalid)
            ),
            "a wrapped-signed snapshot must be rejected with SignatureInvalid"
        );
    }

    // ---- Phase 4: `extensions` slot + member-set check --------------------

    /// Absent vs. present-but-empty `extensions` must canonicalize to
    /// different bytes (mirrors the envelope's and manifest's round-trip
    /// test for the same `Option<ExtensionsMap>` shape).
    #[test]
    fn absent_and_empty_extensions_round_trip_distinctly() {
        let key = issuer_key();
        let mut absent = sample_body(key.aid().clone());
        absent.extensions = None;
        let absent_json = serde_json::to_value(&absent).unwrap();
        assert!(
            absent_json.get("extensions").is_none(),
            "absent extensions must emit no `extensions` key at all"
        );

        let mut present_empty = sample_body(key.aid().clone());
        present_empty.extensions = Some(ExtensionsMap::new());
        let present_json = serde_json::to_value(&present_empty).unwrap();
        assert_eq!(present_json["extensions"], serde_json::json!({}));

        // Round-trips.
        let parsed_absent: RevocationList = serde_json::from_value(absent_json).unwrap();
        assert_eq!(parsed_absent.extensions, None);
        let parsed_present: RevocationList = serde_json::from_value(present_json).unwrap();
        assert_eq!(parsed_present.extensions, Some(ExtensionsMap::new()));

        // Different bytes, hence different signing input.
        let absent_bytes = revocation_signing_bytes(&absent).unwrap();
        let present_bytes = revocation_signing_bytes(&present_empty).unwrap();
        assert_ne!(
            absent_bytes, present_bytes,
            "absent and present-but-empty extensions must NOT canonicalize identically"
        );
    }

    /// **Non-negotiable correctness gate.** `revocation_signing_bytes` for a
    /// body with `extensions: None` must be byte-identical to what it
    /// produced before this field existed — a `RevocationList` value built
    /// exactly as the pre-Phase-4 struct literal would have, with no
    /// `extensions` field to omit. This is a belt-and-braces companion to
    /// `rfc_kat_canonical_bytes_match` and `spec_signed_example_snapshot_verifies`,
    /// which already pin the exact digests: if this test and those two both
    /// pass, the field was modeled correctly (`Option` + `skip_serializing_if`
    /// keeping the omitted case wire-identical to "the field never existed").
    #[test]
    fn signing_bytes_for_none_extensions_omit_the_key_entirely() {
        let key = issuer_key();
        let body = sample_body(key.aid().clone());
        assert_eq!(body.extensions, None);
        let canonical = revocation_signing_bytes(&body).unwrap();
        let as_str = String::from_utf8(canonical).unwrap();
        assert!(
            !as_str.contains("extensions"),
            "signing bytes for extensions:None must contain no `extensions` member: {as_str}"
        );
    }

    /// rev-005 equivalent: an unknown member in the wrapper is rejected as
    /// `UnknownField`, at the envelope level.
    #[test]
    fn unknown_member_in_envelope_is_rejected() {
        let key = issuer_key();
        let env = sign_revocation_list(sample_body(key.aid().clone()), &key).unwrap();
        let mut value = serde_json::to_value(&env).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("rogue".into(), serde_json::json!("nope"));

        match parse_revocation_snapshot_wire(&value) {
            Err(TctError::UnknownField(field)) => assert_eq!(field, "rogue"),
            other => panic!("expected UnknownField(\"rogue\"), got {other:?}"),
        }
    }

    /// rev-005 equivalent: an unknown member of the inner `revocation_list`
    /// body is rejected as `UnknownField` too — RFC-AITP-0008 §1.5 assigns
    /// `UNKNOWN_FIELD` to both levels of this artifact, unlike the session
    /// bundle.
    #[test]
    fn unknown_member_in_body_is_rejected() {
        let key = issuer_key();
        let env = sign_revocation_list(sample_body(key.aid().clone()), &key).unwrap();
        let mut value = serde_json::to_value(&env).unwrap();
        value["revocation_list"]
            .as_object_mut()
            .unwrap()
            .insert("rogue".into(), serde_json::json!("nope"));

        match parse_revocation_snapshot_wire(&value) {
            Err(TctError::UnknownField(field)) => assert_eq!(field, "rogue"),
            other => panic!("expected UnknownField(\"rogue\"), got {other:?}"),
        }
    }

    /// An unknown member nested inside `entries[]` is caught by
    /// `from_serde_error` recovering from the residual
    /// `#[serde(deny_unknown_fields)]` failure on `RevocationEntry`, since
    /// the top-level member-set check never looks inside array elements.
    #[test]
    fn unknown_member_inside_entries_is_rejected_via_from_serde_error() {
        let key = issuer_key();
        let env = sign_revocation_list(sample_body(key.aid().clone()), &key).unwrap();
        let mut value = serde_json::to_value(&env).unwrap();
        value["revocation_list"]["entries"][0]
            .as_object_mut()
            .unwrap()
            .insert("rogue".into(), serde_json::json!("nope"));

        match parse_revocation_snapshot_wire(&value) {
            Err(TctError::UnknownField(field)) => assert_eq!(field, "rogue"),
            other => panic!("expected UnknownField(\"rogue\"), got {other:?}"),
        }
    }

    /// rev-006 equivalent: a snapshot with a legitimate `extensions` member
    /// (both at rest and after a wire round-trip) is accepted.
    #[test]
    fn snapshot_with_extensions_is_accepted() {
        let key = issuer_key();
        let mut body = sample_body(key.aid().clone());
        let mut ext = ExtensionsMap::new();
        ext.insert(
            "vendor.example/feature",
            serde_json::json!({"enabled": true}),
        );
        body.extensions = Some(ext);
        let env = sign_revocation_list(body, &key).unwrap();
        let value = serde_json::to_value(&env).unwrap();

        let parsed = parse_revocation_snapshot_wire(&value)
            .expect("a snapshot with a declared `extensions` member must parse");
        let ctx = VerifyRevocationListContext::new(key.aid(), Timestamp(1_700_001_000));
        verify_revocation_list(&parsed, &ctx)
            .expect("a snapshot with extensions must still verify");
    }

    /// `rev-004` must keep reporting the crypto failure, not `UnknownField`
    /// — a tampered signature is a different failure class from a
    /// structural member-set violation, and the two must stay
    /// distinguishable through `parse_revocation_snapshot_wire` +
    /// `verify_revocation_list`.
    #[test]
    fn tampered_signature_still_reports_signature_invalid_not_unknown_field() {
        let key = issuer_key();
        let env = sign_revocation_list(sample_body(key.aid().clone()), &key).unwrap();
        let mut value = serde_json::to_value(&env).unwrap();
        // Flip the signature to something else well-formed-looking but wrong.
        value["signature"] = serde_json::json!(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        );

        let parsed =
            parse_revocation_snapshot_wire(&value).expect("well-formed shape still parses");
        let ctx = VerifyRevocationListContext::new(key.aid(), Timestamp(1_700_001_000));
        assert!(
            matches!(
                verify_revocation_list(&parsed, &ctx),
                Err(TctError::SignatureInvalid)
            ),
            "tampered signature must report SignatureInvalid, not UnknownField"
        );
    }

    /// `REVOCATION_LIST_MEMBERS` must equal the vendored schema's
    /// `properties.revocation_list.properties` keys — the drift firewall
    /// lives in `tests/schema.rs`, this is the quick smoke check that the
    /// const at least contains the field this phase added.
    #[test]
    fn revocation_list_members_includes_extensions() {
        assert!(REVOCATION_LIST_MEMBERS.contains(&"extensions"));
        assert!(REVOCATION_ENVELOPE_MEMBERS.contains(&"revocation_list"));
        assert!(REVOCATION_ENVELOPE_MEMBERS.contains(&"signature"));
    }
}
