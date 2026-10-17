//! Proposal agentidentitytrustprotocol#72 Items 5 and 6b: the strict v4
//! `jti` / `src_jti` layout, the `ext` and `jti` builder setters, and the
//! self-attestation profile (marker grant `aitp.attestation`).

use aitp_core::ids::{derived_v4, V4Error};
use aitp_core::{Aid, Timestamp};
use aitp_crypto::{jws, AitpSigner, AitpSigningKey};
use aitp_tct::{
    verify_attestation, verify_tct, verify_voucher, AttestationVerifyContext, TctBuilder, TctError,
    TctVerifyContext, TctVerifyContextError, ATTESTATION_GRANT,
};
use serde_json::{json, Map, Value};
use uuid::Uuid;

const NOW: Timestamp = Timestamp(1_711_900_000);
const HUNDRED_YEARS: i64 = 3_155_760_000;
const V7: &str = "01890a5d-ac96-774b-bcce-b302099a8057";
/// Version nibble 4, variant bits `11` (Microsoft).
const BAD_VARIANT: &str = "770e8400-e29b-41d4-c716-446655440702";

fn ed(seed: u8) -> AitpSigningKey {
    AitpSigningKey::from_seed(&[seed; 32])
}

fn p256(seed: u8) -> AitpSigningKey {
    AitpSigningKey::from_p256_seed(&[seed; 32]).unwrap()
}

fn ctx<'a>(aud: &'a Aid, iss: &'a Aid) -> TctVerifyContext<'a> {
    TctVerifyContext::builder(aud, iss, NOW)
        .accept_unchecked_revocation_dangerous()
        .skip_manifest_expiry_cap_dangerous()
        .build()
        .unwrap()
}

fn statement(kat: &str) -> Map<String, Value> {
    json!({"org.aitp.kat": {"statement": format!("{kat} archival attestation")}})
        .as_object()
        .unwrap()
        .clone()
}

/// Valid TCT claims from `issuer` for `subject`, as raw JSON for forging.
fn claims(issuer: &AitpSigningKey, subject: &AitpSigningKey) -> Value {
    json!({
        "ver": "aitp/0.2",
        "jti": "770e8400-e29b-41d4-a716-446655440702",
        "iss": issuer.aid(),
        "sub": subject.aid(),
        "aud": subject.aid(),
        "iat": NOW.0,
        "exp": NOW.0 + 3600,
        "grants": ["demo.echo"],
        "cnf": {"jkt": subject.verifying_key().to_jwk_thumbprint().unwrap()},
    })
}

fn forge(issuer: &AitpSigningKey, claims: &Value) -> String {
    jws::sign_compact(issuer, jws::TYP_TCT, claims).unwrap()
}

/// Break the signature so a check that fires first is provably
/// pre-signature.
fn break_sig(token: &str) -> String {
    let (head, sig) = token.rsplit_once('.').unwrap();
    let flipped = if sig.starts_with('A') { 'B' } else { 'A' };
    format!("{head}.{flipped}{}", &sig[1..])
}

fn base<'a>(issuer: &'a dyn AitpSigner, subject: &AitpSigningKey) -> TctBuilder<'a> {
    TctBuilder::new(issuer)
        .subject(subject.aid().clone())
        .audience(subject.aid().clone())
        .grants(["demo.echo"])
        .subject_pubkey(subject.verifying_key())
        .issued_at(NOW)
}

// --- Item 6b: jti layout --------------------------------------------------

#[test]
fn builder_jti_setter_validates_v4() {
    let (iss, sub) = (ed(1), ed(2));
    for (bad, want) in [(V7, V4Error::Version), (BAD_VARIANT, V4Error::Variant)] {
        let err = base(&iss, &sub)
            .jti(Uuid::parse_str(bad).unwrap())
            .build()
            .unwrap_err();
        assert!(
            matches!(err, TctError::JtiNotV4(e) if e == want),
            "{bad}: {err:?}"
        );
    }
    let ok = Uuid::new_v4();
    assert_eq!(base(&iss, &sub).jti(ok).build().unwrap().claims.jti, ok);
}

#[test]
fn derived_jti_setter_matches_item_6b_and_rejects_bad_tags() {
    let (iss, sub) = (ed(1), ed(2));
    let issued = base(&iss, &sub)
        .derived_jti("com.example.decision-commit", b"record-42")
        .build()
        .unwrap();
    assert_eq!(
        issued.claims.jti,
        derived_v4("com.example.decision-commit", b"record-42").unwrap()
    );
    // The voucher's src_jti follows.
    let v = verify_voucher(issued.voucher.as_deref().unwrap(), iss.aid()).unwrap();
    assert_eq!(v.src_jti, issued.claims.jti);

    let err = base(&iss, &sub)
        .derived_jti("has space", b"x")
        .build()
        .unwrap_err();
    assert!(matches!(err, TctError::InvalidJtiTag), "{err:?}");
}

#[test]
fn verify_rejects_non_v4_jti_before_signature() {
    let (iss, sub) = (ed(1), ed(2));
    for (bad, want) in [
        (V7, V4Error::Version),
        (BAD_VARIANT, V4Error::Variant),
        ("770E8400-E29B-41D4-A716-446655440702", V4Error::Format),
        ("{770e8400-e29b-41d4-a716-446655440702}", V4Error::Format),
    ] {
        let mut c = claims(&iss, &sub);
        c["jti"] = json!(bad);
        let token = break_sig(&forge(&iss, &c));
        let err = verify_tct(&token, &ctx(sub.aid(), iss.aid())).unwrap_err();
        assert!(
            matches!(err, TctError::JtiNotV4(e) if e == want),
            "{bad}: {err:?}"
        );
    }
}

#[test]
fn verify_voucher_rejects_non_v4_src_jti() {
    let iss = ed(1);
    let sub = ed(2);
    let voucher = json!({
        "ver": "aitp/0.2", "iss": iss.aid(), "sub": sub.aid(), "grants": ["demo.echo"],
        "iat": NOW.0, "exp": NOW.0 + 3600, "src_jti": V7,
    });
    let token = jws::sign_compact(&iss, jws::TYP_GRANT_VOUCHER, &voucher).unwrap();
    let err = verify_voucher(&break_sig(&token), iss.aid()).unwrap_err();
    assert!(
        matches!(err, TctError::JtiNotV4(V4Error::Version)),
        "{err:?}"
    );
}

// --- Item 7c: ext setter --------------------------------------------------

#[test]
fn ext_setter_is_signed_and_round_trips() {
    let (iss, sub) = (p256(3), ed(2));
    let ext = statement("ext");
    let issued = base(&iss, &sub).ext(ext.clone()).build().unwrap();
    let v = verify_tct(&issued.token, &ctx(sub.aid(), iss.aid())).unwrap();
    assert_eq!(v.claims.ext.as_ref(), Some(&ext));
    // The voucher mirrors the TCT and stays ext-free.
    let voucher = verify_voucher(issued.voucher.as_deref().unwrap(), iss.aid()).unwrap();
    assert_eq!(voucher.ext, None);
}

// --- Item 5: grant context ------------------------------------------------

#[test]
fn grant_context_rejects_self_issued_tct() {
    let iss = ed(1);
    let token = forge(&iss, &claims(&iss, &iss));
    let err = verify_tct(&token, &ctx(iss.aid(), iss.aid())).unwrap_err();
    assert!(matches!(err, TctError::SelfIssued), "{err:?}");
    // The issuer refuses to mint one, too.
    let err = base(&iss, &iss).build().unwrap_err();
    assert!(matches!(err, TctError::SelfIssued), "{err:?}");
}

#[test]
fn grant_context_rejects_attestation_marker_with_distinct_iss() {
    let (iss, sub) = (ed(1), ed(2));
    let mut c = claims(&iss, &sub);
    c["grants"] = json!([ATTESTATION_GRANT, "demo.echo"]);
    let err = verify_tct(&forge(&iss, &c), &ctx(sub.aid(), iss.aid())).unwrap_err();
    assert!(matches!(err, TctError::AttestationMarker), "{err:?}");
    let err = base(&iss, &sub)
        .grants([ATTESTATION_GRANT])
        .build()
        .unwrap_err();
    assert!(matches!(err, TctError::AttestationMarker), "{err:?}");
}

#[test]
fn grant_context_rejects_a_valid_attestation() {
    let iss = p256(5);
    let issued = TctBuilder::new(&iss)
        .self_attestation()
        .ext(statement("x"))
        .issued_at(NOW)
        .build()
        .unwrap();
    assert!(verify_tct(&issued.token, &ctx(iss.aid(), iss.aid())).is_err());
}

// --- Item 5: attestation profile -------------------------------------------

fn attestation_ctx<'a>(iss: &'a Aid, key: &'a str) -> AttestationVerifyContext<'a> {
    AttestationVerifyContext::builder(iss, key, NOW)
        .waive_manifest_cap_issuer_has_no_manifest()
        .accept_unchecked_revocation_dangerous()
        .build()
        .unwrap()
}

#[test]
fn self_attestation_round_trip() {
    for iss in [ed(0), p256(5)] {
        let issued = TctBuilder::new(&iss)
            .self_attestation()
            .ext(statement("rt"))
            .ttl_secs(HUNDRED_YEARS)
            .issued_at(NOW)
            .build()
            .unwrap();
        assert!(issued.voucher.is_none(), "an attestation confers nothing");
        assert_eq!(issued.claims.grants, [ATTESTATION_GRANT]);
        assert_eq!(issued.claims.sub, *iss.aid());

        let v =
            verify_attestation(&issued.token, &attestation_ctx(iss.aid(), "org.aitp.kat")).unwrap();
        assert_eq!(v.statement, json!({"statement": "rt archival attestation"}));

        let err = verify_attestation(&issued.token, &attestation_ctx(iss.aid(), "org.other"))
            .unwrap_err();
        assert!(
            matches!(&err, TctError::AttestationStatementMissing(k) if k == "org.other"),
            "{err:?}"
        );
    }
}

#[test]
fn attestation_requires_ext() {
    let iss = ed(1);
    let err = TctBuilder::new(&iss)
        .self_attestation()
        .issued_at(NOW)
        .build()
        .unwrap_err();
    assert!(matches!(err, TctError::MissingField("ext")), "{err:?}");
}

#[test]
fn attestation_verifier_rejects_grant_tcts() {
    let (iss, sub) = (ed(1), ed(2));
    let grant = base(&iss, &sub).ext(statement("g")).build().unwrap();
    let err =
        verify_attestation(&grant.token, &attestation_ctx(iss.aid(), "org.aitp.kat")).unwrap_err();
    assert!(matches!(err, TctError::NotAttestation), "{err:?}");
}

#[test]
fn attestation_manifest_cap_is_an_explicit_decision() {
    let iss = ed(1);
    let err = AttestationVerifyContext::builder(iss.aid(), "k", NOW)
        .accept_unchecked_revocation_dangerous()
        .build()
        .unwrap_err();
    assert_eq!(err, TctVerifyContextError::ManifestCapDecisionRequired);
    let err = AttestationVerifyContext::builder(iss.aid(), "k", NOW)
        .waive_manifest_cap_issuer_has_no_manifest()
        .build()
        .unwrap_err();
    assert_eq!(err, TctVerifyContextError::RevocationDecisionRequired);

    // With a Manifest, the cap applies.
    let issued = TctBuilder::new(&iss)
        .self_attestation()
        .ext(statement("cap"))
        .ttl_secs(HUNDRED_YEARS)
        .issued_at(NOW)
        .build()
        .unwrap();
    let capped = AttestationVerifyContext::builder(iss.aid(), "org.aitp.kat", NOW)
        .issuer_manifest_expires_at(NOW.plus_secs(86_400))
        .accept_unchecked_revocation_dangerous()
        .build()
        .unwrap();
    assert!(matches!(
        verify_attestation(&issued.token, &capped),
        Err(TctError::ExpiresAfterManifest)
    ));
}

#[test]
fn attestation_revocation_is_consulted() {
    let iss = ed(1);
    let issued = TctBuilder::new(&iss)
        .self_attestation()
        .ext(statement("rev"))
        .issued_at(NOW)
        .build()
        .unwrap();
    let revoked = |_: &Uuid| true;
    let c = AttestationVerifyContext::builder(iss.aid(), "org.aitp.kat", NOW)
        .waive_manifest_cap_issuer_has_no_manifest()
        .revocation_check(&revoked)
        .build()
        .unwrap();
    assert!(matches!(
        verify_attestation(&issued.token, &c),
        Err(TctError::Revoked)
    ));
}

// --- KATs -----------------------------------------------------------------

/// A vendored spec signed example under `known-answer/signed-examples/tct/`.
fn kat(file: &str) -> Value {
    let path = format!(
        "{}/../../tests/schemas/known-answer/signed-examples/tct/{file}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// The builder reproduces kat-tct-002 / kat-tct-003 byte for byte, the
/// attestation verifier accepts them, and every grant context refuses
/// them.
#[test]
fn self_attestation_kats_reproduce() {
    for (file, key) in [
        ("kat-keypair-001-self-attestation", ed(0)),
        ("kat-keypair-005-self-attestation", p256(5)),
    ] {
        let v = kat(file);
        let input = &v["_kat_input"];
        let id = input["vector_id"].as_str().unwrap();
        let d = &input["jti_derivation"];
        let iat = input["iat"].as_i64().unwrap();
        let issued = TctBuilder::new(&key)
            .self_attestation()
            .derived_jti(
                d["tag"].as_str().unwrap(),
                d["input"].as_str().unwrap().as_bytes(),
            )
            .ext(input["ext"].as_object().unwrap().clone())
            .ttl_secs(input["exp"].as_i64().unwrap() - iat)
            .issued_at(Timestamp(iat))
            .build()
            .unwrap();
        assert_eq!(
            issued.claims.jti.to_string(),
            d["jti"].as_str().unwrap(),
            "{id}"
        );
        assert_eq!(
            serde_json::to_value(&issued.claims).unwrap(),
            v["decoded_claims"],
            "{id}"
        );
        assert_eq!(issued.token, v["tct_token"].as_str().unwrap(), "{id}");

        let ok = verify_attestation(&issued.token, &attestation_ctx(key.aid(), "org.aitp.kat"));
        assert!(ok.is_ok(), "{id}: {ok:?}");
        let err = verify_tct(&issued.token, &ctx(key.aid(), key.aid())).unwrap_err();
        assert!(matches!(err, TctError::SelfIssued), "{id}: {err:?}");
    }
}

/// kat-tct-003's `_must_not_verify.double_hash_jws`: ES256 hashes once,
/// so a signature over `sha256(sha256(signing_input))` is invalid.
#[test]
fn self_attestation_kat_003_double_hash_does_not_verify() {
    let v = kat("kat-keypair-005-self-attestation");
    let token = v["_must_not_verify"]["double_hash_jws"].as_str().unwrap();
    let key = p256(5);
    let err = verify_attestation(token, &attestation_ctx(key.aid(), "org.aitp.kat")).unwrap_err();
    assert!(
        matches!(err, TctError::SignatureInvalid | TctError::Crypto(_)),
        "{err:?}"
    );
}
