//! End-to-end Manifest issue + verify + tamper-detection.

use aitp_core::{jcs, ExtensionsMap, Timestamp};
use aitp_crypto::AitpSigningKey;
use aitp_manifest::{
    parse_manifest_wire, verify_manifest, IdentityHint, IdentityHintKind, ManifestBuilder,
    ManifestError, VerifyManifestContext,
};

fn alice_key() -> AitpSigningKey {
    AitpSigningKey::from_seed(&[1u8; 32])
}

fn build_alice_manifest_at(now: Timestamp) -> aitp_manifest::Manifest {
    let key = alice_key();
    ManifestBuilder::new(&key)
        .handshake_endpoint("https://alice.example.com/handshake".parse().unwrap())
        .identity_hint(IdentityHint {
            kind: IdentityHintKind::Oidc,
            subject: "alice".into(),
            issuer: Some("https://idp.example.com".parse().unwrap()),
            public_key: None,
        })
        .accept_trust_anchor("https://idp.example.com".parse().unwrap())
        .offer("demo.echo")
        .published_at(now)
        .ttl_secs(3600)
        .build()
        .expect("builder produces a manifest")
}

#[test]
fn happy_path_round_trip() {
    let now = Timestamp(1_700_000_000);
    let m = build_alice_manifest_at(now);
    verify_manifest(&m, &VerifyManifestContext { now }).expect("fresh manifest verifies");
}

#[test]
fn tampered_outer_signature_fails() {
    let now = Timestamp(1_700_000_000);
    let mut m = build_alice_manifest_at(now);
    let mut s = m.signature.clone();
    let last = s.pop().unwrap();
    s.push(if last == 'A' { 'B' } else { 'A' });
    m.signature = s;
    let err = verify_manifest(&m, &VerifyManifestContext { now }).unwrap_err();
    assert!(
        matches!(err, ManifestError::SignatureInvalid),
        "got: {:?}",
        err
    );
}

#[test]
fn tampered_pop_signature_fails() {
    let now = Timestamp(1_700_000_000);
    let mut m = build_alice_manifest_at(now);
    let mut s = m.proof_of_possession.signature.clone();
    let last = s.pop().unwrap();
    s.push(if last == 'A' { 'B' } else { 'A' });
    m.proof_of_possession.signature = s;
    let err = verify_manifest(&m, &VerifyManifestContext { now }).unwrap_err();
    // Tampering the PoP signature also invalidates the outer
    // signature, which covers it; PoP is checked first.
    assert!(matches!(err, ManifestError::PopFailed), "got: {err:?}");
}

#[test]
fn tampered_pop_challenge_fails() {
    let now = Timestamp(1_700_000_000);
    let mut m = build_alice_manifest_at(now);
    // Mutate the challenge — sha256(challenge) input changes, PoP fails.
    let bytes = m.proof_of_possession.challenge.as_bytes();
    let mut chars: Vec<u8> = bytes.to_vec();
    chars[0] ^= 1; // still a base64url char (A↔B etc when in range)
    if !chars[0].is_ascii_alphanumeric() {
        chars[0] = b'B';
    }
    m.proof_of_possession.challenge = String::from_utf8(chars).unwrap();
    let err = verify_manifest(&m, &VerifyManifestContext { now }).unwrap_err();
    // Tampering the challenge invalidates BOTH the pop_signature
    // and the outer signature; PoP is checked first.
    assert!(matches!(err, ManifestError::PopFailed), "got: {err:?}");
}

#[test]
fn expired_fails() {
    let issued = Timestamp(1_700_000_000);
    let m = build_alice_manifest_at(issued);
    let later = Timestamp(1_700_000_000 + 7200); // 2h after issuance, TTL was 1h
    let err = verify_manifest(&m, &VerifyManifestContext { now: later }).unwrap_err();
    assert!(matches!(err, ManifestError::Expired), "got: {:?}", err);
}

#[test]
fn unknown_version_fails() {
    let now = Timestamp(1_700_000_000);
    let mut m = build_alice_manifest_at(now);
    m.version = "aitp/9.9".into();
    let err = verify_manifest(&m, &VerifyManifestContext { now }).unwrap_err();
    assert!(
        matches!(err, ManifestError::VersionUnknown),
        "got: {:?}",
        err
    );
}

#[test]
fn empty_extensions_omitted_from_canonical_form() {
    let now = Timestamp(1_700_000_000);
    let m = build_alice_manifest_at(now);
    let s = serde_json::to_string(&m).unwrap();
    assert!(
        !s.contains("\"extensions\":"),
        "empty extensions must not serialize: {}",
        s
    );
}

#[test]
fn pinned_key_manifest_round_trips() {
    let key = alice_key();
    let pubkey_b64 = aitp_core::base64url::encode(
        &key.verifying_key()
            .try_to_ed25519_bytes()
            .expect("key was constructed as Ed25519, never P-256"),
    );
    let now = Timestamp(1_700_000_000);
    let m = ManifestBuilder::new(&key)
        .handshake_endpoint("https://alice.example.com/handshake".parse().unwrap())
        .identity_hint(IdentityHint {
            kind: IdentityHintKind::PinnedKey,
            subject: "internal-1".into(),
            issuer: None,
            public_key: Some(pubkey_b64),
        })
        .accept_trust_anchor("https://idp.example.com".parse().unwrap())
        .offer("demo.echo")
        .published_at(now)
        .build()
        .unwrap();
    verify_manifest(&m, &VerifyManifestContext { now }).unwrap();
}

#[test]
fn builder_rejects_missing_handshake_endpoint() {
    let key = alice_key();
    let err = ManifestBuilder::new(&key)
        .identity_hint(IdentityHint {
            kind: IdentityHintKind::Oidc,
            subject: "x".into(),
            issuer: Some("https://idp.example.com".parse().unwrap()),
            public_key: None,
        })
        .build()
        .unwrap_err();
    assert!(matches!(
        err,
        ManifestError::MissingField("handshake_endpoint")
    ));
}

#[test]
fn builder_rejects_oidc_with_pubkey() {
    let key = alice_key();
    let err = ManifestBuilder::new(&key)
        .handshake_endpoint("https://x".parse().unwrap())
        .identity_hint(IdentityHint {
            kind: IdentityHintKind::Oidc,
            subject: "x".into(),
            issuer: Some("https://idp.example.com".parse().unwrap()),
            public_key: Some("A".repeat(43)),
        })
        .build()
        .unwrap_err();
    assert!(matches!(err, ManifestError::IdentityHintMalformed(_)));
}

#[test]
fn builder_rejects_pinned_without_pubkey() {
    let key = alice_key();
    let err = ManifestBuilder::new(&key)
        .handshake_endpoint("https://x".parse().unwrap())
        .identity_hint(IdentityHint {
            kind: IdentityHintKind::PinnedKey,
            subject: "x".into(),
            issuer: None,
            public_key: None,
        })
        .build()
        .unwrap_err();
    assert!(matches!(err, ManifestError::IdentityHintMalformed(_)));
}

#[test]
fn pop_corruption_surfaces_as_pop_failed_not_signature_invalid() {
    // `proof_of_possession` is part of the outer-signed view, so
    // corrupting only the PoP signature (without re-signing) breaks the
    // OUTER signature too. RFC-AITP-0003 §5 verifies PoP (step 4) before
    // the signature (step 5), so this MUST surface as `PopFailed`, never
    // `SignatureInvalid`.
    let now = Timestamp(1_700_000_000);
    let mut m = build_alice_manifest_at(now);
    // Replace the PoP signature with a different, well-formed Ed25519
    // signature (a self-sign over unrelated bytes) so it parses but does
    // not match — isolating verification (not a parse) failure.
    let other = AitpSigningKey::from_seed(&[2u8; 32]);
    m.proof_of_possession.signature = other
        .sign_jcs(&aitp_crypto::Digest32::sha256(b"unrelated"))
        .into_string();
    let err = verify_manifest(&m, &VerifyManifestContext { now }).unwrap_err();
    assert!(
        matches!(err, ManifestError::PopFailed),
        "PoP corruption must surface as PopFailed (PoP before signature), got: {err:?}"
    );
}

/// OQ1 gate. Before the `Manifest::extensions` `Option<ExtensionsMap>`
/// migration, `ExtensionsMap::is_empty` collapsed "absent" and
/// wire-present `"extensions":{}` onto the same skip decision, so a
/// manifest whose signature was minted over a body that literally
/// contained `"extensions":{}` would fail re-verification (the verifier's
/// signing view dropped the key the issuer's view had kept). This proves
/// the fixed round trip: take a builder-issued manifest (extensions
/// absent), inject a literal `"extensions":{}` into its wire JSON,
/// re-sign over that exact JSON with the same key (mirroring what a real
/// issuer publishing `"extensions":{}` would sign), and confirm
/// `verify_manifest` now accepts it.
#[test]
fn extensions_present_but_empty_now_verifies_end_to_end() {
    let key = alice_key();
    let now = Timestamp(1_700_000_000);
    let m = build_alice_manifest_at(now);

    let mut value = serde_json::to_value(&m).unwrap();
    {
        let obj = value.as_object_mut().unwrap();
        assert!(
            !obj.contains_key("extensions"),
            "builder-issued manifest must start with extensions absent"
        );
        obj.insert("extensions".into(), serde_json::json!({}));
        obj.remove("signature");
    }
    let canonical = jcs::canonicalize(&value).expect("canonicalize body with extensions:{}");
    let signature = key
        .sign_jcs(&aitp_crypto::Digest32::sha256(&canonical))
        .into_string();
    value
        .as_object_mut()
        .unwrap()
        .insert("signature".into(), serde_json::json!(signature));

    let republished: aitp_manifest::Manifest = serde_json::from_value(value).unwrap();
    assert_eq!(republished.extensions, Some(ExtensionsMap::new()));
    verify_manifest(&republished, &VerifyManifestContext { now })
        .expect("a manifest signed WITH \"extensions\":{} must now verify");
}

/// Ordering gate (RFC-AITP-0003 §5 step 2 precedes step 5): a manifest
/// carrying both an unknown top-level member AND a corrupted signature
/// must report `UnknownField`, never `SignatureInvalid` — proving
/// `parse_manifest_wire`'s member-set check truly runs before any
/// cryptographic work, not merely before `verify_manifest` is invoked in
/// the common case.
#[test]
fn unknown_field_precedes_signature_check_via_parse_manifest_wire() {
    let now = Timestamp(1_700_000_000);
    let m = build_alice_manifest_at(now);
    let mut value = serde_json::to_value(&m).unwrap();
    let obj = value.as_object_mut().unwrap();
    obj.insert("deployment_region".into(), serde_json::json!("us-east-1"));
    // Corrupt the signature too — if member-set checking ran second, this
    // would surface as SignatureInvalid instead.
    let mut sig = obj.get("signature").unwrap().as_str().unwrap().to_string();
    let last = sig.pop().unwrap();
    sig.push(if last == 'A' { 'B' } else { 'A' });
    obj.insert("signature".into(), serde_json::json!(sig));

    let err = parse_manifest_wire(&checked(&value)).unwrap_err();
    assert!(
        matches!(err, ManifestError::UnknownField(ref f) if f == "deployment_region"),
        "expected UnknownField(\"deployment_region\"), got: {err:?}"
    );
}

/// Issue #146: wire text goes `bytes -> CheckedJson -> parse_manifest_wire`.
/// A duplicate top-level key is rejected at the first step (so it can
/// never reach the parser); an unknown member passes it and is rejected
/// by the parser as `UnknownField`.
#[test]
fn wire_text_duplicate_key_and_unknown_field_are_both_rejected() {
    let m = build_alice_manifest_at(Timestamp(1_700_000_000));
    let good = serde_json::to_string(&m).unwrap();
    assert!(parse_manifest_wire(&good.parse().unwrap()).is_ok());

    let dup = good.replacen('{', r#"{"version":"aitp/0.3","#, 1);
    let err = dup.parse::<aitp_core::CheckedJson>().unwrap_err();
    assert!(
        err.to_string().contains("duplicate field `version`"),
        "{err}"
    );

    let unknown = good.replacen('{', r#"{"deployment_region":"us-east-1","#, 1);
    let err = parse_manifest_wire(&unknown.parse().unwrap()).unwrap_err();
    assert!(
        matches!(err, ManifestError::UnknownField(ref f) if f == "deployment_region"),
        "{err:?}"
    );
}

/// man-002 regression: an unrecognized *value* for a known member
/// (`version`) is a completely different failure class from an unknown
/// *member* — it must still report `VersionUnknown`, never
/// `UnknownField`. `parse_manifest_wire` must accept the body (its
/// member set is intact) and let `verify_manifest` reject the value.
#[test]
fn unknown_version_value_is_not_confused_with_unknown_field() {
    let now = Timestamp(1_700_000_000);
    let mut m = build_alice_manifest_at(now);
    m.version = "aitp/9.9".into();
    let value = serde_json::to_value(&m).unwrap();

    let parsed =
        parse_manifest_wire(&checked(&value)).expect("known member with an unknown value parses");
    let err = verify_manifest(&parsed, &VerifyManifestContext { now }).unwrap_err();
    assert!(matches!(err, ManifestError::VersionUnknown), "got: {err:?}");
}

/// Library-level accept test for the MUST-ignore half of §7: a junk key
/// nested inside `extensions` must never be reported as an unknown field
/// by `parse_manifest_wire` — it is never inspected below the top level.
#[test]
fn parse_manifest_wire_ignores_junk_key_inside_extensions() {
    let now = Timestamp(1_700_000_000);
    let m = build_alice_manifest_at(now);
    let mut value = serde_json::to_value(&m).unwrap();
    value.as_object_mut().unwrap().insert(
        "extensions".into(),
        serde_json::json!({"junk_key_of_any_shape": {"deeply": {"nested": true}}}),
    );
    let parsed =
        parse_manifest_wire(&checked(&value)).expect("junk key inside extensions must be ignored");
    assert!(parsed.extensions.is_some());
}

/// `parse_manifest_wire` must also accept the `{"manifest": {...}}` HTTP
/// transport wrapper (RFC-AITP-0003 §6.1), checking the wrapper's own
/// member set (`["manifest"]`) in addition to the inner body's.
#[test]
fn parse_manifest_wire_accepts_the_transport_wrapper() {
    let now = Timestamp(1_700_000_000);
    let m = build_alice_manifest_at(now);
    let wrapped = serde_json::json!({ "manifest": m });
    let parsed = parse_manifest_wire(&checked(&wrapped)).expect("wrapped manifest parses");
    assert_eq!(parsed.aid, m.aid);
}

/// An unknown member as a SIBLING of the `manifest` wrapper key (outside
/// the signed body entirely) must still be rejected as UNKNOWN_FIELD —
/// the wrapper's own member set is exactly `["manifest"]`.
#[test]
fn parse_manifest_wire_rejects_unknown_sibling_of_the_wrapper() {
    let now = Timestamp(1_700_000_000);
    let m = build_alice_manifest_at(now);
    let wrapped = serde_json::json!({ "manifest": m, "rogue": 1 });
    let err = parse_manifest_wire(&checked(&wrapped)).unwrap_err();
    assert!(
        matches!(err, ManifestError::UnknownField(ref f) if f == "rogue"),
        "got: {err:?}"
    );
}

/// Gap A (issue #140 Phase 3 gap-closing): `accepted_signature_algorithms`
/// is a schema-declared, legitimate Manifest member (RFC-AITP-0001 §5.4.3
/// / RFC-AITP-0009 §4). It must parse successfully through
/// `parse_manifest_wire`, not be misclassified as `UNKNOWN_FIELD`. Before
/// the field was modeled on `Manifest`, it passed the top-level
/// `MANIFEST_MEMBERS` allow-list check (it's schema-declared) but then
/// failed `serde_json::from_value::<Manifest>` (unknown to the struct),
/// which `from_serde_error` relabeled as `UnknownField`.
#[test]
fn parse_manifest_wire_accepts_accepted_signature_algorithms() {
    let now = Timestamp(1_700_000_000);
    let m = build_alice_manifest_at(now);
    let mut body = serde_json::to_value(&m).unwrap();
    body.as_object_mut().unwrap().insert(
        "accepted_signature_algorithms".into(),
        serde_json::json!(["ed25519"]),
    );
    let parsed = parse_manifest_wire(&checked(&body))
        .expect("accepted_signature_algorithms must not be misclassified as UNKNOWN_FIELD");
    assert_eq!(
        parsed.accepted_signature_algorithms,
        Some(vec!["ed25519".to_string()])
    );
}

/// issue #144 regression: a manifest missing a required member
/// (`handshake_endpoint`) must report `ManifestError::Malformed`, not
/// `UnknownField` — the member set is intact (nothing extra is present),
/// so `check_members` passes and only the typed `serde_json::from_value`
/// deserialize fails, with a "missing field" message `from_serde_error`
/// does not recognize as an unknown-field pattern. This is the MANIFEST_INVALID
/// case (man-006): a structural defect distinct from both `UnknownField`
/// (an extra member) and `ManifestSignatureInvalid` (a bad signature on an
/// otherwise well-formed manifest) — exercised here via the real
/// `parse_manifest_wire` entry point rather than by constructing
/// `ManifestError::Malformed` by hand.
#[test]
fn parse_manifest_wire_missing_required_field_is_malformed_not_unknown_field() {
    let now = Timestamp(1_700_000_000);
    let m = build_alice_manifest_at(now);
    let mut body = serde_json::to_value(&m).unwrap();
    body.as_object_mut().unwrap().remove("handshake_endpoint");

    let err = parse_manifest_wire(&checked(&body)).unwrap_err();
    assert!(
        matches!(err, ManifestError::Malformed(_)),
        "a manifest missing a required field must be Malformed, not {err:?}"
    );
    assert!(
        !matches!(err, ManifestError::UnknownField(_)),
        "a missing member is not an unknown one: got {err:?}"
    );
}

/// Re-enter an in-memory `Value` through `CheckedJson`'s text-only
/// constructor (a `Value` has no duplicate key, so this cannot fail).
fn checked(v: &serde_json::Value) -> aitp_core::CheckedJson {
    v.to_string().parse().expect("valid JSON")
}

/// RFC-AITP-0005 §11 / RFC-AITP-0008 §1.4: the `ListRevoked` URL set via
/// `revocation_list_uri` lands in `extensions` *before* signing, so the
/// Manifest signature covers it — swapping the advertised URL breaks it.
#[test]
fn revocation_list_uri_is_advertised_inside_the_signed_body() {
    let now = Timestamp(1_700_000_000);
    let key = alice_key();
    let uri = "https://alice.example.com/.well-known/aitp-revocation-list";
    let m = ManifestBuilder::new(&key)
        .handshake_endpoint("https://alice.example.com/handshake".parse().unwrap())
        .identity_hint(IdentityHint {
            kind: IdentityHintKind::Oidc,
            subject: "alice".into(),
            issuer: Some("https://idp.example.com".parse().unwrap()),
            public_key: None,
        })
        .accept_trust_anchor("https://idp.example.com".parse().unwrap())
        .offer("demo.echo")
        .revocation_list_uri(uri.parse().unwrap())
        .published_at(now)
        .ttl_secs(3600)
        .build()
        .unwrap();
    assert_eq!(
        m.extensions
            .as_ref()
            .and_then(|e| e.get(aitp_manifest::REVOCATION_LIST_URI_EXT))
            .and_then(|v| v.as_str()),
        Some(uri)
    );
    verify_manifest(&m, &VerifyManifestContext { now }).expect("advertising manifest verifies");

    let mut swapped = m;
    let mut ext = swapped.extensions.take().unwrap();
    ext.insert(
        aitp_manifest::REVOCATION_LIST_URI_EXT,
        serde_json::json!("https://attacker.example/.well-known/aitp-revocation-list"),
    );
    swapped.extensions = Some(ext);
    let err = verify_manifest(&swapped, &VerifyManifestContext { now }).unwrap_err();
    assert!(
        matches!(err, ManifestError::SignatureInvalid),
        "a swapped revocation_list_uri must fail the Manifest signature: {err:?}"
    );
}

/// RFC-AITP-0008 §1.4: a verifier MUST NOT reject a Manifest solely
/// because `rfc-aitp-0008.revocation_list_uri` is absent.
#[test]
fn manifest_without_revocation_list_uri_still_verifies() {
    let now = Timestamp(1_700_000_000);
    let m = build_alice_manifest_at(now);
    assert!(m.extensions.is_none());
    verify_manifest(&m, &VerifyManifestContext { now }).expect("absent key is not a reject");
}

/// RFC-AITP-0014 §4.1: the registered `rfc-aitp-0014.a2a_interfaces`
/// extension key passes strict wire parsing and verifies under the
/// signature like any other extension member.
#[test]
fn a2a_interfaces_extension_key_is_accepted() {
    let now = Timestamp(1_700_000_000);
    let key = alice_key();
    let m = ManifestBuilder::new(&key)
        .handshake_endpoint("https://alice.example.com/handshake".parse().unwrap())
        .identity_hint(IdentityHint {
            kind: IdentityHintKind::Oidc,
            subject: "alice".into(),
            issuer: Some("https://idp.example.com".parse().unwrap()),
            public_key: None,
        })
        .accept_trust_anchor("https://idp.example.com".parse().unwrap())
        .offer("demo.echo")
        .extension(
            "rfc-aitp-0014.a2a_interfaces",
            serde_json::json!(["https://alice.example.com/a2a/v1"]),
        )
        .published_at(now)
        .ttl_secs(3600)
        .build()
        .expect("builder produces a manifest");
    let wire = serde_json::to_string(&m).unwrap();
    let parsed =
        parse_manifest_wire(&wire.parse().unwrap()).expect("strict parse accepts the a2a key");
    verify_manifest(&parsed, &VerifyManifestContext { now }).expect("manifest verifies");
    assert_eq!(
        parsed
            .extensions
            .as_ref()
            .and_then(|e| e.get("rfc-aitp-0014.a2a_interfaces")),
        Some(&serde_json::json!(["https://alice.example.com/a2a/v1"]))
    );
}
