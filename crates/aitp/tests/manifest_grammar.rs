//! RFC-AITP-0003 §5 step 2: `verify_manifest` holds every value to the
//! grammar of `tests/schemas/aitp-manifest.schema.json`, and the schema is
//! the oracle here. Each case re-signs a mutated Manifest, so a rejection
//! can only come from the grammar.

use aitp::core::{base64url, ErrorCode, Timestamp};
use aitp::crypto::{AitpSigningKey, Digest32};
use aitp::handshake::{HandshakeError, IdentityKind};
use aitp::manifest::{
    parse_manifest_wire, verify_manifest, IdentityHint, Manifest, ManifestBuilder, ManifestError,
    ManifestVerifyContext,
};
use boon::{Compiler, Schemas};
use serde_json::{json, Value};
use std::path::PathBuf;

const NOW: Timestamp = Timestamp(1_700_000_000);
const ENDPOINT: &str = "https://a.example.com/aitp/handshake";

fn key() -> AitpSigningKey {
    AitpSigningKey::from_ed25519_seed(&[0x5A; 32])
}

fn base() -> Value {
    let key = key();
    let manifest = ManifestBuilder::new(&key)
        .handshake_endpoint(ENDPOINT.parse().unwrap())
        .identity_hint(
            IdentityHint::new(IdentityKind::PinnedKey, "alice").with_public_key(base64url::encode(
                &key.verifying_key().try_to_ed25519_bytes().unwrap(),
            )),
        )
        .offer("demo.echo")
        .accept_identity_type(IdentityKind::PinnedKey)
        .published_at(NOW)
        .build()
        .unwrap();
    serde_json::to_value(manifest).unwrap()
}

/// Sign `value` as it stands: the outer signature over its JCS bytes.
fn resign(mut value: Value) -> Value {
    let body = value.as_object_mut().unwrap();
    body.remove("signature");
    let digest = Digest32::sha256(&aitp::core::jcs::canonicalize(&value).unwrap());
    value["signature"] = json!(key().sign_jcs(&digest).into_string());
    value
}

fn schema_accepts(manifest: &Value) -> bool {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/schemas/aitp-manifest.schema.json");
    let schema: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let url = format!("file://{}", path.display());
    let mut schemas = Schemas::new();
    let mut compiler = Compiler::new();
    compiler.enable_format_assertions();
    compiler.add_resource(&url, schema).unwrap();
    let id = compiler.compile(&url, &mut schemas).unwrap();
    schemas
        .validate(&json!({ "manifest": manifest }), id)
        .is_ok()
}

fn verify(value: &Value, ctx: &ManifestVerifyContext) -> Result<(), ManifestError> {
    let checked = serde_json::to_string(value).unwrap().parse().unwrap();
    let manifest: Manifest = parse_manifest_wire(&checked)?;
    verify_manifest(&manifest, ctx).map(drop)
}

type Mutation = (&'static str, fn(&mut Value));

/// Values the schema refuses.
const OUTSIDE: &[Mutation] = &[
    ("endpoint bad escape", |m| {
        m["handshake_endpoint"] = json!("https://a.example.com/%zz")
    }),
    ("endpoint lone percent", |m| {
        m["handshake_endpoint"] = json!("https://a.example.com/%")
    }),
    ("endpoint bracket in path", |m| {
        m["handshake_endpoint"] = json!("https://a.example.com/[x]")
    }),
    ("endpoint bracket in query", |m| {
        m["handshake_endpoint"] = json!("https://a.example.com/?q=[")
    }),
    ("endpoint second fragment", |m| {
        m["handshake_endpoint"] = json!("https://a.example.com/a#b#c")
    }),
    ("trust anchor bad escape", |m| {
        m["accepted_trust_anchors"] = json!(["https://a.example.com/%zz"])
    }),
    ("null display_name", |m| m["display_name"] = Value::Null),
    ("null accepted_identity_types", |m| {
        m["accepted_identity_types"] = Value::Null
    }),
    ("null accepted_signature_algorithms", |m| {
        m["accepted_signature_algorithms"] = Value::Null
    }),
    ("null required_peer_capabilities", |m| {
        m["required_peer_capabilities"] = Value::Null
    }),
    ("null extensions", |m| m["extensions"] = Value::Null),
    ("null issuer", |m| {
        m["identity_hint"]["issuer"] = Value::Null
    }),
    ("null public_key", |m| {
        m["identity_hint"]["public_key"] = Value::Null
    }),
    (
        "null public_key on oidc",
        |m| m["identity_hint"] = json!({"type": "oidc", "subject": "s", "issuer": "https://i.example/", "public_key": null}),
    ),
    ("expires_at zero", |m| m["expires_at"] = json!(0)),
    ("endpoint bracket in userinfo", |m| {
        m["handshake_endpoint"] = json!("https://u[s@a.example.com/h")
    }),
    ("endpoint closing bracket in userinfo", |m| {
        m["handshake_endpoint"] = json!("https://u]s@a.example.com/")
    }),
    ("endpoint bracket in password", |m| {
        m["handshake_endpoint"] = json!("https://user:pa[ss@a.example/")
    }),
    ("endpoint second at sign", |m| {
        m["handshake_endpoint"] = json!("https://a@b@a.example.com/")
    }),
    ("anchor bracket after a later ://", |m| {
        m["accepted_trust_anchors"] = json!(["urn:x://a[b]"])
    }),
    ("anchor bracket in query after a later ://", |m| {
        m["accepted_trust_anchors"] = json!(["foo:?a://b["])
    }),
    ("anchor bracket in path after a later ://", |m| {
        m["accepted_trust_anchors"] = json!(["foo:a://b[c]"])
    }),
    ("anchor bracket in userinfo", |m| {
        m["accepted_trust_anchors"] = json!(["foo://u[s@h/"])
    }),
    ("capability feff", |m| {
        m["offered_capabilities"] = json!(["a\u{feff}b"])
    }),
    ("display_name", |m| {
        m["display_name"] = json!("x".repeat(129))
    }),
    ("endpoint http", |m| {
        m["handshake_endpoint"] = json!("http://a.example.com/h")
    }),
    ("endpoint loopback", |m| {
        m["handshake_endpoint"] = json!("http://localhost:8080/h")
    }),
    ("endpoint ftp", |m| {
        m["handshake_endpoint"] = json!("ftp://a.example.com/h")
    }),
    ("endpoint upper", |m| {
        m["handshake_endpoint"] = json!("HTTPS://a.example.com/h")
    }),
    ("endpoint empty", |m| m["handshake_endpoint"] = json!("")),
    ("endpoint not a url", |m| {
        m["handshake_endpoint"] = json!("not a url")
    }),
    ("endpoint space", |m| {
        m["handshake_endpoint"] = json!("https://a.example.com/a b")
    }),
    ("endpoint backslash", |m| {
        m["handshake_endpoint"] = json!("https://a.example.com\\h")
    }),
    ("anchor not a uri", |m| {
        m["accepted_trust_anchors"] = json!(["no scheme"])
    }),
    ("anchor repeated", |m| {
        m["accepted_trust_anchors"] = json!(["https://i.example/", "https://i.example/"])
    }),
    ("offered empty", |m| m["offered_capabilities"] = json!([""])),
    ("offered space", |m| {
        m["offered_capabilities"] = json!(["a b"])
    }),
    ("offered repeated", |m| {
        m["offered_capabilities"] = json!(["a", "a"])
    }),
    ("required space", |m| {
        m["required_peer_capabilities"] = json!(["a\tb"])
    }),
    ("required repeated", |m| {
        m["required_peer_capabilities"] = json!(["a", "a"])
    }),
    ("identity type", |m| {
        m["accepted_identity_types"] = json!(["kerberos"])
    }),
    ("identity type repeated", |m| {
        m["accepted_identity_types"] = json!(["oidc", "oidc"])
    }),
    ("algorithm", |m| {
        m["accepted_signature_algorithms"] = json!(["rsa"])
    }),
    ("algorithm repeated", |m| {
        m["accepted_signature_algorithms"] = json!(["p256", "p256"])
    }),
    ("challenge length", |m| {
        m["proof_of_possession"]["challenge"] = json!("AAAA")
    }),
    ("challenge alphabet", |m| {
        m["proof_of_possession"]["challenge"] = json!("AAAAAAAAAAAAAAAAAAAA+/")
    }),
    ("pop signature", |m| {
        m["proof_of_possession"]["signature"] = json!("short")
    }),
    ("published_at", |m| m["published_at"] = json!(-1)),
    ("subject empty", |m| {
        m["identity_hint"]["subject"] = json!("")
    }),
    ("public_key length", |m| {
        m["identity_hint"]["public_key"] = json!("AAAA")
    }),
    ("public_key alphabet", |m| {
        m["identity_hint"]["public_key"] = json!("+".repeat(43))
    }),
    ("pinned without key", |m| {
        m["identity_hint"]
            .as_object_mut()
            .unwrap()
            .remove("public_key");
    }),
    ("oidc without issuer", |m| {
        m["identity_hint"] = json!({"type": "oidc", "subject": "s"})
    }),
    ("oidc with key", |m| {
        m["identity_hint"] = json!({
            "type": "oidc", "subject": "s", "issuer": "https://i.example/",
            "public_key": "A".repeat(43)
        })
    }),
    (
        "oidc issuer",
        |m| m["identity_hint"] = json!({"type": "oidc", "subject": "s", "issuer": "no scheme"}),
    ),
    ("spiffe with issuer", |m| {
        m["identity_hint"] = json!({
            "type": "spiffe", "subject": "spiffe://d.example/a", "issuer": "https://i.example/"
        })
    }),
    (
        "spiffe no path",
        |m| m["identity_hint"] = json!({"type": "spiffe", "subject": "spiffe://d.example"}),
    ),
    (
        "spiffe upper domain",
        |m| m["identity_hint"] = json!({"type": "spiffe", "subject": "spiffe://D.example/a"}),
    ),
    (
        "spiffe dot segment",
        |m| m["identity_hint"] = json!({"type": "spiffe", "subject": "spiffe://d.example/../a"}),
    ),
    (
        "spiffe empty segment",
        |m| m["identity_hint"] = json!({"type": "spiffe", "subject": "spiffe://d.example/a//b"}),
    ),
    (
        "spiffe trailing slash",
        |m| m["identity_hint"] = json!({"type": "spiffe", "subject": "spiffe://d.example/a/"}),
    ),
    ("spiffe long", |m| {
        m["identity_hint"] = json!({
            "type": "spiffe", "subject": format!("spiffe://d.example/{}", "a".repeat(2048))
        })
    }),
];

/// Values at the edge of the grammar that the schema admits.
const INSIDE: &[Mutation] = &[
    ("endpoint escape", |m| {
        m["handshake_endpoint"] = json!("https://a.example.com/%2F?q=%7e#f")
    }),
    ("endpoint ipv6", |m| {
        m["handshake_endpoint"] = json!("https://[2001:db8::1]:8443/h")
    }),
    ("capability u+0085", |m| {
        m["offered_capabilities"] = json!(["a\u{85}b"])
    }),
    ("base", |_| {}),
    ("display_name max", |m| {
        m["display_name"] = json!("é".repeat(128))
    }),
    ("endpoint with port and query", |m| {
        m["handshake_endpoint"] = json!("https://a.example.com:8443/h?x=1")
    }),
    ("no anchors", |m| m["accepted_trust_anchors"] = json!([])),
    ("anchor http", |m| {
        m["accepted_trust_anchors"] = json!(["http://i.example/", "https://i.example/"])
    }),
    ("no capabilities", |m| m["offered_capabilities"] = json!([])),
    ("no identity types", |m| {
        m["accepted_identity_types"] = json!([])
    }),
    ("all identity types", |m| {
        m["accepted_identity_types"] = json!(["oidc", "pinned_key", "spiffe"])
    }),
    ("all algorithms", |m| {
        m["accepted_signature_algorithms"] = json!(["ed25519", "p256"])
    }),
    ("public_key p256 length", |m| {
        m["identity_hint"]["public_key"] = json!("A".repeat(44))
    }),
    (
        "oidc",
        |m| {
            m["identity_hint"] =
                json!({"type": "oidc", "subject": "s", "issuer": "https://i.example/"})
        },
    ),
    (
        "spiffe",
        |m| m["identity_hint"] = json!({"type": "spiffe", "subject": "spiffe://d.example/a/b.c"}),
    ),
    (
        "spiffe dots",
        |m| m["identity_hint"] = json!({"type": "spiffe", "subject": "spiffe://d.example/.../..a"}),
    ),
    ("extensions any shape", |m| {
        m["extensions"] = json!({"x": {"handshake_endpoint": "http://a"}})
    }),
];

fn mutated(mutation: fn(&mut Value)) -> Value {
    let mut m = base();
    mutation(&mut m);
    resign(m)
}

#[test]
fn the_verifier_refuses_what_the_schema_refuses_with_manifest_invalid() {
    for (name, mutation) in OUTSIDE {
        let m = mutated(*mutation);
        assert!(!schema_accepts(&m), "{name}: the schema admits this");
        let err = verify(&m, &ManifestVerifyContext::at(NOW)).expect_err(name);
        assert!(
            matches!(
                err,
                ManifestError::Malformed(_) | ManifestError::IdentityHintMalformed(_)
            ),
            "{name}: {err:?}"
        );
        assert_eq!(
            HandshakeError::Manifest(err).error_code(),
            ErrorCode::ManifestInvalid,
            "{name}"
        );
    }
}

#[test]
fn the_verifier_accepts_what_the_schema_accepts() {
    for (name, mutation) in INSIDE {
        let m = mutated(*mutation);
        assert!(schema_accepts(&m), "{name}: the schema refuses this");
        verify(&m, &ManifestVerifyContext::at(NOW))
            .unwrap_or_else(|e| panic!("{name}: refused: {e:?}"));
    }
}

#[test]
fn the_outer_signature_is_checked_against_the_grammar() {
    // `mutated` would sign over this value, so it stays unsigned here.
    let mut m = base();
    m["signature"] = json!("not base64url!");
    assert!(!schema_accepts(&m));
    let err = verify(&m, &ManifestVerifyContext::at(NOW)).unwrap_err();
    assert!(matches!(err, ManifestError::Malformed(_)), "{err:?}");
}

#[test]
fn a_uri_naming_no_reachable_host_is_refused_though_the_schema_admits_it() {
    for uri in ["https://", "https://:443/", "https://a.example:99999/"] {
        let mut m = base();
        m["handshake_endpoint"] = json!(uri);
        let m = resign(m);
        assert!(schema_accepts(&m), "{uri}: the schema refuses this");
        let err = verify(&m, &ManifestVerifyContext::at(NOW)).unwrap_err();
        assert!(matches!(err, ManifestError::Malformed(_)), "{uri}: {err:?}");
    }
}

#[test]
fn grammar_runs_before_expiry_and_the_cryptographic_steps() {
    // A value outside the grammar, expired, under a signature that fails.
    let mut m = base();
    m["handshake_endpoint"] = json!("http://a.example.com/h");
    let late = ManifestVerifyContext::at(Timestamp(i64::MAX));
    let err = verify(&m, &late).unwrap_err();
    assert!(matches!(err, ManifestError::Malformed(_)), "{err:?}");
}

#[test]
fn a_rejection_names_the_member_and_not_its_value() {
    let mut m = base();
    m["handshake_endpoint"] = json!("http://canary.example/h");
    let err = verify(&resign(m), &ManifestVerifyContext::at(NOW)).unwrap_err();
    let text = err.to_string();
    assert!(text.contains("handshake_endpoint"), "{text}");
    assert!(!text.contains("canary"), "{text}");
}

#[test]
fn only_the_opt_in_admits_a_loopback_endpoint_and_only_a_loopback_one() {
    let opted_in = || ManifestVerifyContext::at(NOW).with_insecure_localhost_dangerous();
    let with = |endpoint: &str| {
        let mut m = base();
        m["handshake_endpoint"] = json!(endpoint);
        resign(m)
    };
    for endpoint in [
        "http://localhost/h",
        "http://localhost:8080/aitp/handshake/",
        "http://127.0.0.1:8080/h",
    ] {
        let m = with(endpoint);
        assert!(verify(&m, &opted_in()).is_ok(), "{endpoint}");
        assert!(
            verify(&m, &ManifestVerifyContext::at(NOW)).is_err(),
            "{endpoint}"
        );
    }
    for endpoint in [
        "http://a.example.com/h",
        "http://localhost.a.example.com/h",
        "http://localhost@a.example.com/h",
        "http://127.0.0.1.a.example.com/h",
        "http://10.0.0.1/h",
        "ftp://localhost/h",
        "http://local host/h",
    ] {
        assert!(verify(&with(endpoint), &opted_in()).is_err(), "{endpoint}");
    }
    // The opt-in changes nothing else.
    assert!(verify(&with(ENDPOINT), &opted_in()).is_ok());
}
