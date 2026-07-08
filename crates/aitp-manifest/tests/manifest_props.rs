//! Property tests for Manifest parsing and round-tripping.
//!
//! Mirrors the `manifest_parse` fuzz target (single-seed corpus) with a
//! proptest generator: deserializing arbitrary input never panics, and
//! a builder-produced Manifest survives a serialize → parse round-trip
//! byte-for-byte on its verified fields.

use aitp_core::{base64url, Timestamp};
use aitp_crypto::AitpSigningKey;
use aitp_manifest::{IdentityHint, IdentityHintKind, Manifest, ManifestBuilder, ManifestEnvelope};
use proptest::prelude::*;

const NOW: Timestamp = Timestamp(1_700_000_000);

fn arb_json() -> impl Strategy<Value = serde_json::Value> {
    let leaf = prop_oneof![
        Just(serde_json::Value::Null),
        any::<bool>().prop_map(serde_json::Value::Bool),
        any::<i32>().prop_map(|n| serde_json::Value::from(n as i64)),
        "[a-zA-Z0-9_ -]{0,24}".prop_map(serde_json::Value::from),
    ];
    leaf.prop_recursive(3, 12, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..5).prop_map(serde_json::Value::Array),
            prop::collection::hash_map("[a-z]{1,6}", inner, 0..5)
                .prop_map(|m| serde_json::Value::Object(m.into_iter().collect())),
        ]
    })
}

/// Build a valid Manifest with varied but well-formed inputs.
fn build_manifest(seed: u8, caps: &[String], ttl: i64) -> Manifest {
    let key = AitpSigningKey::from_seed(&[seed; 32]);
    let mut b = ManifestBuilder::new(&key)
        .handshake_endpoint("https://example.com/handshake".parse().unwrap())
        .identity_hint(IdentityHint {
            kind: IdentityHintKind::PinnedKey,
            subject: "subj".into(),
            issuer: None,
            public_key: Some(base64url::encode(&key.verifying_key().to_bytes())),
        })
        .accept_trust_anchor("https://idp.example.com".parse().unwrap())
        .ttl_secs(ttl)
        .published_at(NOW);
    for c in caps {
        b = b.offer(c.clone());
    }
    b.build().expect("manifest builds")
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 96, ..ProptestConfig::default() })]

    #[test]
    fn parse_arbitrary_string_never_panics(s in ".{0,256}") {
        let _ = serde_json::from_slice::<Manifest>(s.as_bytes());
        let _ = serde_json::from_slice::<ManifestEnvelope>(s.as_bytes());
    }

    #[test]
    fn parse_arbitrary_json_never_panics(v in arb_json()) {
        let bytes = serde_json::to_vec(&v).unwrap();
        let _ = serde_json::from_slice::<Manifest>(&bytes);
        let _ = serde_json::from_slice::<ManifestEnvelope>(&bytes);
    }

    /// A built Manifest survives serialize → parse with its identity and
    /// offered capabilities intact.
    #[test]
    fn built_manifest_round_trips(
        seed in any::<u8>(),
        caps in prop::collection::vec("[a-z.]{1,12}", 0..6),
        ttl in 60i64..2_000_000i64,
    ) {
        let manifest = build_manifest(seed, &caps, ttl);
        let json = serde_json::to_vec(&manifest).expect("serialize");
        let parsed: Manifest = serde_json::from_slice(&json).expect("parse own output");
        prop_assert_eq!(&parsed.aid, &manifest.aid);
        prop_assert_eq!(&parsed.offered_capabilities, &manifest.offered_capabilities);
        prop_assert_eq!(parsed.expires_at, manifest.expires_at);
    }
}
