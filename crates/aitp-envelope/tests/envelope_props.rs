//! Property tests for the envelope parse/verify surface.
//!
//! Mirrors the `envelope_parse` fuzz target (whose committed corpus is
//! single-seed) with a proptest generator: the parser must never panic
//! on arbitrary input, and a genuinely-signed envelope must survive a
//! JSON round-trip and still verify.

use aitp_core::{AitpEnvelope, MessageType, Timestamp};
use aitp_crypto::AitpSigningKey;
use aitp_envelope::{sign_envelope_with, verify_envelope_signature};
use proptest::prelude::*;
use uuid::Uuid;

/// A bounded JSON value generator (leaves + shallow nesting), reused for
/// both the arbitrary-bytes parse check and as envelope payloads.
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

proptest! {
    #![proptest_config(ProptestConfig { cases: 96, ..ProptestConfig::default() })]

    /// Parsing arbitrary UTF-8 as an envelope never panics — it returns
    /// a value or an error, both fine.
    #[test]
    fn parse_arbitrary_string_never_panics(s in ".{0,256}") {
        let _ = serde_json::from_slice::<AitpEnvelope>(s.as_bytes());
    }

    /// Parsing arbitrary *JSON* (structurally valid, semantically random)
    /// as an envelope never panics.
    #[test]
    fn parse_arbitrary_json_never_panics(v in arb_json()) {
        let bytes = serde_json::to_vec(&v).unwrap();
        let _ = serde_json::from_slice::<AitpEnvelope>(&bytes);
    }

    /// A properly-signed envelope with an arbitrary payload round-trips
    /// through serialize → parse and still verifies against the signer.
    #[test]
    fn signed_envelope_round_trips_and_verifies(
        seed in any::<u8>(),
        ts in 1i64..4_000_000_000i64,
        payload in arb_json(),
    ) {
        let key = AitpSigningKey::from_seed(&[seed; 32]);
        let env = sign_envelope_with(
            &key,
            MessageType::MutualHello,
            payload,
            Uuid::from_u128(0x1234_5678_9abc_def0),
            Timestamp(ts),
        ).expect("sign");

        let json = serde_json::to_vec(&env).expect("serialize");
        let parsed: AitpEnvelope = serde_json::from_slice(&json).expect("parse own output");
        prop_assert_eq!(parsed.message_id, env.message_id);
        prop_assert!(verify_envelope_signature(&parsed, &key.verifying_key()).is_ok());
    }
}
