#![no_main]

//! Fuzz target: OIDC identity proof verification (RFC-AITP-0002 §2,
//! `aitp::handshake::verify_oidc`).
//!
//! The resolver returns the spec's trusted test-issuer key
//! (`kat-oidc-issuer-001`) for its issuer, so input gets past the trust
//! anchor and key lookup into the JWT parser, the signature check and
//! the claim checks. The input reaches verify_oidc two ways:
//!
//! - parsed as an identity descriptor, so its whole shape is fuzzed;
//! - as the `proof` of an oidc descriptor from the trusted issuer, so
//!   the JWT parser gets arbitrary bytes.
//!
//! Every path must return, never panic.

use aitp::core::{Aid, RawUrl};
use aitp::handshake::{
    verify_oidc, IdentityDescriptor, JwkPublicKey, JwksResolver, OidcVerifyContext, ResolveError,
};
use libfuzzer_sys::fuzz_target;
use serde_json::json;
use std::sync::OnceLock;

const ISSUER: &str = "https://auth.openai.com";
const RECEIVER: &str = "aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik";
const SUBJECT: &str = "aid:pubkey:A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg";
const NOW: i64 = 1_711_900_000;

struct KatIssuer;

impl JwksResolver for KatIssuer {
    fn resolve(&self, issuer: &url::Url) -> Result<Vec<JwkPublicKey>, ResolveError> {
        static KEY: OnceLock<JwkPublicKey> = OnceLock::new();
        if issuer.as_str().trim_end_matches('/') != ISSUER {
            return Err(ResolveError::NotTrusted(issuer.clone()));
        }
        let key = KEY.get_or_init(|| {
            // kat-oidc-issuer-001, tests/schemas/known-answer/oidc-test-issuers.json.
            JwkPublicKey::from_jwk_json(&json!({
                "kty": "OKP", "crv": "Ed25519",
                "x": "AOPFa5GrCgFxdLlmRer5KDZs264eh_0hv4ZmHYbz5-8"
            }))
            .expect("KAT issuer JWK parses")
        });
        Ok(vec![key.clone()])
    }
}

fn verify(identity: &IdentityDescriptor) {
    let receiver = Aid::parse(RECEIVER).expect("valid AID");
    let subject = Aid::parse(SUBJECT).expect("valid AID");
    let anchors = [RawUrl::new(ISSUER)];
    let ctx = OidcVerifyContext::new(
        &receiver,
        "AQIDBAUGBwgJCgsMDQ4PEA",
        &anchors,
        &KatIssuer,
        &subject,
        300,
        NOW,
    );
    let _ = verify_oidc(identity, &ctx);
}

fuzz_target!(|data: &[u8]| {
    if let Ok(identity) = serde_json::from_slice::<IdentityDescriptor>(data) {
        verify(&identity);
    }
    if let Ok(proof) = std::str::from_utf8(data) {
        let identity: IdentityDescriptor = serde_json::from_value(json!({
            "type": "oidc", "issuer": ISSUER, "subject": SUBJECT, "proof": proof,
        }))
        .expect("oidc descriptor shape");
        verify(&identity);
    }
});
