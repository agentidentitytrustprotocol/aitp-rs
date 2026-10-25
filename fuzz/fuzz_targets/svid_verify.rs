#![no_main]

//! Fuzz target: SPIFFE SVID parsing and verification
//! (RFC-AITP-0002 §6, `aitp::handshake::identity_spiffe`).
//!
//! The verifier holds a bundle for `prod.example.com` with one
//! JWT-SVID key and one X.509 CA, so input gets past the bundle lookup
//! (§6.5 step 3) and into the JWT-SVID and X509-SVID code. The input
//! reaches verify_spiffe three ways:
//!
//! - parsed as an identity descriptor, so its whole shape is fuzzed;
//! - as the `proof` of a jwt-svid descriptor, so the JWS parser gets
//!   arbitrary bytes;
//! - as the DER leaf in `x5c` of an x509-svid descriptor, so the
//!   certificate parser and path validation get arbitrary bytes.
//!
//! Every path must return, never panic. The keys are throwaway test
//! material, generated for this target and trusted nowhere else.

use aitp::core::{Aid, Timestamp};
use aitp::handshake::identity_spiffe::{verify_spiffe, SpiffeBundleStore, SpiffeVerifyContext};
use aitp::handshake::IdentityDescriptor;
use base64::Engine as _;
use libfuzzer_sys::fuzz_target;
use serde_json::json;
use std::sync::OnceLock;

/// Self-signed P-256 CA for `spiffe://prod.example.com`, valid to 2100.
const X509_CA_DER_B64: &str = "MIIBrzCCAVagAwIBAgIJAPyKgoSKcJb1MAoGCCqGSM49BAMCMDcxEjAQBgNVBAoMCWFpdHAgZnV6ejEhMB8GA1UEAwwYcHJvZC5leGFtcGxlLmNvbSBmdXp6IENBMCAXDTI2MTAyNTE3MzMxMVoYDzIxMDAwOTI3MTczMzExWjA3MRIwEAYDVQQKDAlhaXRwIGZ1enoxITAfBgNVBAMMGHByb2QuZXhhbXBsZS5jb20gZnV6eiBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNdHI2SeKH8SxarLX4CfoxF0mNyC8x6rtActu2U2Y5Gi22sHvGeeWr8XpAR6xEhhbPFAOwfdCjGAubeTnaCtHmGjSTBHMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMCQGA1UdEQQdMBuGGXNwaWZmZTovL3Byb2QuZXhhbXBsZS5jb20wCgYIKoZIzj0EAwIDRwAwRAIgZ0KLnD4GSjdiKgo2HKeDBf+MVRXazoFPtouagJgafrMCIArUS1Ei7k3ZhPkSNeoanWLJlq0afmGJHpxyg/3y7vxe";

const SENDER: &str = "aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik";
const RECEIVER: &str = "aid:pubkey:A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg";
const SUBJECT: &str = "spiffe://prod.example.com/ns/payments/sa/agent";
const NOW: i64 = 1_800_000_000;

fn bundles() -> &'static SpiffeBundleStore {
    static STORE: OnceLock<SpiffeBundleStore> = OnceLock::new();
    STORE.get_or_init(|| {
        SpiffeBundleStore::from_config(&json!([{
            "trust_domain": "prod.example.com",
            "bundle": { "keys": [
                {
                    "use": "jwt-svid",
                    "kid": "fuzz-jwt-1",
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "lSUEOVLLG8GTwxJKcqbl8azgbGY7votLAXAAergy65M",
                    "y": "lRosQ6BnrvNqCR7rlyn5GLUUJ09tQEb5vPkkbZuVruQ"
                },
                { "use": "x509-svid", "kty": "EC", "x5c": [X509_CA_DER_B64] }
            ]}
        }]))
        .expect("fuzz bundle parses")
    })
}

fn verify(identity: &IdentityDescriptor) {
    let sender = Aid::parse(SENDER).expect("valid AID");
    let receiver = Aid::parse(RECEIVER).expect("valid AID");
    let message_id = uuid::Uuid::nil();
    let ctx = SpiffeVerifyContext {
        bundles: bundles(),
        sender_aid: &sender,
        receiver_aid: &receiver,
        message_id: &message_id,
        timestamp: Timestamp(NOW),
        pop_nonce: "bQ88kiChryTKduskLXSCNg",
        iat_tolerance_secs: 300,
        now_unix_secs: NOW,
    };
    let _ = verify_spiffe(identity, &ctx);
}

fn descriptor(svid_type: &str, proof: &str, x5c: Option<Vec<String>>) -> IdentityDescriptor {
    let mut v = json!({
        "type": "spiffe",
        "subject": SUBJECT,
        "svid_type": svid_type,
        "proof": proof,
    });
    if let Some(x5c) = x5c {
        v["x5c"] = json!(x5c);
    }
    serde_json::from_value(v).expect("descriptor shape")
}

fuzz_target!(|data: &[u8]| {
    if let Ok(identity) = serde_json::from_slice::<IdentityDescriptor>(data) {
        verify(&identity);
    }
    if let Ok(proof) = std::str::from_utf8(data) {
        verify(&descriptor("jwt-svid", proof, None));
    }
    let leaf = base64::engine::general_purpose::STANDARD.encode(data);
    verify(&descriptor(
        "x509-svid",
        "AAAA",
        Some(vec![leaf, X509_CA_DER_B64.to_string()]),
    ));
});
