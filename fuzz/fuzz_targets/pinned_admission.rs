#![no_main]

//! Fuzz target: pinned-key admission (RFC-AITP-0002 §3.4, feature
//! `pinned-admission`).
//!
//! The input is the request body of an `identity_presentation`, taken
//! through `CheckedJson` and `PinnedAdmission::admit_wire_at`, which
//! runs the whole §3.4 check order. Each run gets a fresh verifier set
//! up as in conformance fixture id-019: verifier kat-keypair-001,
//! trusting kat-keypair-003, with one outstanding challenge, so input
//! can get as far as the proof and the nonce consume. Every path must
//! return, never panic.

use aitp::core::{Aid, CheckedJson, Timestamp};
use aitp::handshake::admission::{
    ChallengeSource, InMemoryNonceStore, IssuedNonce, NonceStore, PinnedAdmission,
};
use aitp::handshake::StaticPinnedKeyStore;
use libfuzzer_sys::fuzz_target;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

const VERIFIER: &str = "aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik";
const SUBJECT: &str = "aid:pubkey:dqFZIESm5PURJlvKc6YE2QsFKdHfYCvjChmpJXZg0fU";
const NONCE: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
const NOW: i64 = 1_711_900_000;

/// The in-memory stores never wait, so one poll completes the future.
fn ready<F: Future>(fut: F) -> F::Output {
    let mut fut = std::pin::pin!(fut);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    match fut.as_mut().poll(&mut cx) {
        std::task::Poll::Ready(v) => v,
        std::task::Poll::Pending => unreachable!("in-memory admission stores never wait"),
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(body) = CheckedJson::from_slice(data) else {
        return;
    };
    let verifier = Aid::parse(VERIFIER).expect("valid AID");
    let subject = Aid::parse(SUBJECT).expect("valid AID");
    let nonces = Arc::new(InMemoryNonceStore::default());
    let rec = IssuedNonce::new(
        NONCE,
        verifier.clone(),
        "fuzz",
        Timestamp(NOW),
        Timestamp(NOW + 250),
    );
    ready(nonces.issue(&rec)).expect("seed challenge");
    let trust = StaticPinnedKeyStore::from_aids([&subject]).expect("trust store");
    let admission = PinnedAdmission::builder(verifier, nonces, Arc::new(trust)).build();
    let source = ChallengeSource::ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
    let _ = ready(admission.admit_wire_at(&body, &source, Timestamp(NOW)));
});
