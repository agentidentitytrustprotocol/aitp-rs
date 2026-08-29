//! Benchmark TCT issuance and verification — the primary per-request
//! hot path for any AITP resource server.

use aitp_core::Timestamp;
use aitp_crypto::AitpSigningKey;
use aitp_tct::{verify_tct, TctBuilder, TctVerifyContext};
use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;

const NOW: Timestamp = Timestamp(1_700_000_000);

fn issuer() -> AitpSigningKey {
    AitpSigningKey::from_seed(&[0xA1; 32])
}
fn subject() -> AitpSigningKey {
    AitpSigningKey::from_seed(&[0xB1; 32])
}

fn mint_token() -> String {
    TctBuilder::new(&issuer())
        .subject(subject().aid().clone())
        .audience(subject().aid().clone())
        .grants(["demo.echo", "demo.read", "demo.write"])
        .ttl_secs(3600)
        .subject_pubkey(subject().verifying_key())
        .issued_at(NOW)
        .build()
        .unwrap()
        .token
}

fn bench_issue(c: &mut Criterion) {
    let issuer = issuer();
    let subject = subject();
    c.bench_function("tct_issue", |b| {
        b.iter(|| {
            TctBuilder::new(black_box(&issuer))
                .subject(subject.aid().clone())
                .audience(subject.aid().clone())
                .grants(["demo.echo", "demo.read", "demo.write"])
                .ttl_secs(3600)
                .subject_pubkey(subject.verifying_key())
                .issued_at(NOW)
                .build()
                .unwrap()
        })
    });
}

fn bench_verify(c: &mut Criterion) {
    let token = mint_token();
    let subject_aid = subject().aid().clone();
    let issuer_aid = issuer().aid().clone();
    let verify_at = Timestamp(NOW.0 + 60);
    c.bench_function("tct_verify", |b| {
        b.iter(|| {
            let ctx = TctVerifyContext::builder(&subject_aid, &issuer_aid, verify_at)
                .accept_unchecked_revocation_dangerous()
                .skip_manifest_expiry_cap_dangerous()
                .build()
                .unwrap();
            verify_tct(black_box(&token), &ctx).unwrap()
        })
    });
}

criterion_group!(benches, bench_issue, bench_verify);
criterion_main!(benches);
