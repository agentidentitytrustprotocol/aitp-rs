//! Benchmark the compact-JWS sign/verify hot path — every TCT, grant
//! voucher, and delegation token goes through this on mint and verify.

use aitp_crypto::{jws, AitpSigningKey};
use criterion::{criterion_group, criterion_main, Criterion};
use serde_json::json;
use std::hint::black_box;

fn claims() -> serde_json::Value {
    json!({
        "ver": "0.2",
        "iss": "aid:pubkey:ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "sub": "aid:pubkey:ed25519:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
        "aud": "aid:pubkey:ed25519:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
        "iat": 1_700_000_000,
        "exp": 1_700_003_600,
        "grants": ["demo.echo", "demo.read", "demo.write"],
        "cnf": {"jkt": "9ZP03Nu8GrXPAUkbKNxHOKBzxPX83SShgFkRNK-f2lw"},
    })
}

fn bench_sign_ed25519(c: &mut Criterion) {
    let key = AitpSigningKey::from_seed(&[0x11; 32]);
    let claims = claims();
    c.bench_function("jws_sign_compact_ed25519", |b| {
        b.iter(|| jws::sign_compact(black_box(&key), jws::TYP_TCT, black_box(&claims)).unwrap())
    });
}

fn bench_verify_ed25519(c: &mut Criterion) {
    let key = AitpSigningKey::from_seed(&[0x11; 32]);
    let token = jws::sign_compact(&key, jws::TYP_TCT, &claims()).unwrap();
    c.bench_function("jws_verify_compact_ed25519", |b| {
        b.iter(|| {
            jws::verify_compact(black_box(key.aid()), jws::TYP_TCT, black_box(&token)).unwrap()
        })
    });
}

fn bench_sign_p256(c: &mut Criterion) {
    let key = AitpSigningKey::from_p256_seed(&[0x22; 32]).unwrap();
    let claims = claims();
    c.bench_function("jws_sign_compact_p256", |b| {
        b.iter(|| jws::sign_compact(black_box(&key), jws::TYP_TCT, black_box(&claims)).unwrap())
    });
}

fn bench_verify_p256(c: &mut Criterion) {
    let key = AitpSigningKey::from_p256_seed(&[0x22; 32]).unwrap();
    let token = jws::sign_compact(&key, jws::TYP_TCT, &claims()).unwrap();
    c.bench_function("jws_verify_compact_p256", |b| {
        b.iter(|| {
            jws::verify_compact(black_box(key.aid()), jws::TYP_TCT, black_box(&token)).unwrap()
        })
    });
}

criterion_group!(
    benches,
    bench_sign_ed25519,
    bench_verify_ed25519,
    bench_sign_p256,
    bench_verify_p256
);
criterion_main!(benches);
