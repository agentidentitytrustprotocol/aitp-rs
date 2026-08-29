//! Benchmark JCS canonicalization (RFC 8785) — the hot path every
//! signed AITP artifact goes through on both mint and verify.

use aitp_core::jcs;
use criterion::{criterion_group, criterion_main, Criterion};
use serde_json::json;
use std::hint::black_box;

/// Roughly manifest/TCT-claims-shaped: nested objects, an array of
/// strings, unicode, and out-of-order keys (JCS must re-sort them).
fn sample_object() -> serde_json::Value {
    json!({
        "ver": "0.2",
        "iss": "aid:pubkey:ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "sub": "aid:pubkey:ed25519:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
        "aud": "aid:pubkey:ed25519:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
        "iat": 1_700_000_000,
        "exp": 1_700_003_600,
        "grants": [
            "demo.echo", "demo.read", "demo.write", "demo.admin.\u{1f512}",
        ],
        "cnf": {"jkt": "9ZP03Nu8GrXPAUkbKNxHOKBzxPX83SShgFkRNK-f2lw"},
        "metadata": {
            "display_name": "conformance-agent",
            "endpoints": {
                "handshake": "https://peer.example.com/aitp/handshake",
                "revocation": "https://peer.example.com/aitp/revocation",
            },
            "tags": ["staging", "internal", "unicode-\u{1f680}"],
        },
    })
}

fn bench_canonicalize(c: &mut Criterion) {
    let value = sample_object();
    c.bench_function("jcs_canonicalize", |b| {
        b.iter(|| jcs::canonicalize(black_box(&value)).unwrap())
    });
}

fn bench_canonicalize_and_hash(c: &mut Criterion) {
    let value = sample_object();
    c.bench_function("jcs_canonicalize_and_hash", |b| {
        b.iter(|| jcs::canonicalize_and_hash(black_box(&value)).unwrap())
    });
}

criterion_group!(benches, bench_canonicalize, bench_canonicalize_and_hash);
criterion_main!(benches);
