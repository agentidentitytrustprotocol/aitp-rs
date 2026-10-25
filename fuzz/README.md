# Fuzzing

libFuzzer targets (via [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz))
over every point where untrusted bytes first meet a parser or verifier.
Each target must return on any input. A panic, an OOM, a timeout or
unbounded recursion is a finding.

This directory is its own Cargo workspace (cargo-fuzz needs nightly and
a custom profile). The main workspace excludes it.

## Targets

| Target | Entry point | Spec |
|---|---|---|
| `envelope_parse` | `AitpEnvelope` deserialization | RFC-AITP-0001 §5 |
| `manifest_parse` | `Manifest` deserialization | RFC-AITP-0003 |
| `delegation_parse` | `DelegationClaims` deserialization, multi-hop included | RFC-AITP-0006, 0011 |
| `jws_verify` | `aitp_crypto::jws::verify_compact` | RFC-AITP-0001 §5.4.5 |
| `tct_verify` | `aitp_tct::verify_tct` | RFC-AITP-0005 §7.2 |
| `delegation_verify` | `aitp_delegation::verify_delegation` | RFC-AITP-0006 |
| `jcs_canonicalize` | `aitp_core::jcs::canonicalize` | RFC 8785 |
| `revocation_verify` | `aitp_tct::verify_revocation_list` | RFC-AITP-0008 |
| `interop_enroll` | the interop peer's `POST /enroll` body | — |
| `svid_verify` | X.509-SVID and JWT-SVID verification | RFC-AITP-0002 §6 |
| `handshake_payload_decode` | the four Mutual Handshake payloads: duplicate keys, unknown members, typed decode | RFC-AITP-0004 |
| `oidc_verify` | `verify_oidc`, with the spec's test issuer trusted | RFC-AITP-0002 §2 |
| `session_bundle_verify` | both bundle wire parsers, then `verify_session_bundle` | RFC-AITP-0010 |
| `pinned_admission` | `PinnedAdmission::admit_wire_at`, the whole §3.4 check order | RFC-AITP-0002 §3.4 |

The comment at the top of each `fuzz_targets/*.rs` says which keys and
verifier state it sets up, so input can get past the early checks.

## Running locally

```bash
rustup toolchain install nightly
cargo +nightly install --locked cargo-fuzz
cd fuzz
cargo +nightly fuzz run pinned_admission -- -max_total_time=60 -max_len=65536
```

On macOS, if linking fails with `tapi: unknown architecture`, export
`SDKROOT=$(xcrun --sdk macosx --show-sdk-path)` first.

### Seed corpora

`scripts/fuzz-seed-corpus.py` pulls the JSON each new target parses out
of the spec's conformance fixtures: handshake payloads, oidc descriptors
and their proofs, session bundles (wrapped and bare), and
`identity_presentation` envelopes.

```bash
python3 scripts/fuzz-seed-corpus.py ../agentidentitytrustprotocol fuzz/corpus
cd fuzz && cargo +nightly fuzz run oidc_verify corpus/oidc_verify
```

Placeholders in the fixtures (`__VALID_ENVELOPE_SIG__`, `__JWS_TCT__`,
…) are left as they are: the seeds give libFuzzer the shape of a valid
input, and mutation does the rest. The fixtures are spec-licensed, so
using them as seeds is fine. `fuzz/corpus/` and `fuzz/artifacts/` are
git-ignored.

### Reproducing a crash

```bash
cd fuzz
cargo +nightly fuzz run <target> artifacts/<target>/crash-<hash>
cargo +nightly fuzz fmt <target> artifacts/<target>/crash-<hash>   # pretty-print the input
```

## CI

- **`fuzz-pr.yml`**: on pull requests that touch `crates/` or `fuzz/`,
  every target runs for 30 s.
- **`fuzz.yml`**: nightly at 03:17 UTC (or on demand from the Actions
  tab, with a custom duration). Every target runs for 5 minutes from
  a corpus seeded at the pinned spec commit (`tests/schemas/SPEC_VERSION`).
  A crash uploads the reproducer as the `crashes-<target>` artifact
  and files an issue labelled `fuzz-crash`. There is one open issue per
  target, and a later crash comments on it. A green run uploads the
  grown corpus as `corpus-<target>`.

Both cap input size at 64 KiB (`-max_len=65536`), so a large input
cannot OOM the runner.

## Adding a target

1. Add `fuzz_targets/<name>.rs`, with a header comment saying what it
   drives and what state it sets up.
2. Add a `[[bin]]` entry to `Cargo.toml`.
3. Add the name to the matrix in both `fuzz.yml` and `fuzz-pr.yml`, and
   to the table above.
4. If spec fixtures hold inputs for it, teach
   `scripts/fuzz-seed-corpus.py` to extract them.
