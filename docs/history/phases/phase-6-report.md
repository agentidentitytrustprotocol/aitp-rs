# Phase 6 Report — polish and release prep

## Final test counts

| Status | Count |
|---|---|
| Passed | **133** (after Phase 6 audit closed remaining plan gaps: OIDC handshake test, mock OIDC issuer, http handshake test, manifest-fetcher failure-path tests, wire transcript doc) |
| Failed | **0** |
| Ignored | 3 (1 known-broken `serde_jcs` surrogate vector + 2 examples-only doctests) |

`cargo fmt --all -- --check` ✓
`cargo clippy --workspace --all-targets --all-features -- -D warnings` ✓
`cargo test --workspace --all-features` ✓
`RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features` ✓
`make demo` ✓

## Files added/updated in this phase

- `crates/aitp/src/lib.rs` — working doctest demonstrating issue + verify
  of a TCT (passes `cargo test -p aitp --doc`).
- `README.md` — updated status table, replaced "not yet buildable" with
  a working **Quick start** section, fixed crate-status table.
- `CHANGELOG.md` — full v0.1.0-alpha.1 entry.
- `RELEASE_NOTES_v0.1.0-alpha.1.md` — draft release notes for the human
  to use when actually publishing.
- Two `#[allow(dead_code, clippy::large_enum_variant)]` annotations on
  the handshake state enums; the `Done`/`Failed` variants are
  intentionally smaller than the active states.

## Workspace summary

| Crate | LOC* | Public API | Tests |
|---|---|---|---|
| `aitp-core` | ~700 | `Aid`, `AitpEnvelope`, JCS, base64url, ErrorCode, envelope signing | 33 unit + 24 vectors + 3 properties + 2 KAT |
| `aitp-crypto` | ~250 | `AitpSigningKey`, `AitpVerifyingKey`, `Signature`, JWK thumbprint | 7 unit + 11 integration |
| `aitp-manifest` | ~450 | `Manifest`, `ManifestBuilder`, `verify_manifest` | 6 unit + 11 round-trip |
| `aitp-tct` | ~450 | `Tct`, `TctBuilder`, `verify_tct`, downstream PoP | 5 unit + 13 round-trip |
| `aitp-delegation` | ~400 | `DelegationToken`, `DelegationBuilder`, `verify_delegation` | 5 unit + 11 round-trip |
| `aitp-handshake` | ~700 | `Initiator`, `Responder`, `bootstrap_verify_peer`, OIDC + pinned-key | 10 unit + 4 full-handshake |
| `aitp-transport-http` | ~450 | `ManifestFetcher`, `JwksFetcher`, `ManifestServer`, `HandshakeServer` | 1 TCP integration |
| `aitp` (facade) | ~70 | re-exports + doctest | 1 doctest |
| `aitp-conformance` | ~600 | runner, fixture loader, output formatters, CLI, `Adapter` trait, `SubprocessAdapter` | 3 integration |
| `aitp-rs-adapter` | ~250 | NDJSON Tier-A adapter binary | (covered by conformance integration) |
| `examples/two-agents` | ~400 | `agent-a` + `agent-b` binaries + helper | 1 spawn-both-and-talk |

\* approximate, including doc comments.

## What's NOT in alpha.1, and why

| Item | Reason |
|---|---|
| Multi-hop delegation | Spec reserves to RFC-AITP-0011 (v0.2). |
| Session Trust Bundle | Spec reserves to RFC-AITP-0010 (v0.2). |
| Conformance Tier B/C/D ops | Tier A landed; B/C/D would require an issuer-side state map and a clock-override hook. Deferred to alpha.2. |
| Spec KAT (signing hashes / thumbprint) | Spec hasn't published reference hashes (`SPEC-005`, `SPEC-006`). |
| Surrogate-pair JCS ordering | `serde_jcs` upstream bug; one vector is `#[ignore]`'d. |
| HTTPS in the demo | Skipped to keep `make demo` self-contained. `ManifestFetcher` only allows HTTP for `localhost`/`127.0.0.1`. |
| Per-crate `README.md` files | Plan §6.7 explicitly marks optional. |

## Six-phase summary

| Phase | Crate(s) | Tests landed (cumulative) | Notes |
|---|---|---|---|
| 0 | (preflight) | — | Fixed `secrecy::Secret` Zeroize bound; bumped MSRV. |
| 1 | `aitp-core` | 39 | Removed `extensions` from envelope per schema; added envelope signing helper per RFC §5.4. |
| 2 | `aitp-crypto` | 18 | `verify_strict` for cross-impl interop. |
| 3a | `aitp-manifest` | 17 | View-struct signing pattern. |
| 3b | `aitp-tct` | 18 | `cnf` is the public key, not the JWK thumbprint (schema). |
| 3c | `aitp-delegation` | 16 | Reused source TCT signature verbatim per spec §3.1. |
| 3d | `aitp-handshake` | 14 | OIDC + pinned-key + bootstrap helper + INSUFFICIENT_GRANTS. |
| 4a | `aitp-transport-http` | 1 | TCP round-trip; HTTPS-only with `localhost` exception. |
| 4b | demo | 1 | `make demo` runs end-to-end. |
| 5 | conformance | 3 | Tier A only; spec fixtures need migration. |
| 6 | polish | 1 (doctest) | README/CHANGELOG/release notes refreshed. |

## Spec ambiguities surfaced (recorded in PENDING.md)

1. **`BLOCKED-JCS-SURROGATE`** — `serde_jcs` 0.1 sorts UTF-8 not UTF-16.
2. **`BLOCKED-SPEC-DELEGATION-ISSUEDAT`** — `grant_proof` lacks the
   source TCT's `issued_at` field.
3. **PoP signing input** — `sha256(nonce.as_bytes())` vs `sha256(decoded_nonce)`.
4. **Manifest example placeholders** — spec example doesn't carry real
   signatures (`BLOCKED-SPEC-EXAMPLE`).
5. **Conformance fixture migration** — fixtures pre-date the runner's
   wire protocol.

Each is captured in `docs/design/PENDING.md` with enough context for
the spec authors to resolve.

## Things that could be different next time

- **Build the demo helper struct first.** I started agent-a/agent-b
  with bare `Initiator::start` / `Responder::on_hello` calls and
  re-discovered the `pinned-key proof signed over envelope mid/ts`
  invariant the hard way. A small `HandshakeClient` / `HandshakeServer`
  that owns the envelope wrap+sign would have made the demo binaries
  half their current size. Worth lifting into `aitp-transport-http` for
  alpha.2.
- **Conformance fixtures live in the spec repo.** Iterating against
  them was hampered by the migration gap. A repo-local `fixtures/`
  with hand-built minimum-viable fixtures would let the runner be
  exercised independently of spec progress.
- **OIDC test path.** A small `MockJwksResolver` plus `MockJwtIssuer`
  fixture would close the OIDC-side coverage gap with ~150 lines.

## Tag readiness

`git status` is dirty in the working tree because none of this run's
changes have been committed. The tree is otherwise clean and CI-green.
The human reviewer can:

1. Commit the changes phase-by-phase using the report files as commit
   message bodies, or in one squash.
2. Tag `v0.1.0-alpha.1` once committed.
3. Run `cargo publish` — but DO NOT publish in this phase. Publishing
   is a human decision.
