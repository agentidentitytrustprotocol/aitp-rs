# DECISIONS — jcs-inner-body-signing-input (issue #82)

Decisions made by the user during `/plan`, 2026-08-24.

## D1 — No dual-accept. Flip atomically.
`verify_revocation_list` verifies the inner body only; the legacy wrapped form is
rejected. **Why:** RFC-AITP-0010 grants no transition allowance, so the session bundle
must flip atomically regardless — dual-accept could only ever have covered revocation,
making it a half-measure by construction. The ecosystem is `aitp-rs` + `aitp-verifier-py`
shipped in lockstep, snapshots default to a 3600 s TTL, and there is no installed base of
long-lived wrapped artifacts. Accepting two byte strings under one signature would have
silently masked the exact divergence being fixed. Failure is fail-closed.
**Consequence:** issuers and verifiers must roll close together; see the CHANGELOG
operational note. Supersedes the source plan's Phase 6 dual-accept suggestion.

## D2 — `#[non_exhaustive]` on both verification context structs.
`DelegationVerifyContext` and `RevocationListVerifyContext` both get `#[non_exhaustive]`
in the 0.5.0 breaking window. **Why:** both are pub-field, builder-less structs today, so
every future field addition is a breaking change; this is the cheapest it will ever be.
**Consequence (real work, not free):** cross-crate struct-literal construction stops
compiling. `DelegationVerifyContext` needs `crates/aitp-rs-adapter/src/lib.rs:1552` moved
onto `new()` + builder; `RevocationListVerifyContext` has no constructor at all and needs
one, plus every caller migrated (`crates/aitp-transport-http/src/revocation.rs:330`,
`crates/aitp-rs-adapter/src/lib.rs:1250,1507,2493`, `tools/mint-signed-examples/tests/verify.rs`,
fuzz targets). In-crate literals are unaffected. Tracked as its own phase.

## D3 — The cross-implementation job is a required check immediately.
The Phase 5 `aitp-verifier-py` job goes onto `main`'s branch protection in this change.
**Why:** maximum enforcement — a signing-input regression cannot be merged.
**Consequence (accepted):** merge availability is coupled to an external repo checkout and
a `pip install`; an `aitp-verifier-py` outage or transient network failure blocks all
merges. Mitigate by pinning `aitp-verifier-py` by SHA (no floating refs) and keeping the
job's dependency surface to one package. The check must be added to branch protection
*after* it has passed once on the PR, or it blocks its own merge.

## D4 — `aitp-verifier-py` is in scope for this drive (cross-repo go-ahead given).
User explicitly asked to execute
`plans/cross-repo/aitp-verifier-py-jcs-signing-input.md` alongside the `aitp-rs` work,
2026-08-24. This is the per-change cross-repo authorization `/implement` requires.
**Scope there:** test coverage only — verified independently during planning that
`aitp-verifier-py` already signs/verifies the inner body everywhere
(`aitp_verifier/{revocation,sessionbundle,manifest,minter}.py`) and passes 51/0/2 against
spec `5f8e588`. **No wire-format change.**
**Coupling:** that repo's Phase 3 and `aitp-rs` Phase 5 are the same work from two sides;
neither repo can do it alone. `aitp-rs` Phase 5 pins `aitp-verifier-py` by SHA, so the
verifier's own test work must merge first.
**Sequencing:** aitp-rs P1-P4 -> aitp-verifier-py P1-P2 (own PR, merged) -> joint
acceptance (aitp-rs P5 + verifier P3, pinning the merged SHA) -> aitp-rs P6-P8.

## D5 — Everything must be green, in all three repos.
Reconciliation answer, 2026-08-24: the acceptance bar is a fully green CI in
the **spec repo, the runtime repo (aitp-rs), and the verifier
(aitp-verifier-py)** — not "no regression versus a baseline that was already
red". A pre-existing failure is not a licence to ship another one.
**Why it matters here:** two red checks were being carried as "expected".
Both turned out to be real and fixable, and one was actively harmful —
`cargo-audit` had been failing to build for so long that it was auditing
nothing while still reporting a security failure. Treating it as known-red
meant nobody looked. The other, `cargo-semver-checks`, was red only because
the version had not been bumped; fixing it properly (0.5.0) also made the
release deterministic instead of inferred.
**Consequence:** no check is dismissed as "expected red" without either
fixing it or recording why it cannot be fixed.

---

# DECISIONS — drop the jsonwebtoken runtime dependency (issue #99)

Decision approved ahead of implementation, 2026-08-29.

## D1 — Drop `jsonwebtoken` from every runtime dependency graph rather than re-pinning it again.
`jsonwebtoken` was held at 9.x with a long comment explaining why: 9.x carries its own
`ring`-backed crypto, disjoint from this workspace's RustCrypto stack, and jsonwebtoken
10+ requires opting into a backend feature. As of 11.0.0, both available backends are
worse than staying on 9.x: `rust_crypto` pins the pre-bump RustCrypto stack (forking
ed25519-dalek/p256/sha2 into two copies) and pulls `rsa` 0.9, which carries
RUSTSEC-2023-0071 (Marvin timing sidechannel) with no patched release; `aws_lc_rs` avoids
that but adds a C/CMake/NASM build dependency to both wheel matrices and would put two
JOSE crypto backends (ring via 9.x, aws-lc-rs via 11.x) in the same cdylib. This is a
closed, passively-maintained upstream line with no version on the horizon that both
tracks current RustCrypto and avoids `rsa` 0.9 — waiting for one is not a plan.
**Why not just re-pin to a newer 9.x patch or add an ignore for the advisory:** `rsa` 0.9's
Marvin sidechannel has no fix; ignoring it would be the first crypto-advisory ignore in
`deny.toml`, which exists specifically to make that kind of erosion visible and rare.
**Consequence:** RS256 (RSA) verification moves to `ring`'s
`RsaPublicKeyComponents::verify` with `RSA_PKCS1_2048_8192_SHA256` — the same code path
jsonwebtoken 9's RS256 support used internally, so no crypto behavior changes, only the
wrapper is removed. Verification-only usage is unaffected by RUSTSEC-2023-0071 (a
signing/decryption padding-timing issue). EdDSA/ES256 move onto this workspace's own
already-KAT-tested `aitp-crypto` JWS primitives. `jsonwebtoken` survives only as a
dev-dependency differential test oracle (`jose_backend_tripwire.rs`,
`aitp-crypto`'s JWS KATs).

## D2 — `JwkPublicKey`'s public fields become owned types, decoupling the crate's public API from any JOSE library.
`aitp_handshake::JwkPublicKey` exposed `jsonwebtoken::{Algorithm, DecodingKey}` directly,
so any future jsonwebtoken major bump — even a dev-only one — would have been a breaking
change for `aitp-handshake` and both bindings in lockstep. **Why go further than the
minimum fix:** the plan could have kept `jsonwebtoken`'s types and just swapped what
implements the traits, but that leaves the exact coupling this issue exists to remove.
**Consequence:** `alg: JwsAlgorithm` (`EdDSA`/`ES256`/`RS256`) and
`key: JwkKeyMaterial` (`Ed25519{x}`/`P256{x,y}`/`Rsa{n,e}`), both plain, owned, `Clone
+ Debug + PartialEq + Eq`. This is a breaking change to `aitp-handshake`'s public API
(major bump on next release) but decouples it from any JOSE library's version
permanently — considered an improvement, not just an accepted cost. A single shared
parser, `JwkPublicKey::from_jwk_json`, replaces four duplicated hand-rolled JWK parsers
(`aitp-transport-http`'s JWKS fetch and DPoP verification, both language bindings).

## D6 — Session-bundle HTTP endpoint keeps accepting both wrapped and bare bodies (reconciled 2026-08-30, plan: unknown-field-error-code).
**Assumption:** routing `session_bundle_server.rs` through `parse_session_bundle_wire`
(which has always accepted a bare body as an alternative to `{"session_bundle": {...}}`)
widens the live network contract, since the endpoint previously only accepted the wrapped
shape.
**Fable's recommendation:** confirm as-is. RFC-AITP-0010 §4.3.1 is explicitly
non-normative for Draft, and its wording ("Request body is the `session_bundle` object
defined in §3") arguably favors the bare shape over the wrapper — unlike the manifest's
RFC-AITP-0003 §6.1 explicit wrapper MUST, which is a genuinely different RFC clause, not
an inconsistency in this repo. The server re-wraps whatever it accepts before storing and
always serves the wrapped form on GET, so the leniency never propagates downstream; both
shapes go through identical member-set checks and full signature verification. One
asymmetry worth tracking: `aitp-verifier-py`'s own (non-HTTP) parser requires the wrapper.
**Verdict:** confirmed as-is. File an upstream spec-clarification issue on RFC-AITP-0010
§4.3.1's ambiguous "the `session_bundle` object" wording, since it currently supports
either implementation's reading.
**Status:** CONFIRMED (2026-08-30). Follow-up filed:
agentidentitytrustprotocol/agentidentitytrustprotocol#43.

## D7 — Add a `typ`-first gate to delegation's claim peek, closing a real cross-impl divergence (reconciled 2026-08-30, plan: unknown-field-error-code).
**Assumption:** delegation's `peek_claims` lacking a `typ`-first gate (unlike TCT/voucher
after Phase 6a) was a pre-existing, out-of-scope wire-format completeness gap with no
fixture coverage.
**Fable's recommendation:** change. Confirmed by reading all three sources directly:
`aitp-verifier-py/aitp_verifier/delegation.py` checks `typ` before unknown-fields and
reports `TOKEN_TYP_MISMATCH` for a TCT presented as a delegation token; `aitp-rs`'s
`peek_claims` runs the member-set check first and reports `UNKNOWN_FIELD` for the same
input; RFC-AITP-0006 §4 step 1 mandates the Python side's ordering. This is a live
interop divergence between the two implementations, not a dormant purity gap, and the
fix mirrors an already-proven pattern (`peek_header_typ`) one file away.
**Verdict:** change now, before shipping. Mirror `peek_header_typ` into
`aitp-delegation`'s `peek_claims`, gate the member-set check on `typ` matching first,
update `tct_presented_as_delegation_rejected`'s expectation to `TypMismatch` only.
**Status:** NEEDS-CHANGE — implemented in this same session before `/ship`.

## D8 — Extend xcheck to cross-verify a revocation snapshot with populated `extensions` (reconciled 2026-08-30, plan: unknown-field-error-code).
**Assumption:** `extensions` is an opaque, schema-declared passthrough that never drives
a trust decision, so xcheck never minting a populated-`extensions` snapshot was low-risk,
out-of-scope busywork.
**Fable's recommendation:** change. The "opaque passthrough" framing is correct for trust
decisions but wrong for the signing input: `aitp-verifier-py`'s `verify_revocation_snapshot`
JCS-canonicalizes the entire body, including `extensions`, before verifying the
signature — a populated `extensions` map flows through both implementations' JCS
canonicalization and must agree byte-for-byte. `xcheck` is a required CI check; the
one-time local verification run for this PR dies at merge, while a CI vector runs
forever, including against every future Python-pin bump.
**Verdict:** change now, before shipping. Add a populated-`extensions` revocation
snapshot vector to `xcheck_mint.rs` and a matching check in `xcheck-verify.py`.
**Status:** NEEDS-CHANGE — implemented in this same session before `/ship`.

## D9 — Add manifest vectors to xcheck; manifest had zero cross-impl coverage, not just the `extensions` edge case (reconciled 2026-08-30, plan: unknown-field-error-code).
**Assumption:** the logged entry stated only that `Some(empty extensions)` specifically
lacked a cross-impl witness, with the KATs as the load-bearing gate in the meantime.
**Fable's recommendation:** change — and the situation is worse than the logged
assumption stated. `xcheck_mint.rs` mints no manifest vector of any kind; `xcheck-verify.py`
never calls `verify_manifest`. Phase 3's real JCS signing-input change (the
`ExtensionsMap` → `Option<ExtensionsMap>` fix) has never been independently cross-verified
at all, in any shape. `aitp-verifier-py` already has a working `verify_manifest()`, so
this needs no cross-repo edit — only a local addition. `Some(ExtensionsMap::new())`
(present-but-empty) stays genuinely unreachable from the public `ManifestBuilder` and is
correctly left out of the new vectors; a populated-extensions manifest (a reachable state)
is the one that matters.
**Verdict:** change now, before shipping. Add two manifest vectors (no extensions,
populated extensions) to `xcheck_mint.rs` and matching `verify_manifest` checks to
`xcheck-verify.py`.
**Status:** NEEDS-CHANGE — implemented in this same session before `/ship`.

## D10 — Phase 6a's claim-registry check running after `typ` enforcement is correct, CI-enforced ordering (reconciled 2026-08-30, plan: unknown-field-error-code).
**Assumption:** the plan's Approach text said the claim-set check runs before `typ`
enforcement; the implementation gates it on `typ` matching first instead, per an earlier
verify round's finding.
**Fable's recommendation:** confirm. Independently re-read `crates/aitp-tct/src/verifier.rs`
(the `peek_header_typ` gate), RFC-AITP-0005 §7.2's actual text ("before any cryptographic
step" scopes to alg-pin/signature, not `typ`), and fixture `tct-010` (already green,
requires exactly this order) — all confirm the implementation's ordering, not the plan's
paraphrase, is correct. One residual note: the RFC's own "MUST, in order" step list
arguably contradicts its own fixture's description of that same ordering — an upstream
wording issue, not a code defect here.
**Verdict:** confirmed as-is. Worth an upstream spec-clarification issue for RFC-AITP-0005
§7.2's internally inconsistent step-ordering language.
**Status:** CONFIRMED (2026-08-30). Follow-up filed:
agentidentitytrustprotocol/agentidentitytrustprotocol#44.

## D11 — Accumulating all 11 phases locally before one closing `/ship` was the right call (reconciled 2026-08-30, plan: unknown-field-error-code).
**Assumption:** shipping every phase individually (push + full CI watch after each) would
have cost far more than it bought, since the conformance corpus stayed red by design
until Phase 6b landed.
**Fable's recommendation:** confirm. Git history shows 22 clean, independently-revertable
commits (11 feature + 11 doc-tracking). Specifically tested whether accumulating delayed
catching the duplicate-key security regression found during Phase 7b's review: it did
not — that bug was caught by a verifier's own investigation, not by any test, and CI runs
the same suites as local `cargo test`, so an earlier push would not have surfaced it any
sooner. No actual cost materialized from accumulating.
**Verdict:** confirmed as-is.
**Status:** CONFIRMED (2026-08-30).

## D12 — The `aitp-verifier-ts` cross-implementation job is a required check too (2026-10-25, RS4.3).
`cross-impl acceptance (aitp-verifier-ts)` (`xcheck-ts`, #379) went onto `main`'s branch
protection after it passed on its own PR, on the same terms as D3.
**Consequence (accepted):** merges also depend on a GitHub checkout of `aitp-verifier-ts`
and an `npm ci` (dev dependencies only; the package has no runtime ones). The verifier is
pinned by commit SHA in `tests/AITP_VERIFIER_TS_VERSION` because it is not on npm yet (since #384 its adapter comes from npm, and the SHA pin feeds only `xcheck-verify.mjs`);
`bump-verifier-ts.yml` opens a held PR weekly when its `main` moves. Once a v0.1.x
release is published, the pin can move to the release.
**Status:** CONFIRMED (2026-10-25).

## D13 — The published SDKs carry the stable surface only; experimental is a source build (reconciled 2026-10-30, plan: rs-rc4-experimental-quarantine, Q4).
**Assumption:** no separately published experimental SDK package. Renewal, session bundles and multi-hop delegation are opt-in through a source build only (Cargo features; `npm run build:experimental`).
**Analysis (Opus):** confirm. The packaging enforces the policy: the npm `files` list holds only `index.js`/`index.d.ts`, both release workflows build with default features, and STABILITY.md excludes the `experimental-*` features from the promise. Publishing Draft RFCs (0010, 0011, 0013) as packages would imply support before the 1.0 freeze. Reversing later is additive: a new npm package or dist-tag with its own `binaryName`, or a new PyPI distribution. No consumer depends on a published experimental build. aitp-playground's docs wrongly assume the wheel has them, which aitp-playground#117 already tracks.
**Decided by:** Opus (reversible tier).
**Verdict:** confirmed as-is. Reopen if one of RFC-0010/0011/0013 nears Accepted, or an external user asks for prebuilt experimental binaries.
**Status:** CONFIRMED (2026-10-30).

## D14 — `RenewalServer` has no metrics; the absence is documented (reconciled 2026-10-30, plan: rs-rc4-experimental-quarantine, Q5).
**Assumption:** renewal-server metrics only if `aitp-experimental` already takes `metrics`; otherwise documented as absent.
**Analysis (Opus):** confirm, and write the missing doc line. `aitp-experimental` has no `metrics` feature and `aitp`'s counter helpers are crate-private (`crates/aitp/src/transport/obs.rs`), so adding metrics now means a new dependency plus duplicate helpers. Adding them later is purely additive, and the crate makes no promise. Only aitp-rs's own tests and example host `RenewalServer`, so there is no operational gap. The route already has a rate limit, a `handle_renew` tracing span and `warn!` events, and the shared `NonceStore` gauge fires under `aitp/metrics`. The plan said the absence was documented, but it was not.
**Decided by:** Opus (reversible tier).
**Verdict:** confirmed; a "No metrics" bullet was added to `docs/tct-renewal.md` Known limitations.
**Status:** CONFIRMED (2026-10-30).

## D15 — A2A Agent Card binding, P1 library decisions (reconciled 2026-11-01, plan: a2a-agent-card).
**Assumption:** see the `ASSUMPTIONS.md` entry.
**Analysis (Opus):** version-first, the strict SecurityScheme reading and the default-built conformance op stand. `https_url` works as coded, but becomes a cross-implementation contract once spec #176 item 16 lands, and that text says a host URL parsing leaves unchanged while case changes and IPv6 rewrites pass here. Its use on `handshake_endpoint` isn't covered by items 15-17. `ManifestError::Crypto` as MANIFEST_POP_FAILED differs from the handshake mapping for the same AID, and no fixture pins it.
**Decided by:** Opus for the reversible parts. The HTTPS URL definition goes to the spec owner.
**Verdict:** confirmed, with the entry's text corrected. Open: the `Crypto` code. Deferred: the HTTPS URL definition, until item 16 and 17 dispositions at RC2.1.
**Status:** CONFIRMED (2026-11-01) in part; see the entry.

## D16 — Manifest grammar check in `verify_manifest` (reconciled 2026-11-01, PR #477).
**Assumption:** see the `ASSUMPTIONS.md` entry.
**Analysis (Opus):** the hand-written check holds: a differential of `is_uri` against boon on 1,075,200 generated URIs found no false accept. Opt-ins are default-off and follow `STABILITY.md`. Closed enums match the RFC and schema, but `VERSIONING.md:104` allows additive identity types on the frozen line. The step 6 overlap predates this work and needs a ruling on an OIDC initiator whose verification mode isn't OIDC.
**Decided by:** the project lead for the SDK opt-ins, delegation opt-in, strict bundle verification and 0.25.0; Opus for the rest. Closed enums and step 6 go to the spec owner.
**Verdict:** confirmed, with the entry's text corrected. Deferred: closed enums against `VERSIONING.md`, and the step 6 overlap, until a spec ruling.
**Status:** CONFIRMED (2026-11-01) in part; see the entry.
