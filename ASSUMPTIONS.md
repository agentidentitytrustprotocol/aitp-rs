# ASSUMPTIONS — jcs-inner-body-signing-input (issue #82)

## Phase 1 AC6 reworded from "green" to "no change in outcome"
- **Plan:** `plans/jcs-inner-body-signing-input.md` (Phase 1)
- **Assumed:** the plan's "cargo test --workspace is green" was written before the baseline
  was measured; the workspace has a pre-existing failure.
- **Chose:** treat the criterion as *no change in test outcome vs the recorded baseline*
  (71 pass / 1 fail both before and after). `minted_revocation_snapshot_verifies` reads the
  **sibling spec repo**, not the vendored tree, so re-vendoring cannot affect it, and it was
  already red on the baseline. Recorded inline in the plan's Phase 1 section.
- **Alternatives:** fixing that test in Phase 1 (rejected — it goes green in Phase 3 when the
  signing view moves, and fixing it here would hide the finding).
- **Blast radius if wrong:** none; the phase is data-only and fully reversible.
- **Status:** RESOLVED — **NEEDS-CHANGE, then fixed.** Reconciled 2026-08-24.
  The reinterpretation was rejected: the standard is that **everything must be
  green — spec repo, runtime repo, and verifier** — not merely "no change in
  outcome". Acted on rather than merely noted:
    * `minted_revocation_snapshot_verifies` went green in Phase 3.
    * `cargo-semver-checks` was red because the version was still 0.4.1; fixed
      by bumping to 0.5.0 so it evaluates the breaking changes against the bump
      that permits them — not by suppressing it.
    * `cargo-audit` was red because the tool failed to BUILD (unlocked install
      pulled kstring 2.0.4, needing rustc 1.96 vs the 1.89 pin); fixed with
      `--locked`. It had been auditing nothing while reporting a security
      failure.
  Final: aitp-rs **34/34 green**; spec repo `main` green at 5f8e588;
  aitp-verifier-py green on 3.11/3.12/3.13.

## Phase 0 shipped as accumulate, not ship-now
- **Plan:** `plans/unknown-field-error-code.md` (Phase 0)
- **Assumed:** the Phase 0 verifier's "ship now" call (independently shippable,
  flips `vendored schemas in sync` green) is technically correct but not the
  better call for this run.
- **Chose:** accumulate all 11 phases locally and run one closing `/ship` pass
  against PR #141's branch, rather than pushing after every phase.
- **Alternatives:** push+watch-CI after each phase per the verifier's literal
  call — rejected because 9 of the remaining 10 phases will still leave
  `conformance fixtures` red by design (the corpus only reaches 0 failures once
  Phase 6b lands), so an early push buys no additional signal beyond what local
  `cargo test`/diff review already gives, at the cost of a full CI matrix watch
  (`/ship` §5, blocking) repeated up to 10 extra times.
- **Blast radius if wrong:** none structurally — every phase is still a
  separate, revertable commit; the only cost of this choice being wrong is a
  later, larger CI watch instead of several smaller ones. Reversible at any
  point by pushing the accumulated branch early.
- **Status:** CONFIRMED (2026-08-30). See DECISIONS.md D11.

## Revocation snapshot `Some(extensions)` has no cross-impl witness
- **Plan:** `plans/unknown-field-error-code.md` (Phase 4)
- **Assumed:** xcheck's local pass (mint with aitp-rs, verify with
  `aitp-verifier-py` at the pinned SHA, byte-compare) is sufficient
  cross-impl assurance for this phase's `extensions` addition.
- **Chose:** accept it for the absent-`extensions` case, which is what
  `tools/mint-signed-examples/src/bin/xcheck_mint.rs` actually mints
  (byte-identical to the committed reference) — but flag that it never
  mints a snapshot WITH `extensions` populated, so `rev-006`'s accept-side
  shape (a snapshot carrying `extensions`) is only verified by this
  repo's own tests, not independently cross-checked against
  `aitp-verifier-py`.
- **Alternatives:** extending `xcheck_mint.rs` to also mint a
  populated-`extensions` variant — rejected for this pass as
  out-of-scope busywork; low risk since `extensions` is an opaque,
  schema-declared passthrough that never drives a trust decision.
- **Blast radius if wrong:** low, same reasoning as the manifest entry
  above — the KATs are the load-bearing gate and are untouched.
- **Status:** NEEDS-CHANGE (2026-08-30) → CHANGED. See DECISIONS.md D8.
  `extensions` was found to enter the JCS signing input in both
  implementations (not merely an opaque passthrough), so this was
  fixed: `xcheck_mint.rs` now also mints a populated-`extensions`
  snapshot, cross-verified in `xcheck-verify.py`.

## Phase 6a's claim-registry check runs after `typ` enforcement, not before
- **Plan:** `plans/unknown-field-error-code.md` (Phase 6a)
- **Assumed:** the plan's Approach text ("RFC-AITP-0005 §7.2 folds the
  claim-set check into step 1 — before `typ` enforcement, before
  AID-pinned `alg`, before signature") was an imprecise paraphrase, not
  the RFC's actual guarantee.
- **Chose:** gate the member-set check on `typ` enforcement passing
  FIRST — i.e. `typ` check, then claim-registry check, then `alg`
  pin/signature. Verified against RFC-AITP-0005 §7.2 itself at the
  pinned spec commit: the "before any cryptographic step" language
  scopes to steps 3-4 (alg pin, signature), not step 2 (`typ`). Fixture
  `tct-010` is the normative tiebreaker: a grant voucher presented where
  a TCT is expected must report `TOKEN_TYP_MISMATCH` even though its
  claims (e.g. `src_jti`) aren't TCT-registry members — a TCT claim
  registry is meaningless against an artifact that isn't a TCT in the
  first place. `tct-010` was already passing before this phase; a
  literal step-1-first implementation would have regressed it.
- **Alternatives:** implementing the plan's literal paraphrase
  (member-set check strictly first) — rejected because it fails
  `tct-010`, a fixture already in the corpus.
- **Blast radius if wrong:** low and immediately visible — `tct-010` is
  a real conformance fixture in CI; getting the order wrong fails a
  currently-green check, it doesn't ship silently.
- **Status:** CONFIRMED (2026-08-30). See DECISIONS.md D10.

## Delegation's `peek_claims` has no `typ`-first gate like TCT's (pre-existing gap, unaltered)
- **Plan:** `plans/unknown-field-error-code.md` (Phase 6b)
- **Assumed:** `tct_presented_as_delegation_rejected`'s updated expectation
  (now includes `UnknownField` alongside `ClaimsMalformed`/`TypMismatch`)
  is correct, not a regression of Phase 6a's typ-before-claims lesson.
- **Chose:** verified `DelegationClaims`'s pre-existing
  `deny_unknown_fields` already rejected the same inputs at the same
  call site before this phase — `check_members`'s rejection set is a
  strict subset, so no outcome that used to report `TypMismatch` can
  flip to `UnknownField`; this phase only relabels a subset of what was
  previously `ClaimsMalformed`. RFC-AITP-0006 §4 step 1 does specify a
  `typ`-check-first ordering (`TOKEN_TYP_MISMATCH`) that delegation
  doesn't implement — but that gap predates this phase (a TCT-as-
  delegation reported `INVALID_ENVELOPE` before, `UNKNOWN_FIELD` now;
  neither is the RFC's `TOKEN_TYP_MISMATCH`), and the plan explicitly
  directed this phase to change only the error code, not the ordering.
- **Alternatives:** adding a `peek_header_typ`-style gate to
  `peek_claims` (mirroring Phase 6a's TCT/voucher fix) — would genuinely
  improve delegation to the RFC-correct code, but is out of scope for
  issue #140 (a wire-format completeness gap, not part of the
  UNKNOWN_FIELD rollout) and no fixture exercises it.
- **Blast radius if wrong:** low — `del-004`/`del-007` are the only
  delegation-adjacent fixtures and are frozen permanent skips; no
  fixture in the corpus exercises this ordering, so getting it "wrong"
  changes no CI signal today.
- **Status:** NEEDS-CHANGE (2026-08-30) → CHANGED. See DECISIONS.md D7.
  A real cross-implementation divergence with `aitp-verifier-py` was
  found (it reports `TOKEN_TYP_MISMATCH`, aitp-rs reported
  `UNKNOWN_FIELD`, for the same input), so this was fixed rather than
  left as a follow-up: a `typ`-first gate was added to delegation's
  `peek_claims`, mirroring TCT/voucher's Phase 6a fix.

## Session-bundle HTTP endpoint now also accepts an unwrapped body
- **Plan:** `plans/unknown-field-error-code.md` (Phase 5)
- **Assumed:** routing `session_bundle_server.rs`'s POST handler through
  the shared `parse_session_bundle_wire` (this phase's approach for
  every artifact) is fine even though that function has always accepted
  a bare, unwrapped body as an alternative to `{"session_bundle": {...}}`
  — the endpoint previously only accepted the wrapped shape (a bare
  `serde_json::from_slice::<SessionBundleEnvelope>`), so this is a small
  widening of the live network contract.
- **Chose:** accept the widening rather than adding a wrapper-required
  check at this one call site (the way Phase 3 did for the manifest's
  `/.well-known` fetcher), because: (1) unlike the manifest case, no RFC
  clause was found mandating the wrapper specifically at this HTTP
  endpoint; (2) the bare-body path is pre-existing, deliberate library
  behavior (documented in the adapter as serving "legacy internal
  callers" since before this phase); (3) `signature` is a member of the
  bundle body itself, not the wrapper, in both shapes — so accepting a
  bare body does not accept an unsigned or less-verified bundle, only a
  differently-shaped one that still goes through full cryptographic
  verification.
- **Alternatives:** requiring the wrapper at this endpoint specifically,
  mirroring Phase 3's manifest-fetcher fix — rejected for now for lack of
  a normative citation; worth revisiting if RFC-AITP-0010 turns out to
  require it.
- **Blast radius if wrong:** low — no cryptographic or trust-boundary
  weakening either way, only an acceptance-shape question.
- **Status:** CONFIRMED (2026-08-30). See DECISIONS.md D6. RFC-AITP-0010
  §4.3.1 is non-normative for Draft and its wording arguably favors the
  bare shape; the server normalizes both shapes on read/write regardless.
  Follow-up: file an upstream spec-clarification issue for §4.3.1's
  ambiguous wording (`aitp-verifier-py`'s own parser requires the
  wrapper, an asymmetry worth resolving upstream, not by code here).

## Manifest `Some(empty extensions)` has no cross-impl witness
- **Plan:** `plans/unknown-field-error-code.md` (Phase 3)
- **Assumed:** running `aitp-verifier-py`'s xcheck locally (it passed) is
  sufficient cross-implementation assurance for Phase 3's manifest
  signing-input change.
- **Chose:** accept it as sufficient for the *absent-extensions* case
  (covered by `crates/aitp-cli/tests/cli.rs`'s spec-minted manifest
  round-trip and fixtures man-001/man-005 going through the full
  `ManifestSigningView` path), but flag that xcheck's own vectors
  (`scripts/xcheck-verify.py`) cover only the revocation snapshot and
  session bundle — zero manifest coverage — so the *`Some(empty)`
  extensions* case this phase's OQ1 fix specifically introduces has no
  independent cross-implementation witness, only this repo's own KATs.
- **Alternatives:** hand-authoring a new xcheck vector for
  `Some(ExtensionsMap::new())` manifests — rejected for this pass because
  it requires either a cross-repo edit to `aitp-verifier-py` (gated) or a
  local-only script that CI can't enforce going forward, so it wouldn't
  reduce ongoing risk, only one-time risk.
- **Blast radius if wrong:** low — the KAT vectors are the load-bearing
  gate here and are untouched; if `aitp-verifier-py` ever disagreed about
  this case, the first real cross-impl manifest carrying
  `"extensions":{}` would surface it as a signature mismatch, not a
  silent divergence.
- **Status:** NEEDS-CHANGE (2026-08-30) → CHANGED. See DECISIONS.md D9.
  Reconciliation found the situation was worse than logged here: `xcheck`
  had ZERO manifest coverage of any kind, not just the extensions edge
  case, so Phase 3's real JCS signing-input change had never been
  cross-verified at all. Fixed by adding two manifest vectors (no
  extensions, populated extensions — not the unreachable `Some(empty)`
  case) to `xcheck_mint.rs`/`xcheck-verify.py`.
