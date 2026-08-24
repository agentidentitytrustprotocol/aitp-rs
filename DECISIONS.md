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
`VerifyDelegationContext` and `VerifyRevocationListContext` both get `#[non_exhaustive]`
in the 0.5.0 breaking window. **Why:** both are pub-field, builder-less structs today, so
every future field addition is a breaking change; this is the cheapest it will ever be.
**Consequence (real work, not free):** cross-crate struct-literal construction stops
compiling. `VerifyDelegationContext` needs `crates/aitp-rs-adapter/src/lib.rs:1552` moved
onto `new()` + builder; `VerifyRevocationListContext` has no constructor at all and needs
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
