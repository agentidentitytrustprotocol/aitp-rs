# Testing guide

How `aitp-rs` is tested, layer by layer, and the command to run each.
The one-shot local gauntlet is `make test` (fmt + clippy + workspace
tests); `make ci` adds the doc build, `cargo-deny`, and `cargo-audit`.

## Layers at a glance

| Layer | What it covers | Run it |
|---|---|---|
| Unit + integration | Per-crate `#[test]` modules and `tests/` dirs across the workspace | `cargo test --workspace --all-features` (CI uses `cargo nextest run`) |
| Doctests | Runnable `///` examples on the public API (nextest skips these) | `cargo test --doc --workspace --all-features` |
| Property tests | `proptest` over JCS canonicalization and envelope/manifest parsing | part of the workspace test run (`crates/*/tests/*_prop*.rs`) |
| Fuzzing | libFuzzer targets over every untrusted-byte entry point | `cd fuzz && cargo +nightly fuzz run <target>` |
| Miri | UB / provenance checks on the pure crates | `cargo +nightly miri test -p aitp-core -p aitp-crypto --lib` |
| Conformance | The spec's fixture corpus, driven through the NDJSON adapter | see [Conformance](#conformance) below |
| Bindings | Node (`node --test`) and Python (`pytest`) SDK suites | see [Language bindings](#language-bindings) |
| Cross-language interop | A real Python ↔ Node handshake through the native bindings | `make interop` |
| End-to-end (LLM) | Two agents driven by live LLM calls (opt-in, networked) | `AITP_RUN_LLM_TESTS=1` in `tests/e2e-llm/` |

## Unit and integration tests

Every crate carries `#[cfg(test)]` unit tests plus a `tests/` directory
for integration coverage. The workspace run is the default gate:

```bash
cargo test --workspace --all-features        # or: make test
cargo nextest run --workspace --all-features  # what CI runs (faster)
```

`cargo nextest` runs each test in its own process and gives clearer
output, but it does **not** run doctests — CI runs `cargo test --doc`
separately, and you should too when you touch a `///` example.

## Known-answer tests, and the two ways they go blind

A known-answer test pins a value the spec publishes and checks the
implementation reproduces it. That only works if the test can actually
fail. Two patterns silently guarantee it cannot, and this repo shipped
both — for a full release, with two implementations and a green
conformance pack. Recognising them is the point of this section.

### Blindness 1 — deriving the question from the answer

`crates/aitp-core/tests/kat.rs` used to decide *which JSON shape to
canonicalize* by searching for the artifact's wrapper key inside the
pinned answer hex. If the pin looked wrapped it canonicalized the wrapped
form; otherwise the inner one. It therefore agreed with whatever shape the
vector happened to carry and **could not fail in either direction**.

The rule now: a vector must *declare* its `signing_input`, the test
**hard-codes** the expected declaration per artifact, and an absent
declaration is a `panic!` rather than a default. A vector may not
self-certify its own convention, and the harness may not infer one.

### Blindness 2 — re-minting before verifying

A test that signs an artifact and then verifies its own output proves only
that the implementation agrees with itself. It passes identically whether
the convention is right or wrong.

This is subtler than it sounds because the conformance pack does it
structurally: fixtures carry `__VALID_*_SIG__` placeholders that
`crates/aitp-conformance/src/fixture/placeholder.rs` **mints with the
harness's own key** before handing them to the adapter. So `aitp-rs` and
`aitp-verifier-py` each minted under their own convention, verified their
own output, and both reported 51/51 — while a revocation snapshot minted
by one could never verify against the other. See
[conformance.md](conformance.md#what-the-fixture-corpus-cannot-detect).

The rule now: **verify committed bytes as committed.** The spec's
`signed-examples/` exist for exactly this, and its README says so — those
files "MUST verify under any conformant AITP v0.2 implementation,
byte-for-byte, without any placeholder substitution."

### What every JCS-profile artifact must have

Three cells, not one. A positive test alone pins nothing, because a
signature valid over *both* shapes satisfies it:

| | Manifest | Revocation snapshot | Session bundle |
|---|---|---|---|
| canonical bytes vs the pinned vector | ✓ | ✓ | ✓ |
| pinned signature verifies over **committed** bytes | ✓ | ✓ | ✓ |
| **negative**: fails over the wrong shape | ✓ | ✓ | ✓ |

Drive the canonical-bytes test through the **production** signing-input
helper (`revocation_signing_bytes`, `bundle_signing_bytes`), never a
re-implementation in the test. A test that canonicalizes locally can stay
green while the production path signs something else — measured: before
that was fixed, a regression in `bundle_signing_bytes` was caught by a
single test in the entire workspace.

### The only acceptance criterion that means anything

Mutate the vector and confirm the suite goes red. Not a corrupted digest —
a **self-consistent** re-wrap: object, canonical hex, byte length and both
digests all updated together, so the file is internally coherent in the
wrong convention. That is precisely the state the spec shipped before
commit `5f8e588`. If the suite stays green, the harness is still adaptive
and the tests are decoration.

## Property tests

`proptest` (a workspace dev-dependency) drives generator-based tests
where a single example can't cover the input space:

- `crates/aitp-core/tests/jcs_properties.rs` — JCS idempotence, order
  invariance, whitespace-free output.
- `crates/aitp-delegation/tests/attenuation_props.rs` — delegated scope
  is always a subset; delegated expiry never exceeds the voucher.
- `crates/aitp-envelope/tests/envelope_props.rs` and
  `crates/aitp-manifest/tests/manifest_props.rs` — parsing arbitrary
  input never panics, and a valid instance round-trips. These mirror the
  `envelope_parse` / `manifest_parse` fuzz targets so the invariant is
  checked on every CI run, not only in the nightly fuzz window.

## Fuzzing

Eight libFuzzer targets under `fuzz/fuzz_targets/` cover every point
where an untrusted byte stream first meets a parser or verifier:

`envelope_parse`, `manifest_parse`, `delegation_parse`,
`delegation_verify`, `jws_verify`, `tct_verify`, `jcs_canonicalize`,
`revocation_verify`.

```bash
cd fuzz
cargo +nightly fuzz run tct_verify -- -max_total_time=60
```

CI runs a short per-target gate on changed targets
(`.github/workflows/fuzz-pr.yml`) and a longer nightly sweep across all
eight (`fuzz.yml`). The `fuzz/corpus/` directory is git-ignored; the
nightly job uploads corpus deltas as build artifacts.

## Miri

`.github/workflows/miri.yml` runs weekly (and on demand) against the
two pure crates most likely to harbor UB — `aitp-core` (JCS, AID
parsing) and `aitp-crypto` — under tree-borrows + strict-provenance.

```bash
cargo +nightly miri test -p aitp-core -p aitp-crypto --lib
```

## WASM portability

The pure verify/protocol crates must not pull in a native-only syscall
dependency. CI checks this with `cargo check --target wasm32-wasip1` on
`aitp-core`, `aitp-crypto`, `aitp-envelope`, `aitp-manifest`, `aitp-tct`,
`aitp-delegation`, and `aitp-session-bundle`. (Full browser
`wasm32-unknown-unknown` additionally needs a `uuid` randomness feature;
see `../plans/defered/deferred.md`.)

## Conformance

The v0.2 conformance corpus lives in the **spec repo**
(`agentidentitytrustprotocol/schemas/conformance/`), pinned to the
commit in [`../tests/schemas/SPEC_VERSION`](../tests/schemas/SPEC_VERSION).
The `aitp-conformance` runner drives fixtures through an adapter that
speaks the NDJSON protocol described in [`conformance.md`](conformance.md);
`aitp-rs-adapter` is the canonical Rust adapter.

```bash
cargo build -p aitp-rs-adapter -p aitp-conformance
./target/debug/aitp-conformance run \
  --target ./target/debug/aitp-rs-adapter \
  --fixtures-dir ../agentidentitytrustprotocol/schemas/conformance \
  --feature experimental-multihop-delegation \
  --feature experimental-session-bundle
```

Expected: **51 pass / 0 fail / 2 skip** with the draft features enabled
(`del-004` is a frozen v0.1 shape). The `conformance` job in `ci.yml`
runs exactly this against the pinned spec commit. See
[`conformance.md`](conformance.md) for the per-fixture matrix.

## Language bindings

Both SDKs are excluded from the Cargo workspace and built with their
native toolchains. Their test-file sets are kept at parity.

**Node** (`bindings/aitp-node`, NAPI-rs):

```bash
cd bindings/aitp-node
npm install
npm run build:debug        # the binding must be built with default features
npm test                   # node --test tests/*.mjs
```

**Python** (`bindings/aitp-py`, PyO3/maturin):

```bash
cd bindings/aitp-py
python -m venv .venv && . .venv/bin/activate
pip install maturin pytest httpx 'pyjwt[crypto]' cryptography
maturin develop           # add --no-default-features for the minimal surface
pytest tests/ -v
```

> A stale, git-tracked `aitp*.so` in the Python package dir can shadow a
> fresh `maturin develop` build — remove it if pytest imports an old
> binding.

## Cross-language interop

`make interop` (`scripts/interop.sh`) builds both bindings and runs a
real four-message Python ↔ Node handshake in both directions through the
native SDKs (`bindings/interop/`), plus third-party JOSE acceptance of
the spec's signed-example KATs. CI runs it in `bindings.yml`.

## End-to-end (LLM)

`tests/e2e-llm/` is a separate, workspace-excluded crate: two agents
handshake and then delegate, driven by live OpenAI/Anthropic calls. It
is opt-in and networked — run it by hand:

```bash
cd tests/e2e-llm
AITP_RUN_LLM_TESTS=1 cargo test
```

## Coverage

CI measures line coverage with `cargo-tarpaulin` and enforces a floor
(`--fail-under` in the `coverage` job of `ci.yml`); the report is
uploaded as a build artifact. Locally:

```bash
make coverage        # tarpaulin over the workspace, prints to stdout
```

The floor is a ratchet — raise it as coverage climbs, never lower it to
make a red run pass.
