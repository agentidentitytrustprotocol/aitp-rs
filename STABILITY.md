# Stability policy

This file says which parts of aitp-rs carry a compatibility promise, what
that promise is from 1.0 on, and how CI enforces it.

## Covered

These follow [semver](https://semver.org/):

- **The `aitp` crate's stable surface.** That is every item frozen, with
  its signature, in
  [`crates/aitp/public-api.stable.txt`](crates/aitp/public-api.stable.txt),
  together with the `http-client`, `http-server`, `source-ip`,
  `pinned-admission`, `metrics` and `all` features. It includes
  `aitp::handshake::IdentityVerifier`, the hook that verifies identity
  types `aitp` does not verify itself, and `IdentityVerifyContext`.
- **The language SDKs.** `@agentidentitytrustprotocol/aitp` on npm
  (declared in [`bindings/aitp-node/index.d.ts`](bindings/aitp-node/index.d.ts))
  and `aitp-sdk` on PyPI (declared in
  [`bindings/aitp-py/aitp.pyi`](bindings/aitp-py/aitp.pyi)). The bindings'
  `experimental-*` Cargo features are not covered; the published packages
  do not enable them.

| Change to a covered surface | Release |
|---|---|
| Breaking: an item removed, renamed or changed incompatibly, a variant added to an exhaustive enum, a stricter bound | next **major** |
| Additive: a new item, feature, variant of a `#[non_exhaustive]` enum or field of a `#[non_exhaustive]` struct | next **minor** |
| A bug fix with no API change | next **patch** |

Until 1.0.0 the same rules apply one digit down: a breaking change bumps
the minor digit (0.x → 0.x+1).

The published crates (`aitp`, `aitp-experimental` and `aitp-cli`) and the
SDKs ship in lockstep at one shared version, so a breaking change anywhere
in a covered surface bumps the major digit of every package. Every
breaking release lists its breaks under `### BREAKING` in
[`CHANGELOG.md`](CHANGELOG.md).

### Decision and outcome enums are exhaustive on purpose

`HandshakeRevocationDecision`, `RevocationOutcome`, `KeyResolutionOutcome`
and `RateLimitOutcome` report a security or admission decision. They are
not `#[non_exhaustive]`, so a caller's `match` must name every outcome and
cannot let a new one fall into a wildcard arm that admits or ignores it.
Adding a variant to one of them is therefore always a breaking change: a
**major** release from 1.0 on (the next minor before it). A new decision
or outcome enum follows the same rule, and is listed as `exhaustive` with
that reason in [`docs/api-classification.md`](docs/api-classification.md).

### Behaviour that follows the spec

From 1.0, a change that brings observable behaviour into line with the
AITP RFCs, such as the order of verification steps or which error code a
defect gets, is a fix only when it closes a security hole. It then ships
in any release, under [`SECURITY.md`](SECURITY.md), with a `### Fixed`
entry that says what an application can observe. Any other spec-aligning
change an application can observe is breaking and waits for a major
release. The protocol version (`aitp/0.3`) is set by the spec, not by this
crate's version.

## Not covered

These can change or disappear in any release, including a patch:

- **`aitp-experimental`.** Multi-hop delegation
  (`aitp_experimental::delegation`, RFC-AITP-0011, Draft), Session Trust
  Bundles (`aitp_experimental::session_bundle`, RFC-AITP-0010, Draft), TCT
  renewal (`aitp_experimental::renewal`, RFC-AITP-0013, Draft), SPIFFE
  identity (`aitp_experimental::spiffe`, RFC-AITP-0002 §6, registry
  status Proposed; feature `spiffe-identity`) and their HTTP endpoints
  and client (features `http-server`, `http-client`). The crate tracks
  Draft spec text.
- **Unstable features of `aitp`.** These are `experimental-axum`
  (`HandshakeServer::into_router`, `ManifestServer::into_router` and the
  `with_request_body_limit*` helpers, which expose axum, a pre-1.0
  crate), `client-spki-pinning` and `test-util` (`crypto::testing`). Any feature named `experimental-*`
  belongs here. What each one adds is listed in
  [`public-api.experimental.txt`](crates/aitp/public-api.experimental.txt).
- **The CLI's flags and output.** `aitp-cli` is documented in
  [`docs/cli.md`](docs/cli.md), but scripts that parse its output get no
  promise.
- **Test tooling.** `aitp-conformance` (the conformance runner and the
  aitp-rs adapter, `aitp-rs-adapter`), `tools/` and the fuzz targets are
  not published.
- **The retired crates.** `aitp-core`, `aitp-crypto`, `aitp-tct`,
  `aitp-manifest`, `aitp-handshake`, `aitp-delegation`, `aitp-envelope`,
  `aitp-session-bundle` and `aitp-transport-http` are now modules of `aitp`
  (and `aitp-experimental`). Their last release is 0.23; they get no new
  APIs and no fixes.

## MSRV

The minimum supported Rust version is the workspace `rust-version` in
[`Cargo.toml`](Cargo.toml). CI builds and tests on it (the `test (… / <MSRV>)`
leg and `cargo-msrv`).

- aitp-rs builds on the latest stable Rust and the two before it (N-2):
  the MSRV is never newer than the third-newest stable release.
- An MSRV bump happens only in a minor release, never in a patch, and is
  listed in the CHANGELOG. It is not a breaking change.
- The MSRV is raised only when a dependency or a needed language feature
  forces it. [`CONTRIBUTING.md`](CONTRIBUTING.md) lists every file that moves
  with it.

## Support window

| Line | Gets |
|---|---|
| The latest minor | bug fixes and security fixes |
| The previous minor | security fixes, for 6 months after the latest minor's first release |
| Older lines | nothing; upgrade |

A fix ships as a patch release on each supported line it applies to.
Because every package ships in lockstep, a line means the same thing for
the crates and the SDKs. How to report a vulnerability is in
[`SECURITY.md`](SECURITY.md).

## Enforcement

- **`cargo-semver-checks` is a required check**
  ([`semver.yml`](.github/workflows/semver.yml)). It compares each pull
  request with its base commit.
  - On `aitp` it is **blocking**: a breaking change to `aitp`, built with
    the stable features `http-client`, `http-server`, `pinned-admission`
    and `metrics`, fails the check.
  - The same job also compares the stable signature snapshot with the
    base commit's
    ([`scripts/public-api.py`](scripts/public-api.py) `breaks`). It is
    **blocking**, and catches breaks cargo-semver-checks misses. It fails
    on a removed or changed line, and on a field or variant added to a
    struct or enum without `#[non_exhaustive]`.
  - On `aitp-experimental` it is **advisory**: breaks are reported in the
    log and never fail the check.
- **Approving an intentional break.** Add the `semver-break-approved` label
  to the pull request. The blocking step is then skipped. Instead the job
  requires at least one entry under `### BREAKING` in the `[Unreleased]`
  section of `CHANGELOG.md`, checked by
  [`scripts/check-breaking-entry.sh`](scripts/check-breaking-entry.sh).
- **`aitp public API snapshot`** fails on any change to the `aitp` surface,
  additive ones included, until the snapshots are regenerated with
  `make public-api`. Every surface change is therefore visible in the diff
  under review. There are two snapshots, both generated by
  [`scripts/public-api.py`](scripts/public-api.py):
  - [`public-api.stable.txt`](crates/aitp/public-api.stable.txt) covers the
    stable features: every item with its signature, fields, variants,
    methods and impls, at each public path. Generating it fails if a
    stable signature names a type no public path reaches.
  - [`public-api.experimental.txt`](crates/aitp/public-api.experimental.txt)
    lists what each unstable feature adds to the stable surface. It
    carries no promise, and changes to it never count as breaks.
- **`aitp public API snapshot and classification`** also checks that
  every public struct and enum in the stable surface is classified in
  [`docs/api-classification.md`](docs/api-classification.md) as
  `non_exhaustive`, `private fields` or `exhaustive`, and that each
  exhaustive one has a reason (`make api-classification-check`). Only an
  exhaustive type can gain a field or variant as a breaking change.
- **No pre-1.0 dependency in the stable surface.** A crate below 1.0 can
  break its API in any minor release, which would force a breaking
  `aitp` release. [`scripts/check-stable-deps.py`](scripts/check-stable-deps.py)
  (`make stable-deps-check`, in the same CI job) fails if a path in
  `public-api.stable.txt` names a crate that has a 0.x version in
  `aitp`'s dependency graph (`cargo metadata`). axum is pre-1.0, so the
  servers are hosted with `serve(listener)` and their routers are
  behind `experimental-axum`.
- **No experimental mechanism in the stable surface.**
  [`scripts/check-stable-experimental.py`](scripts/check-stable-experimental.py)
  (`make stable-experimental-check`, in the same CI job) fails if
  `public-api.stable.txt` names TCT renewal, Session Trust Bundles,
  SPIFFE or multi-hop delegation, apart from the `spiffe` identity-type
  wire names it lists.
- **`feature matrix`** ([`ci.yml`](.github/workflows/ci.yml)) builds,
  lints and tests `aitp` and `aitp-experimental` with each feature on its
  own (`cargo hack --each-feature`), and
  [`scripts/check-dep-surface.sh`](scripts/check-dep-surface.sh) checks
  that `pinned-admission` and `source-ip` alone pull in no HTTP stack.
- **The SDKs** do not have a signature gate yet. A snapshot check of
  `index.d.ts` and `aitp.pyi` arrives with the bindings work for 1.x
  (#403). [`scripts/check-binding-surface.py`](scripts/check-binding-surface.py)
  fails if `aitp.pyi`, `index.d.ts` or `index.js` (`make
  binding-surface-check`, CI), or the default build of either binding
  (`bindings.yml` and the release workflows' smoke steps, before upload),
  exposes an experimental symbol.
