# Stability policy

This file says which parts of aitp-rs carry a compatibility promise, what
that promise is, and how CI enforces it.

## The `aitp` crate follows semver

The [`aitp`](crates/aitp) crate is the supported way to use this
implementation. Its stable surface consists of:

- every item frozen, with its signature, in
  [`crates/aitp/public-api.stable.txt`](crates/aitp/public-api.stable.txt);
- the `http-client`, `http-server`, `source-ip`, `pinned-admission`,
  `metrics` and `all` features.

It is outside the unstable features listed below. That surface has
followed [semver](https://semver.org/) since 0.20.

While aitp-rs is pre-1.0:

| Change to the stable surface | Release |
|---|---|
| Breaking: an item removed, renamed or changed incompatibly, a variant added to an exhaustive enum, a stricter bound | next **minor** (0.x → 0.x+1) |
| Additive or a fix | next **patch** |

At 1.0 the usual rules take over, with breaking changes in a major release.

### Decision and outcome enums are exhaustive on purpose

`HandshakeRevocationDecision`, `RevocationOutcome`, `KeyResolutionOutcome`
and `RateLimitOutcome` report a security or admission decision. They are
not `#[non_exhaustive]`, so a caller's `match` must name every outcome and
cannot let a new one fall into a wildcard arm that admits or ignores it.
Adding a variant to one of them is therefore always a breaking change: a
**major** release from 1.0 on (the next minor before it). A new decision
or outcome enum follows the same rule, and is listed as `exhaustive` with
that reason in [`docs/api-classification.md`](docs/api-classification.md).

The published crates (`aitp`, `aitp-experimental` and `aitp-cli`) ship in
lockstep at one shared version, so a breaking change anywhere in the stable
surface bumps the minor digit of every crate.
Every breaking release lists its breaks under `### BREAKING` in
[`CHANGELOG.md`](CHANGELOG.md).

A change that brings behaviour into line with the AITP RFCs is a fix, not a
break, even when an application can observe it. Examples include the order
of verification steps and which error code a defect gets. Such a change can
ship in any release, with a `### Fixed` entry. The protocol version (`aitp/0.3`)
is set by the spec, not by this crate's version.

## No promise

- **`aitp-experimental`.** Session Trust Bundles
  (`aitp_experimental::session_bundle`, RFC-AITP-0010, Draft) and their
  HTTP endpoint (feature `http-server`). The crate tracks Draft spec text
  and can change or lose items in any release, including a patch.
- **Unstable features of `aitp`.** These are `experimental-renewal`
  (`facade::renew_tct`, `TctStore::needs_refresh` and the `tct` renewal
  items), `experimental-spiffe-identity` (`handshake::identity_spiffe`),
  `client-spki-pinning` and `test-util` (`crypto::testing`). Any feature
  named `experimental-*` belongs here. They can change or disappear in any
  release.
- **The retired crates.** `aitp-core`, `aitp-crypto`, `aitp-tct`,
  `aitp-manifest`, `aitp-handshake`, `aitp-delegation`, `aitp-envelope`,
  `aitp-session-bundle` and `aitp-transport-http` are now modules of `aitp`
  (and `aitp-experimental`). Their last release is 0.23; they get no new
  APIs.
- **`aitp-cli`.** The CLI's flags and output are documented in
  [`docs/cli.md`](docs/cli.md), but they are not covered by this policy.
- **`aitp-conformance`.** The conformance runner and the aitp-rs adapter
  (`aitp_conformance::rs_adapter`, binary `aitp-rs-adapter`) are test
  tooling and are not published.

## MSRV

The minimum supported Rust version is the workspace `rust-version` in
[`Cargo.toml`](Cargo.toml). CI builds and tests on it (the `test (… / <MSRV>)`
leg and `cargo-msrv`).

- An MSRV bump happens only in a minor release, never in a patch, and is
  listed in the CHANGELOG.
- The MSRV is raised only when a dependency or a needed language feature
  forces it. [`CONTRIBUTING.md`](CONTRIBUTING.md) lists every file that moves
  with it.

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
  The release that ships the break bumps the minor digit.
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
- **`feature matrix`** ([`ci.yml`](.github/workflows/ci.yml)) builds,
  lints and tests `aitp` and `aitp-experimental` with each feature on its
  own (`cargo hack --each-feature`), and
  [`scripts/check-dep-surface.sh`](scripts/check-dep-surface.sh) checks
  that `pinned-admission` and `source-ip` alone pull in no HTTP stack.

Security fixes are covered separately, in [`SECURITY.md`](SECURITY.md).
