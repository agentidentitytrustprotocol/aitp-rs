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
  [`bindings/aitp-py/aitp.pyi`](bindings/aitp-py/aitp.pyi)), with the
  runtimes and platforms listed under
  [SDK runtimes and platforms](#sdk-runtimes-and-platforms). The bindings'
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

`RevocationStatus` and `KeyResolutionOutcome` report a security or admission decision. They are
not `#[non_exhaustive]`, so a caller's `match` must name every outcome and
cannot let a new one fall into a wildcard arm that admits or ignores it.
Adding a variant to one of them is therefore always a breaking change: a
**major** release from 1.0 on (the next minor before it). A new decision
or outcome enum follows the same rule, and is listed as `exhaustive` with
that reason in [`docs/api-classification.md`](docs/api-classification.md).

### Options that relax a check end in `_dangerous`

A builder or config method of the stable surface that switches a check
off or relaxes it ends in `_dangerous` and takes no argument: calling it
is the opt-in, and not calling it keeps the check. It keeps the prefix of
the builder it belongs to (`with_` on a `with_*` builder, `without_` for
turning a feature off, none on a builder whose methods are bare names).
The ones in `aitp` are `TctVerifyContextBuilder::skip_manifest_expiry_cap_dangerous`,
`ManifestFetcher::with_insecure_localhost_dangerous`,
`RevocationFetcher::with_insecure_localhost_dangerous`,
`InitiatorConfig::with_insecure_localhost_dangerous`,
`HostGuard::allow_loopback_dangerous` and
`HandshakeServer::without_rate_limit_dangerous`. A new one follows the
same rule.

Values of a policy enum keep their names even when they name a weaker
policy, such as `RevocationFailMode::FailOpen`, `RevocationSource::FailOpen`,
`GuardMode::WarnPrivate` and `GuardMode::AllowAll`: they are chosen by
passing them, and their docs say what they relax. The CLI flags (such as
`--insecure-localhost`) and the SDKs' Python and JavaScript names are not
Rust identifiers and keep their own names.

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

## Async runtime

The HTTP features (`http-client`, `http-server`) run on tokio 1.x, and
that is permanent: `aitp` will not add a runtime abstraction, and the
stable API names tokio types where a runtime type is the honest one
(`HandshakeServer::serve` takes a `tokio::net::TcpListener`,
`spawn_session_sweeper` returns a tokio `JoinHandle`). Moving to a tokio
2.x would be a breaking `aitp` release.

- Every future the stable API returns is `Send`, so it can run in
  `tokio::spawn`. `crates/aitp/tests/send_sync_probe.rs` fails to
  compile if one stops being `Send`.
- `aitp` never blocks a runtime thread on a future (`block_on`): an
  operation that does I/O is `async`.
- Built without `http-client` (`default-features = false`), `aitp` does
  not depend on tokio.

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

## SDK runtimes and platforms

| SDK | Runtime floor | Set in |
|---|---|---|
| `aitp-sdk` (PyPI) | CPython 3.10 | `requires-python` in [`pyproject.toml`](bindings/aitp-py/pyproject.toml); one `cp310-abi3` wheel per platform |
| `@agentidentitytrustprotocol/aitp` (npm) | Node.js 20 | `engines.node` in [`package.json`](bindings/aitp-node/package.json) |

Both SDKs publish a prebuilt binary for:

- macOS x86_64 and arm64;
- Linux glibc x86_64 and aarch64 (manylinux for Python);
- Linux musl x86_64 and aarch64 (musllinux 1.2 for Python, for Alpine).

Windows binaries are built on demand only: open an issue, and the release
workflows get a Windows leg. On any other platform `aitp-sdk` builds from
its source distribution, which needs a Rust toolchain at the MSRV.

- Raising a runtime floor or dropping a platform is a breaking change.
- Adding a platform is additive.
- CI tests the Python SDK on the floor and on later CPython releases
  ([`bindings.yml`](.github/workflows/bindings.yml)).
- A pull request that touches a binding runs its release workflow as a
  dry run: every platform binary is built and smoke-tested, and nothing is
  published.

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
    methods and impls, at each public path. The impls include the derived
    traits, the `From` conversions and the auto traits (`Send`, `Sync`,
    `Unpin`, `UnwindSafe`, `RefUnwindSafe`), so losing one is a visible
    break. Only blanket impls and compiler-internal markers are left out.
    Generating it fails if a stable signature names a type no public path
    reaches.
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
- **The SDKs' API snapshots.**
  [`bindings/aitp-py/api.txt`](bindings/aitp-py/api.txt) and
  [`bindings/aitp-node/api.txt`](bindings/aitp-node/api.txt) list every
  declared item of the default build with its signature, one per line.
  [`scripts/binding-api.py`](scripts/binding-api.py) generates them from
  `aitp.pyi` and `index.d.ts`. `make binding-api-check` (CI) fails if a
  snapshot differs from its declarations, so a signature change fails CI
  until the snapshot is regenerated (`make binding-api`) and the diff is
  reviewed. The declarations follow the code: `aitp.pyi` must match the
  compiled module (`tests/test_stub_signatures.py`), and `index.d.ts` is
  regenerated by the build and diffed in `bindings.yml`.
  `binding-api.py runtime` fails unless the built default binding exports
  exactly the names its snapshot lists (`bindings.yml`, and the release
  workflows' smoke steps before upload), which also keeps every
  experimental symbol out of it. `binding-api.py breaks BASE NEW` lists
  the snapshot lines a change removed or altered.
