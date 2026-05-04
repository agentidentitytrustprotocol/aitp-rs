# Phase 6 — Polish and Release Prep

You are working on the `aitp-rs` Rust reference implementation. This is
Phase 6 of 6 — the final phase.

**Your goal:** the workspace is in a state worthy of cutting an
`v0.1.0-alpha.1` release. Tests pass on Linux and macOS, docs build
cleanly, the facade crate has a clear "hello world" example, and the
CHANGELOG reflects what's actually shipped.

You will NOT publish to crates.io in this phase. Publishing is a human
decision.

---

## Required reading

1. `phase-5-report.md`
2. Skim every `phase-N-report.md` to catch any cross-phase issues
3. The current `README.md` and `CHANGELOG.md` (if present)
4. `crates/aitp/src/lib.rs` (the facade)
5. `docs/design/PENDING.md` — what's still open

---

## Global rules

[All 12 apply.]

- **Stop at the phase boundary.** This is the final phase, so "stop"
  means: do not publish to crates.io, do not push tags, do not announce.

---

## Tasks

### 6.1 — Full workspace test sweep

Run every test:

```sh
cargo fmt --all
cargo clippy --workspace --all-features --all-targets -- -D warnings
cargo test --workspace --all-features
cargo test --workspace --no-default-features
cargo doc --workspace --no-deps --all-features
```

All clean. Document any flakes or warnings you see.

If `cargo doc` emits warnings about broken intra-doc links, fix them.

### 6.2 — Facade crate documentation (IMPL-045)

File: `crates/aitp/src/lib.rs`

Expand the doc comment at the top of the crate to include a working
"30-line example" demonstrating issuing and verifying a TCT:

```rust
//! # Example
//!
//! Issue a TCT to a peer and verify it:
//!
//! ```rust
//! use aitp::prelude::*;
//! use aitp::tct::TctBuilder;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Two peers each have a signing key.
//! let alice = AitpSigningKey::generate();
//! let bob = AitpSigningKey::generate();
//!
//! // Alice issues a TCT to Bob granting one capability.
//! let tct = TctBuilder::new(&alice)
//!     .subject(bob.aid().clone())
//!     .audience(bob.aid().clone())  // v0.1: audience = subject
//!     .grants(["demo.echo"])
//!     .ttl_secs(3600)
//!     .subject_pubkey(bob.verifying_key())
//!     .build()?;
//!
//! // Bob verifies the TCT against Alice's verifying key.
//! let alice_pubkey = AitpVerifyingKey::from_aid(alice.aid())?;
//! let ctx = aitp::tct::TctVerifyContext {
//!     expected_audience: bob.aid(),
//!     issuer_pubkey: &alice_pubkey,
//!     revocation_check: None,
//! };
//! aitp::tct::verify_tct(&tct, &ctx)?;
//! # Ok(())
//! # }
//! ```

Verify the doctest compiles and runs:

```sh
cargo test -p aitp --doc
```

If the API doesn't quite line up with what's been built, adjust the
doctest to match reality. Don't hand-write a doctest that doesn't
compile.

### 6.3 — Top-level README update

Update `README.md` to reflect actual implementation status. Replace the
"Status by crate" table with current state:

| Crate | Status | Notes |
|---|---|---|
| `aitp-core` | ✅ complete | All primitives, JCS vectors passing |
| `aitp-crypto` | ✅ complete | Ed25519 + JWK thumbprint |
| `aitp-manifest` | ✅ complete | Issue + verify with PoP |
| ... | | |

Add a "Quick start" section near the top:

```markdown
## Quick start

Add to your `Cargo.toml`:

\`\`\`toml
[dependencies]
aitp = "0.1"
\`\`\`

See the [crate docs](https://docs.rs/aitp) for examples, or run the
two-agent demo:

\`\`\`sh
make demo
\`\`\`
```

### 6.4 — CHANGELOG.md

Create or update `CHANGELOG.md`:

```markdown
# Changelog

All notable changes to `aitp-rs` will be documented here.
This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## v0.1.0-alpha.1 — UNRELEASED

First release with working primitives. Tracks AITP spec v0.1.0-rc.1.

### Added
- `aitp-core`: Aid, base64url, JCS, Timestamp, ExtensionsMap, AitpEnvelope, ErrorCode
- `aitp-crypto`: AitpSigningKey, AitpVerifyingKey, JWK thumbprint
- `aitp-manifest`: ManifestBuilder + verify_manifest
- `aitp-tct`: TctBuilder + verify_tct + PoP exchange
- `aitp-delegation`: DelegationBuilder + verify_delegation (single-hop)
- `aitp-handshake`: Initiator and Responder state machines
- `aitp-transport-http`: ManifestFetcher, JwksFetcher, ManifestServer, HandshakeServer
- `aitp-conformance`: runner + Adapter trait + SubprocessAdapter
- `aitp-rs-adapter`: subprocess conformance adapter for the reference impl
- `examples/two-agents`: end-to-end demo

### Known limitations
- Multi-hop delegation not supported (RFC-AITP-0011 reserved for v0.2)
- Session Trust Bundle not supported (RFC-AITP-0010 reserved)
- OIDC `cnf.jkt` requires DPoP-aware identity provider; no token-exchange
  proxy shipped in this release
- Conformance runner cannot validate against spec known-answer hashes
  until SPEC-005 lands in the spec repo
```

### 6.5 — Final PENDING.md sweep

Read `docs/design/PENDING.md` start to finish.

For each task:
- ✅ check off completed tasks
- ❌ add reasoning for tasks that won't ship in alpha.1
- 🔒 mark `BLOCKED-*` items still blocked

For Open Questions section: mark any that have been resolved as
resolved with the answer.

If there are tasks that should be done in v0.1.0-alpha.2 but aren't
worth blocking the alpha.1 release, list them under a new "Deferred to
alpha.2" section at the bottom.

### 6.6 — Cargo.toml metadata

For every crate intended to be publishable:

```toml
[package]
description = "..."         # one-line description
keywords = ["aitp", "agent", "trust", "identity"]  # max 5
categories = ["cryptography", "authentication"]    # validated against
                                                   # https://crates.io/category_slugs
homepage = "https://github.com/agentidentitytrustprotocol/aitp-rs"
documentation = "https://docs.rs/<crate-name>"
readme = "README.md"        # if a per-crate README exists
```

The `aitp-rs-adapter` and `examples/two-agents` are NOT publishable —
add `publish = false` to their Cargo.toml if not already there.

### 6.7 — Per-crate README files (optional but nice)

For each publishable crate, write a short `crates/aitp-X/README.md`
(50-100 lines) that:
- Explains what the crate is for
- Notes that it's part of the `aitp-rs` workspace and points back
- Has a short usage example

Skip this if you're short on time — `cargo doc` is enough.

### 6.8 — Tag readiness

Verify the workspace is at a clean state for tagging:

```sh
git status                                  # clean
cargo test --workspace --all-features       # green
cargo build --workspace --release           # green
cargo doc --workspace --no-deps             # no warnings
```

DO NOT push a git tag yet. Just confirm the workspace is in a state
worth tagging. The actual tag and crates.io publish is a human action.

### 6.9 — Draft release notes

Create `RELEASE_NOTES_v0.1.0-alpha.1.md` in the repo root:

```markdown
# AITP-rs v0.1.0-alpha.1

First implementation milestone for the
[Agent Identity & Trust Protocol](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol)
in Rust.

This release tracks AITP spec v0.1.0-rc.1.

## What works
- Manifest issuance, verification, and HTTP discovery
- Mutual handshake (4 messages, both pinned-key and OIDC identity)
- TCT issuance, verification, downstream PoP
- Single-hop delegation
- Conformance runner with subprocess adapter protocol

## What doesn't work yet
- Multi-hop delegation (reserved for v0.2)
- Session Trust Bundle (reserved)
- Full conformance against spec known-answer tests (waiting on spec-side
  KAT publication)

## Try it
\`\`\`sh
git clone https://github.com/agentidentitytrustprotocol/aitp-rs
cd aitp-rs
make demo
\`\`\`

## Feedback
Open issues at the repo. Especially interested in:
- Implementer experience reports
- Cross-language interop (write an adapter in $LANG and tell us what's confusing)
- Spec ambiguities you hit during implementation
```

This is for the human to use when actually publishing. Don't push it.

---

## Format, lint, doc, build

Final sweep:

```sh
cargo fmt --all
cargo clippy --workspace --all-features --all-targets -- -D warnings
cargo test --workspace --all-features
cargo test --workspace --no-default-features
cargo doc --workspace --no-deps --all-features 2>&1 | grep -i warning
cargo build --workspace --release
```

All clean.

---

## Phase report

Write `phase-6-report.md` with:

- Final test counts across the workspace
- Any clippy warnings that needed fixing
- Lines of code per crate
- A note on what's NOT in alpha.1 and why

Also, summary of the entire 6-phase journey:
- Total time taken
- Phases that were harder than expected and why
- Spec ambiguities hit (these become spec-side issues for the
  agentidentitytrustprotocol repo)
- Anything that should be different next time

---

## Success gate

- Full workspace builds, tests, docs cleanly
- `make demo` runs successfully
- Conformance runner runs against the Rust adapter
- README, CHANGELOG, and crate metadata are coherent
- A draft release notes file exists
- PENDING.md reflects reality

## Stop here

Do not push tags. Do not publish to crates.io. Do not announce. The
human reviews, decides whether to ship, and runs the publish steps if
yes.
