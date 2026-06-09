# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://github.com/agentidentitytrustprotocol/aitp-rs/releases/tag/aitp-transport-http-v0.2.0) - 2026-06-09

### Added

- *(transport)* DPoP-bound token exchange, empty revocation provider, docs + P-256 adapter readiness
- P0/P1 production hardening — panic removal, DoS bounds, semver hygiene
- Python & Node SDKs with cross-language interop tests
- rc.2 security hardening — revocation ordering, rate limiting, facade & conformance
- unified plan — fixture metadata, RFC alignment, P-256 verifier, lifecycle plumbing
- *(v0.2)* multihop delegation, session trust bundle, observability
- *(aitp-rs)* v0.1.0-beta.1 — security hardening + production layer
- aitp-rs v0.1.0-alpha.4 — Rust reference implementation

### Fixed

- enforce verifier-side identity bindings and DoS bounds
- *(semver)* keep envelope helpers locally defined; exclude new crate
- *(conformance)* canonical-form alignment, multi-hop rule, OIDC + production polish
- DPoP ath binding, TLS pinning handshake-sig, conformance nonce counter

### Other

- bump workspace version 0.1.0 → 0.2.0 for breaking changes
- v0.1.0
- rustfmt + fix broken intra-doc links
- Wire format is unchanged. Breaking source-level changes are confined to
