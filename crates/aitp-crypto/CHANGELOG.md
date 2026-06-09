# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://github.com/agentidentitytrustprotocol/aitp-rs/releases/tag/aitp-crypto-v0.2.0) - 2026-06-09

### Added

- binding hardening — strict delegation default, OIDC mint callback, TCT verify cache
- P0/P1 production hardening — panic removal, DoS bounds, semver hygiene
- end-to-end P-256 algorithm-agility for OIDC + TCT + delegation
- algorithm-agile signing, OIDC identity, and broader SDK parity
- unified plan — fixture metadata, RFC alignment, P-256 verifier, lifecycle plumbing
- close out deferred plan — 41/41 conformance + crypto-agility wire format
- *(aitp-rs)* v0.1.0-beta.1 — security hardening + production layer
- aitp-rs v0.1.0-alpha.4 — Rust reference implementation

### Other

- bump workspace version 0.1.0 → 0.2.0 for breaking changes
- v0.1.0
- rustfmt + fix broken intra-doc links
- Wire format is unchanged. Breaking source-level changes are confined to
