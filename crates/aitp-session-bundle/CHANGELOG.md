# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.17.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-session-bundle-v0.16.0...aitp-session-bundle-v0.17.0) - 2026-10-20

### Added

- [**breaking**] adopt aitp/0.3 — envelope signing input v2 and revision bump ([#253](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/253)) ([#254](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/254))

## [0.16.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-session-bundle-v0.15.0...aitp-session-bundle-v0.16.0) - 2026-10-19

### Fixed

- *(conformance,bindings)* [**breaking**] require the coordinator Manifest for session-bundle verification ([#238](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/238)) ([#247](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/247))

## [0.15.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-session-bundle-v0.14.0...aitp-session-bundle-v0.15.0) - 2026-10-18

### Added

- [**breaking**] CheckedJson newtype for parse_*_wire; route bindings through hardened wire parsers (#146, #152) ([#227](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/227))

### Fixed

- *(session-bundle)* [**breaking**] RFC-AITP-0010 §5 check order, coordinator Manifest step, wrapped-only HTTP ingest, bundle_uri advertisement (#197, #195) ([#233](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/233))

## [0.14.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-session-bundle-v0.13.2...aitp-session-bundle-v0.14.0) - 2026-10-17

### Added

- [**breaking**] 0.14.0 — P-256 single hash, pluggable signers, pinned-key trust store and admission (spec #72) ([#207](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/207))

## [0.12.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-session-bundle-v0.11.0...aitp-session-bundle-v0.12.0) - 2026-09-20

### Other

- *(spec)* adopt AITP spec @ 5063c08 ([#141](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/141))

## [0.11.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-session-bundle-v0.10.0...aitp-session-bundle-v0.11.0) - 2026-08-30

### Fixed

- *(session-bundle)* reject sibling-signature wire shape; adopt spec @ 43f9d39 ([#132](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/132))

## [0.8.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-session-bundle-v0.7.0...aitp-session-bundle-v0.8.0) - 2026-08-28

### Other

- *(xcheck)* both-directions cross-impl coverage for the session bundle ([#96](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/96))
- Adopt spec commit 45b5ef978e13: session-bundle extensions slot + shim cleanup ([#95](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/95))

## [0.7.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-session-bundle-v0.4.1...aitp-session-bundle-v0.7.0) - 2026-08-26

### Added

- *(bindings)* give verify_manifest_json a typed error with a stable code ([#92](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/92))
- *(bindings)* let callers reach the delegation revocation checks ([#93](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/93))

## [0.4.1](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-session-bundle-v0.4.0...aitp-session-bundle-v0.4.1) - 2026-07-10

### Other

- force lockstep releases via version_group + exact pins
- fill unit/integration gaps in adapter, envelope, session-bundle, CLI
