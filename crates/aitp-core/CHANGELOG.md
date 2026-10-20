# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.17.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-core-v0.16.0...aitp-core-v0.17.0) - 2026-10-20

### Added

- [**breaking**] adopt aitp/0.3 — envelope signing input v2 and revision bump ([#253](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/253)) ([#254](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/254))

### Fixed

- *(envelope)* [**breaking**] enforce envelope schema rules for payload, timestamp and signature ([#261](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/261)) ([#262](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/262))

## [0.15.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-core-v0.14.0...aitp-core-v0.15.0) - 2026-10-18

### Added

- [**breaking**] CheckedJson newtype for parse_*_wire; route bindings through hardened wire parsers (#146, #152) ([#227](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/227))

### Fixed

- *(renewal)* [**breaking**] replay-guard, re-check revocation and grants, advertise renew_uri ([#196](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/196)) ([#235](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/235))

## [0.14.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-core-v0.13.2...aitp-core-v0.14.0) - 2026-10-17

### Added

- [**breaking**] 0.14.0 — P-256 single hash, pluggable signers, pinned-key trust store and admission (spec #72) ([#207](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/207))

## [0.12.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-core-v0.11.0...aitp-core-v0.12.0) - 2026-09-20

### Added

- adopt MANIFEST_INVALID / REVOCATION_SNAPSHOT_* codes; identity descriptor gains extensions ([#144](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/144)) ([#145](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/145))

### Other

- *(spec)* adopt AITP spec @ 5063c08 ([#141](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/141))

## [0.11.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-core-v0.10.0...aitp-core-v0.11.0) - 2026-08-30

### Fixed

- *(session-bundle)* reject sibling-signature wire shape; adopt spec @ 43f9d39 ([#132](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/132))

## [0.9.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-core-v0.8.0...aitp-core-v0.9.0) - 2026-08-29

### Other

- add criterion benchmarks for JCS/JWS/TCT hot paths

## [0.8.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-core-v0.7.0...aitp-core-v0.8.0) - 2026-08-28

### Other

- *(deps)* adapt to 8 major dependency bumps, and hold jsonwebtoken at 9.x rather than fork the crypto stack ([#98](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/98))

## [0.7.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-core-v0.4.1...aitp-core-v0.7.0) - 2026-08-26

### Added

- *(bindings)* give verify_manifest_json a typed error with a stable code ([#92](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/92))
- *(bindings)* let callers reach the delegation revocation checks ([#93](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/93))

## [0.4.1](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-core-v0.4.0...aitp-core-v0.4.1) - 2026-07-10

### Other

- proptests, doctests, and drop unused insta dev-dep
