# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.20.1](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-manifest-v0.20.0...aitp-manifest-v0.20.1) - 2026-10-25

### Other

- *(spec)* adopt AITP spec @ 9f9cdd9 (RFC-AITP-0014 A2A) ([#332](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/332))

## [0.20.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-manifest-v0.19.0...aitp-manifest-v0.20.0) - 2026-10-25

### Added

- *(aitp)* [**breaking**] curate the facade re-exports, add a public-api snapshot ([#293](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/293)) ([#323](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/323))

## [0.17.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-manifest-v0.16.0...aitp-manifest-v0.17.0) - 2026-10-20

### Added

- [**breaking**] adopt aitp/0.3 — envelope signing input v2 and revision bump ([#253](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/253)) ([#254](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/254))

## [0.15.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-manifest-v0.14.0...aitp-manifest-v0.15.0) - 2026-10-18

### Added

- [**breaking**] always serve ListRevoked and advertise rfc-aitp-0008.revocation_list_uri ([#225](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/225)) ([#230](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/230))
- [**breaking**] CheckedJson newtype for parse_*_wire; route bindings through hardened wire parsers (#146, #152) ([#227](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/227))

### Fixed

- *(delegation)* [**breaking**] resolve multi-hop issuer keys from verified Manifests ([#202](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/202)) ([#234](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/234))

## [0.14.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-manifest-v0.13.2...aitp-manifest-v0.14.0) - 2026-10-17

### Added

- [**breaking**] 0.14.0 — P-256 single hash, pluggable signers, pinned-key trust store and admission (spec #72) ([#207](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/207))

## [0.13.1](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-manifest-v0.13.0...aitp-manifest-v0.13.1) - 2026-09-25

### Fixed

- *(manifest)* close the wrapped-manifest signing regression gap ([#181](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/181))

## [0.13.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-manifest-v0.12.0...aitp-manifest-v0.13.0) - 2026-09-23

### Fixed

- [**breaking**] report REVOCATION_SNAPSHOT_INVALID for malformed snapshots, not SignatureInvalid ([#168](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/168))

## [0.12.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-manifest-v0.11.0...aitp-manifest-v0.12.0) - 2026-09-20

### Other

- *(spec)* adopt AITP spec @ 5063c08 ([#141](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/141))

## [0.9.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-manifest-v0.8.0...aitp-manifest-v0.9.0) - 2026-08-29

### Fixed

- deprecate AitpVerifyingKey::to_bytes panic path

## [0.8.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-manifest-v0.7.0...aitp-manifest-v0.8.0) - 2026-08-28

### Other

- *(deps)* adapt to 8 major dependency bumps, and hold jsonwebtoken at 9.x rather than fork the crypto stack ([#98](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/98))

## [0.7.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-manifest-v0.4.1...aitp-manifest-v0.7.0) - 2026-08-26

### Added

- *(bindings)* give verify_manifest_json a typed error with a stable code ([#92](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/92))
- *(bindings)* let callers reach the delegation revocation checks ([#93](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/93))

## [0.4.1](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-manifest-v0.4.0...aitp-manifest-v0.4.1) - 2026-07-10

### Other

- force lockstep releases via version_group + exact pins
- proptests, doctests, and drop unused insta dev-dep
