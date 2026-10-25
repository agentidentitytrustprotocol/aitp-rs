# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.21.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-handshake-v0.20.0...aitp-handshake-v0.21.0) - 2026-10-25

### Other

- release v0.21.0 ([#339](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/339))

## [0.20.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-handshake-v0.19.0...aitp-handshake-v0.20.0) - 2026-10-25

### Added

- *(aitp)* [**breaking**] curate the facade re-exports, add a public-api snapshot ([#293](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/293)) ([#323](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/323))
- [**breaking**] fail-closed revocation by default ([#290](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/290)) ([#316](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/316))
- *(handshake)* [**breaking**] make PeerConfig non_exhaustive with new + with_* ([#289](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/289)) ([#314](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/314))

### Other

- *(transport-http)* [**breaking**] delete DPoP and token exchange ([#292](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/292)) ([#295](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/295))

## [0.17.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-handshake-v0.16.0...aitp-handshake-v0.17.0) - 2026-10-20

### Added

- [**breaking**] adopt aitp/0.3 — envelope signing input v2 and revision bump ([#253](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/253)) ([#254](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/254))

## [0.15.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-handshake-v0.14.0...aitp-handshake-v0.15.0) - 2026-10-18

### Added

- [**breaking**] vendor spec cfd2f16; pinned admission 429 vs 503 ([#226](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/226)) ([#229](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/229))
- [**breaking**] CheckedJson newtype for parse_*_wire; route bindings through hardened wire parsers (#146, #152) ([#227](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/227))

### Fixed

- *(renewal)* [**breaking**] replay-guard, re-check revocation and grants, advertise renew_uri ([#196](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/196)) ([#235](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/235))

## [0.14.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-handshake-v0.13.2...aitp-handshake-v0.14.0) - 2026-10-17

### Added

- [**breaking**] 0.14.0 — P-256 single hash, pluggable signers, pinned-key trust store and admission (spec #72) ([#207](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/207))

## [0.12.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-handshake-v0.11.0...aitp-handshake-v0.12.0) - 2026-09-20

### Added

- adopt MANIFEST_INVALID / REVOCATION_SNAPSHOT_* codes; identity descriptor gains extensions ([#144](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/144)) ([#145](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/145))

### Other

- *(spec)* adopt AITP spec @ 5063c08 ([#141](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/141))

## [0.11.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-handshake-v0.10.0...aitp-handshake-v0.11.0) - 2026-08-30

### Fixed

- [**breaking**] encode pinned-key proof timestamp as ASCII-decimal per RFC-AITP-0002 erratum ([#134](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/134))
- *(handshake)* report unresolved issuer keys as KEY_RESOLUTION_FAILED ([#126](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/126))

## [0.10.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-handshake-v0.9.0...aitp-handshake-v0.10.0) - 2026-08-29

### Other

- *(aitp-handshake)* [**breaking**] drop jsonwebtoken from runtime deps ([#122](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/122))

## [0.9.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-handshake-v0.8.0...aitp-handshake-v0.9.0) - 2026-08-29

### Fixed

- deprecate AitpVerifyingKey::to_bytes panic path

## [0.8.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-handshake-v0.7.0...aitp-handshake-v0.8.0) - 2026-08-28

### Other

- *(deps)* adapt to 8 major dependency bumps, and hold jsonwebtoken at 9.x rather than fork the crypto stack ([#98](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/98))

## [0.7.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-handshake-v0.4.1...aitp-handshake-v0.7.0) - 2026-08-26

### Added

- *(bindings)* give verify_manifest_json a typed error with a stable code ([#92](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/92))
- *(bindings)* let callers reach the delegation revocation checks ([#93](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/93))

## [0.4.1](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-handshake-v0.4.0...aitp-handshake-v0.4.1) - 2026-07-10

### Other

- force lockstep releases via version_group + exact pins
