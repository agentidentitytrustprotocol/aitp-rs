# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.11.1](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-handshake-v0.11.0...aitp-handshake-v0.11.1) - 2026-08-30

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
