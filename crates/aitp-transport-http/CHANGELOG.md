# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.10.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-transport-http-v0.9.0...aitp-transport-http-v0.10.0) - 2026-08-29

### Other

- *(aitp-handshake)* [**breaking**] drop jsonwebtoken from runtime deps ([#122](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/122))

## [0.9.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-transport-http-v0.8.0...aitp-transport-http-v0.9.0) - 2026-08-29

### Added

- [**breaking**] remove deprecated verify_dpop_proof shim

### Fixed

- deprecate AitpVerifyingKey::to_bytes panic path

## [0.8.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-transport-http-v0.7.0...aitp-transport-http-v0.8.0) - 2026-08-28

### Other

- *(deps)* adapt to 8 major dependency bumps, and hold jsonwebtoken at 9.x rather than fork the crypto stack ([#98](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/98))
- Adopt spec commit 45b5ef978e13: session-bundle extensions slot + shim cleanup ([#95](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/95))

## [0.7.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-transport-http-v0.6.0...aitp-transport-http-v0.7.0) - 2026-08-26

### Added

- *(bindings)* give verify_manifest_json a typed error with a stable code ([#92](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/92))
- *(bindings)* let callers reach the delegation revocation checks ([#93](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/93))

## [0.6.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-transport-http-v0.5.0...aitp-transport-http-v0.6.0) - 2026-08-26

### Other

- *(e2e)* revive the tier-3 suite, and cover the 0.5.0 signing input on the wire ([#85](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/85))

## [0.4.1](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-transport-http-v0.4.0...aitp-transport-http-v0.4.1) - 2026-07-10

### Added

- *(metrics)* optional operational metrics facade (R7)

### Fixed

- *(metrics)* allow dead_code in obs — server/client-only emit points

### Other

- force lockstep releases via version_group + exact pins
- proptests, doctests, and drop unused insta dev-dep
