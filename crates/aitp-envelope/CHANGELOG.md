# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.21.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-envelope-v0.20.0...aitp-envelope-v0.21.0) - 2026-10-25

### Other

- release v0.21.0 ([#339](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/339))

## [0.20.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-envelope-v0.19.0...aitp-envelope-v0.20.0) - 2026-10-25

### Added

- *(aitp)* [**breaking**] curate the facade re-exports, add a public-api snapshot ([#293](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/293)) ([#323](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/323))

## [0.17.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-envelope-v0.16.0...aitp-envelope-v0.17.0) - 2026-10-20

### Added

- [**breaking**] adopt aitp/0.3 — envelope signing input v2 and revision bump ([#253](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/253)) ([#254](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/254))

### Fixed

- *(envelope)* [**breaking**] enforce envelope schema rules for payload, timestamp and signature ([#261](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/261)) ([#262](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/262))

## [0.16.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-envelope-v0.15.0...aitp-envelope-v0.16.0) - 2026-10-19

### Other

- release v0.15.0 ([#242](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/242))

## [0.15.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-envelope-v0.14.0...aitp-envelope-v0.15.0) - 2026-10-18

### Other

- release v0.15.0 ([#222](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/222))

## [0.14.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-envelope-v0.13.2...aitp-envelope-v0.14.0) - 2026-10-17

### Added

- [**breaking**] 0.14.0 — P-256 single hash, pluggable signers, pinned-key trust store and admission (spec #72) ([#207](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/207))

## [0.12.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-envelope-v0.11.0...aitp-envelope-v0.12.0) - 2026-09-20

### Other

- *(spec)* adopt AITP spec @ 5063c08 ([#141](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/141))

## [0.9.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-envelope-v0.8.0...aitp-envelope-v0.9.0) - 2026-08-29

### Other

- release v0.8.0

## [0.8.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-envelope-v0.7.0...aitp-envelope-v0.8.0) - 2026-08-29

### Other

- release v0.8.0

## [0.7.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-envelope-v0.4.1...aitp-envelope-v0.7.0) - 2026-08-26

### Added

- *(bindings)* give verify_manifest_json a typed error with a stable code ([#92](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/92))
- *(bindings)* let callers reach the delegation revocation checks ([#93](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/93))

## [0.4.1](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-envelope-v0.4.0...aitp-envelope-v0.4.1) - 2026-07-10

### Other

- force lockstep releases via version_group + exact pins
- proptests, doctests, and drop unused insta dev-dep
- fill unit/integration gaps in adapter, envelope, session-bundle, CLI
