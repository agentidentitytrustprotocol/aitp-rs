# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.11.1](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-session-bundle-v0.11.0...aitp-session-bundle-v0.11.1) - 2026-08-30

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
