# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.20.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-delegation-v0.19.0...aitp-delegation-v0.20.0) - 2026-10-25

### Added

- *(aitp)* [**breaking**] curate the facade re-exports, add a public-api snapshot ([#293](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/293)) ([#323](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/323))
- [**breaking**] fail-closed revocation by default ([#290](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/290)) ([#316](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/316))

## [0.17.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-delegation-v0.16.0...aitp-delegation-v0.17.0) - 2026-10-20

### Added

- [**breaking**] adopt aitp/0.3 — envelope signing input v2 and revision bump ([#253](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/253)) ([#254](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/254))

## [0.16.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-delegation-v0.15.0...aitp-delegation-v0.16.0) - 2026-10-19

### Fixed

- *(delegation)* [**breaking**] verify single-hop delegation under the issuer's Manifest key ([#246](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/246))

## [0.15.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-delegation-v0.14.0...aitp-delegation-v0.15.0) - 2026-10-18

### Fixed

- *(delegation)* [**breaking**] resolve multi-hop issuer keys from verified Manifests ([#202](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/202)) ([#234](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/234))

### Other

- fix stale rustdoc/help text ([#200](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/200)) and mark DPoP/token exchange unsupported ([#151](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/151)) ([#219](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/219))

## [0.14.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-delegation-v0.13.2...aitp-delegation-v0.14.0) - 2026-10-17

### Added

- [**breaking**] 0.14.0 — P-256 single hash, pluggable signers, pinned-key trust store and admission (spec #72) ([#207](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/207))

## [0.12.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-delegation-v0.11.0...aitp-delegation-v0.12.0) - 2026-09-20

### Other

- *(spec)* adopt AITP spec @ 5063c08 ([#141](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/141))

## [0.8.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-delegation-v0.7.0...aitp-delegation-v0.8.0) - 2026-08-28

### Other

- update Cargo.toml dependencies

## [0.7.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-delegation-v0.4.1...aitp-delegation-v0.7.0) - 2026-08-26

### Added

- *(bindings)* give verify_manifest_json a typed error with a stable code ([#92](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/92))
- *(bindings)* let callers reach the delegation revocation checks ([#93](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/93))

## [0.4.1](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-delegation-v0.4.0...aitp-delegation-v0.4.1) - 2026-07-10

### Other

- force lockstep releases via version_group + exact pins
