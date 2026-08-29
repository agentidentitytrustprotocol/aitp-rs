# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.9.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-tct-v0.8.0...aitp-tct-v0.9.0) - 2026-08-29

### Other

- add criterion benchmarks for JCS/JWS/TCT hot paths

## [0.8.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-tct-v0.7.0...aitp-tct-v0.8.0) - 2026-08-28

### Other

- update Cargo.toml dependencies

## [0.7.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-tct-v0.6.0...aitp-tct-v0.7.0) - 2026-08-26

### Added

- *(bindings)* give verify_manifest_json a typed error with a stable code ([#92](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/92))
- *(bindings)* let callers reach the delegation revocation checks ([#93](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/93))

## [0.6.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-tct-v0.5.0...aitp-tct-v0.6.0) - 2026-08-26

### Added

- *(bindings)* bind verify_revocation_list in Python and Node ([#90](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/90))

## [0.4.1](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-tct-v0.4.0...aitp-tct-v0.4.1) - 2026-07-10

### Other

- force lockstep releases via version_group + exact pins
- proptests, doctests, and drop unused insta dev-dep
- fix stale 0.4-era drift across guides and SDK READMEs
