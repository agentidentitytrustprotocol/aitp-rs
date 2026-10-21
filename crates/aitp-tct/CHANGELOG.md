# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.19.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-tct-v0.18.0...aitp-tct-v0.19.0) - 2026-10-21

### Other

- release v0.19.0 ([#284](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/284))

## [0.18.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-tct-v0.17.0...aitp-tct-v0.18.0) - 2026-10-20

### Fixed

- *(revocation)* [**breaking**] report REVOCATION_SNAPSHOT_INVALID for unknown snapshot versions ([#265](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/265)) ([#266](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/266))

## [0.17.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-tct-v0.16.0...aitp-tct-v0.17.0) - 2026-10-20

### Added

- [**breaking**] adopt aitp/0.3 — envelope signing input v2 and revision bump ([#253](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/253)) ([#254](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/254))

## [0.15.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-tct-v0.14.0...aitp-tct-v0.15.0) - 2026-10-18

### Added

- [**breaking**] CheckedJson newtype for parse_*_wire; route bindings through hardened wire parsers (#146, #152) ([#227](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/227))

### Fixed

- *(renewal)* [**breaking**] replay-guard, re-check revocation and grants, advertise renew_uri ([#196](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/196)) ([#235](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/235))

## [0.14.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-tct-v0.13.2...aitp-tct-v0.14.0) - 2026-10-17

### Added

- [**breaking**] 0.14.0 — P-256 single hash, pluggable signers, pinned-key trust store and admission (spec #72) ([#207](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/207))

## [0.12.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-tct-v0.11.0...aitp-tct-v0.12.0) - 2026-09-20

### Added

- adopt MANIFEST_INVALID / REVOCATION_SNAPSHOT_* codes; identity descriptor gains extensions ([#144](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/144)) ([#145](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/145))

### Other

- *(spec)* adopt AITP spec @ 5063c08 ([#141](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/141))

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
