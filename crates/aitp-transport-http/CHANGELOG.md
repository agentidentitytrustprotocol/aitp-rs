# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.21.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-transport-http-v0.20.0...aitp-transport-http-v0.21.0) - 2026-10-25

### Fixed

- split PoP error codes; flag the CLI's unauthenticated audience default ([#334](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/334))

## [0.20.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-transport-http-v0.19.0...aitp-transport-http-v0.20.0) - 2026-10-25

### Added

- *(aitp)* [**breaking**] curate the facade re-exports, add a public-api snapshot ([#293](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/293)) ([#323](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/323))
- [**breaking**] fail-closed revocation by default ([#290](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/290)) ([#316](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/316))
- *(handshake)* [**breaking**] make PeerConfig non_exhaustive with new + with_* ([#289](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/289)) ([#314](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/314))

### Other

- *(transport-http)* [**breaking**] delete DPoP and token exchange ([#292](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/292)) ([#295](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/295))

## [0.18.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-transport-http-v0.17.0...aitp-transport-http-v0.18.0) - 2026-10-20

### Fixed

- *(revocation)* [**breaking**] report REVOCATION_SNAPSHOT_INVALID for unknown snapshot versions ([#265](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/265)) ([#266](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/266))

## [0.17.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-transport-http-v0.16.0...aitp-transport-http-v0.17.0) - 2026-10-20

### Added

- [**breaking**] adopt aitp/0.3 — envelope signing input v2 and revision bump ([#253](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/253)) ([#254](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/254))

### Fixed

- *(envelope)* [**breaking**] enforce envelope schema rules for payload, timestamp and signature ([#261](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/261)) ([#262](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/262))
- *(handshake)* [**breaking**] run RFC-AITP-0009 §3.1 checks before envelope validation ([#255](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/255)) ([#259](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/259))

## [0.15.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-transport-http-v0.14.0...aitp-transport-http-v0.15.0) - 2026-10-18

### Added

- [**breaking**] always serve ListRevoked and advertise rfc-aitp-0008.revocation_list_uri ([#225](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/225)) ([#230](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/230))
- [**breaking**] CheckedJson newtype for parse_*_wire; route bindings through hardened wire parsers (#146, #152) ([#227](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/227))

### Fixed

- *(renewal)* [**breaking**] replay-guard, re-check revocation and grants, advertise renew_uri ([#196](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/196)) ([#235](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/235))
- *(transport-http)* [**breaking**] RFC-AITP-0009 handshake defaults ([#198](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/198)) ([#231](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/231))
- *(session-bundle)* [**breaking**] RFC-AITP-0010 §5 check order, coordinator Manifest step, wrapped-only HTTP ingest, bundle_uri advertisement (#197, #195) ([#233](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/233))

### Other

- fix stale rustdoc/help text ([#200](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/200)) and mark DPoP/token exchange unsupported ([#151](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/151)) ([#219](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/219))

## [0.14.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-transport-http-v0.13.2...aitp-transport-http-v0.14.0) - 2026-10-17

### Added

- [**breaking**] 0.14.0 — P-256 single hash, pluggable signers, pinned-key trust store and admission (spec #72) ([#207](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/207))

## [0.13.2](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-transport-http-v0.13.1...aitp-transport-http-v0.13.2) - 2026-10-08

### Fixed

- *(transport-http)* map malformed manifest identity_hint to MANIFEST_INVALID ([#185](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/185))

## [0.13.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-transport-http-v0.12.0...aitp-transport-http-v0.13.0) - 2026-09-23

### Fixed

- [**breaking**] report REVOCATION_SNAPSHOT_INVALID for malformed snapshots, not SignatureInvalid ([#168](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/168))

## [0.12.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-transport-http-v0.11.0...aitp-transport-http-v0.12.0) - 2026-09-20

### Added

- adopt MANIFEST_INVALID / REVOCATION_SNAPSHOT_* codes; identity descriptor gains extensions ([#144](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/144)) ([#145](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/145))

### Other

- *(spec)* adopt AITP spec @ 5063c08 ([#141](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/141))

## [0.11.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-transport-http-v0.10.0...aitp-transport-http-v0.11.0) - 2026-08-30

### Fixed

- *(session-bundle)* reject sibling-signature wire shape; adopt spec @ 43f9d39 ([#132](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/132))
- *(handshake)* report unresolved issuer keys as KEY_RESOLUTION_FAILED ([#126](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/126))

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
