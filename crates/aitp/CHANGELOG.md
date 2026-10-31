# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.24.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-v0.23.0...aitp-v0.24.0) - 2026-10-31

### Added

- *(api)* [**breaking**] RS-RC7b follow-ups: argument-free verify builders, one IdentityKind, IssuedTct/IssuedDelegation, variable-length signatures, CLI private-network opt-in ([#456](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/456))
- *(api)* [**breaking**] each stable item has one public path (RS-RC7b P8) ([#455](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/455))
- *(api)* [**breaking**] immutable verified results, durable variants, explicit names, one time model, builders, typed kinds and extensions (RS-RC7b P7) ([#454](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/454))
- *(api)* [**breaking**] HostGuard defaults to DenyPrivate; the Manifest cache takes verified Manifests; relaxing options end in _dangerous (RS-RC7b P6) ([#453](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/453))
- *(api)* [**breaking**] one revocation model; async fallible hooks; no block_on; tokio is permanent (RS-RC7b P5) ([#452](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/452))
- *(api)* [**breaking**] typed errors, ErrorCode strings, verified identities, grant policy context (RS-RC7b P4) ([#451](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/451))
- *(api)* [**breaking**] the handshake future is Send; contexts lose Copy; Debug everywhere (RS-RC7b P3) ([#450](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/450))
- *(api)* [**breaking**] dead and duplicated surface leaves the stable API (RS-RC7b P2) ([#449](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/449))
- *(api)* the stable snapshot lists derived traits, From impls and auto traits (RS-RC7b P1) ([#445](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/445))
- *(core)* [**breaking**] ErrorCode holds core registry codes only; guard the stable surface (RS-RC4 P4) ([#439](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/439))
- *(handshake)* [**breaking**] SPIFFE moves to aitp-experimental behind an IdentityVerifier hook (RS-RC4 P3) ([#437](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/437))
- *(renewal)* [**breaking**] move TCT renewal to aitp-experimental (RS-RC4 P2) ([#436](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/436))
- *(delegation)* [**breaking**] move multi-hop delegation to aitp-experimental (RS-RC4 P1) ([#435](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/435))
- *(renewal)* [**breaking**] align experimental renewal to RFC-AITP-0013 Draft (RS-RC4a) ([#433](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/433))

### Fixed

- *(handshake)* the initiator checks the MUTUAL_HELLO_ACK sender; new code PEER_MISMATCH ([#427](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/427))
- *(admission)* a zero, negative or NaN TokenBucketLimiter rate no longer panics ([#412](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/412))

### Other

- [**breaking**] no pre-1.0 crate's type in the stable surface (RS-RC5) ([#415](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/415))
- [**breaking**] every stable struct and enum is non_exhaustive, private or classified exhaustive (RS-RC3) ([#413](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/413))
- [**breaking**] collapse the workspace into aitp, aitp-experimental and aitp-cli (RS-RC2) ([#411](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/411))
- *(semver)* signature snapshots; the gate sees breaks in re-exported types (RS-RC1) ([#396](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/396))

## [0.23.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-v0.22.0...aitp-v0.23.0) - 2026-10-25

### Added

- *(cli,transport-http)* [**breaking**] interop peer `aitp serve --interop` with key enrolment and PoP `/echo` (RS4.2) ([#354](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/354))

## [0.22.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-v0.21.0...aitp-v0.22.0) - 2026-10-25

### Added

- *(handshake)* experimental SPIFFE identity verifier (RFC-AITP-0002 §6) ([#343](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/343))

## [0.20.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-v0.19.0...aitp-v0.20.0) - 2026-10-25

### Added

- *(aitp)* [**breaking**] curate the facade re-exports, add a public-api snapshot ([#293](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/293)) ([#323](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/323))
- [**breaking**] fail-closed revocation by default ([#290](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/290)) ([#316](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/316))
- *(handshake)* [**breaking**] make PeerConfig non_exhaustive with new + with_* ([#289](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/289)) ([#314](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/314))

## [0.19.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-v0.18.0...aitp-v0.19.0) - 2026-10-20

### Other

- Lockstep release with no Rust API or behaviour change. 0.19.0 changes the Python and Node bindings: wire-bound UUIDs are strict, and `revoked_jtis` is normalized and fails closed ([#279](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/279)). It also fixes the conformance adapter ([#278](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/278)). See the root `CHANGELOG.md` and `docs/upgrading-0.19.md`.

## [0.17.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-v0.16.0...aitp-v0.17.0) - 2026-10-20

### Added

- [**breaking**] adopt aitp/0.3 — envelope signing input v2 and revision bump ([#253](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/253)) ([#254](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/254))

### Fixed

- *(handshake)* [**breaking**] run RFC-AITP-0009 §3.1 checks before envelope validation ([#255](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/255)) ([#259](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/259))

## [0.15.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-v0.14.0...aitp-v0.15.0) - 2026-10-18

### Added

- [**breaking**] CheckedJson newtype for parse_*_wire; route bindings through hardened wire parsers (#146, #152) ([#227](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/227))

### Fixed

- *(renewal)* [**breaking**] replay-guard, re-check revocation and grants, advertise renew_uri ([#196](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/196)) ([#235](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/235))
- *(transport-http)* [**breaking**] RFC-AITP-0009 handshake defaults ([#198](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/198)) ([#231](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/231))

## [0.14.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-v0.13.2...aitp-v0.14.0) - 2026-10-17

### Added

- [**breaking**] 0.14.0 — P-256 single hash, pluggable signers, pinned-key trust store and admission (spec #72) ([#207](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/207))

## [0.12.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-v0.11.0...aitp-v0.12.0) - 2026-09-20

### Other

- *(spec)* adopt AITP spec @ 5063c08 ([#141](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/141))

## [0.9.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-v0.8.0...aitp-v0.9.0) - 2026-08-29

### Fixed

- deprecate AitpVerifyingKey::to_bytes panic path

### Other

- dependency & CI hygiene for the workspace and bindings

## [0.8.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-v0.7.0...aitp-v0.8.0) - 2026-08-28

### Other

- *(deps)* adapt to 8 major dependency bumps, and hold jsonwebtoken at 9.x rather than fork the crypto stack ([#98](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/98))

## [0.7.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-v0.4.1...aitp-v0.7.0) - 2026-08-26

### Added

- *(bindings)* give verify_manifest_json a typed error with a stable code ([#92](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/92))
- *(bindings)* let callers reach the delegation revocation checks ([#93](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/93))

## [0.4.1](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-v0.4.0...aitp-v0.4.1) - 2026-07-10

### Other

- force lockstep releases via version_group + exact pins
- proptests, doctests, and drop unused insta dev-dep
