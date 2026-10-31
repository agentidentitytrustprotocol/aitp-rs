# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.24.1](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-cli-v0.24.0...aitp-cli-v0.24.1) - 2026-10-31

### Other

- release v0.24.1 ([#466](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/466))

## [0.24.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-cli-v0.23.0...aitp-cli-v0.24.0) - 2026-10-31

### Added

- *(api)* [**breaking**] RS-RC7b follow-ups: argument-free verify builders, one IdentityKind, IssuedTct/IssuedDelegation, variable-length signatures, CLI private-network opt-in ([#456](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/456))
- *(api)* [**breaking**] each stable item has one public path (RS-RC7b P8) ([#455](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/455))
- *(api)* [**breaking**] immutable verified results, durable variants, explicit names, one time model, builders, typed kinds and extensions (RS-RC7b P7) ([#454](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/454))
- *(api)* [**breaking**] HostGuard defaults to DenyPrivate; the Manifest cache takes verified Manifests; relaxing options end in _dangerous (RS-RC7b P6) ([#453](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/453))
- *(api)* [**breaking**] one revocation model; async fallible hooks; no block_on; tokio is permanent (RS-RC7b P5) ([#452](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/452))
- *(api)* [**breaking**] typed errors, ErrorCode strings, verified identities, grant policy context (RS-RC7b P4) ([#451](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/451))
- *(api)* [**breaking**] dead and duplicated surface leaves the stable API (RS-RC7b P2) ([#449](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/449))

### Fixed

- *(cli)* aitp enroll and aitp echo's /echo request go through the host guard ([#457](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/457))
- *(cli)* name the token type when tct inspect/verify gets a non-TCT JWS ([#448](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/448))
- *(serve)* drain an over-limit body before the 413 ([#380](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/380)) ([#386](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/386))

### Other

- [**breaking**] no pre-1.0 crate's type in the stable surface (RS-RC5) ([#415](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/415))
- [**breaking**] every stable struct and enum is non_exhaustive, private or classified exhaustive (RS-RC3) ([#413](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/413))

## [0.23.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-cli-v0.22.0...aitp-cli-v0.23.0) - 2026-10-25

### Added

- *(cli,transport-http)* [**breaking**] interop peer `aitp serve --interop` with key enrolment and PoP `/echo` (RS4.2) ([#354](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/354))

### Other

- *(cli)* take now after minting in own_tct_checks_issuer_audience_and_grant ([#358](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/358))
- *(aitp-cli)* release v0.22.0 ([#352](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/352))

## [0.22.0](https://github.com/agentidentitytrustprotocol/aitp-rs/releases/tag/aitp-cli-v0.22.0) - 2026-10-25

First crates.io release of the `aitp` command-line tool, versioned in
lockstep with the `aitp` library crates.

### Added

- *(cli)* publish aitp-cli; add `aitp handshake` and `aitp manifest fetch` (RS4.1) ([#350](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/350))
- *(cli)* offline commands: `aitp keygen`, `aitp aid`, `aitp tct inspect` / `verify`, `aitp manifest verify`
