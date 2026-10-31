# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.24.0](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-experimental-v0.23.0...aitp-experimental-v0.24.0) - 2026-10-31

### Added

- *(experimental)* RENEWAL_UNAVAILABLE for unreadable revocation state and nonce store failures ([#459](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/459))
- *(api)* [**breaking**] RS-RC7b follow-ups: argument-free verify builders, one IdentityKind, IssuedTct/IssuedDelegation, variable-length signatures, CLI private-network opt-in ([#456](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/456))
- *(api)* [**breaking**] each stable item has one public path (RS-RC7b P8) ([#455](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/455))
- *(api)* [**breaking**] immutable verified results, durable variants, explicit names, one time model, builders, typed kinds and extensions (RS-RC7b P7) ([#454](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/454))
- *(api)* [**breaking**] HostGuard defaults to DenyPrivate; the Manifest cache takes verified Manifests; relaxing options end in _dangerous (RS-RC7b P6) ([#453](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/453))
- *(api)* [**breaking**] one revocation model; async fallible hooks; no block_on; tokio is permanent (RS-RC7b P5) ([#452](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/452))
- *(api)* [**breaking**] typed errors, ErrorCode strings, verified identities, grant policy context (RS-RC7b P4) ([#451](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/451))
- *(api)* [**breaking**] dead and duplicated surface leaves the stable API (RS-RC7b P2) ([#449](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/449))
- *(handshake)* [**breaking**] SPIFFE moves to aitp-experimental behind an IdentityVerifier hook (RS-RC4 P3) ([#437](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/437))
- *(renewal)* [**breaking**] move TCT renewal to aitp-experimental (RS-RC4 P2) ([#436](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/436))
- *(delegation)* [**breaking**] move multi-hop delegation to aitp-experimental (RS-RC4 P1) ([#435](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/435))

### Other

- [**breaking**] every stable struct and enum is non_exhaustive, private or classified exhaustive (RS-RC3) ([#413](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/413))
- [**breaking**] collapse the workspace into aitp, aitp-experimental and aitp-cli (RS-RC2) ([#411](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/411))
