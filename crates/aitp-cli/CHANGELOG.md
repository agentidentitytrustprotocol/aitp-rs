# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.22.0](https://github.com/agentidentitytrustprotocol/aitp-rs/releases/tag/aitp-cli-v0.22.0) - 2026-10-25

### Added

- *(cli)* publish aitp-cli; add `aitp handshake` and `aitp manifest fetch` (RS4.1) ([#350](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/350))
- [**breaking**] adopt aitp/0.3 — envelope signing input v2 and revision bump ([#253](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/253)) ([#254](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/254))
- [**breaking**] 0.14.0 — P-256 single hash, pluggable signers, pinned-key trust store and admission (spec #72) ([#207](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/207))
- *(cli)* add `aitp` command-line tool (R8.1, first slice)

### Fixed

- split PoP error codes; flag the CLI's unauthenticated audience default ([#334](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/334))
- *(jcs)* [**breaking**] adopt the inner-body signing input, and fix the harnesses that hid it ([#81](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/81))

### Other

- release v0.22.0 ([#342](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/342))
- release v0.21.0 ([#339](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/339))
- release v0.20.0 ([#315](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/315))
- release v0.19.0 ([#284](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/284))
- release v0.18.0 ([#273](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/273))
- release v0.17.0 ([#257](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/257))
- release v0.16.0 ([#243](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/243))
- release v0.15.0 ([#222](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/222))
- release v0.14.0 ([#189](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/189))
- release v0.13.2 ([#186](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/186))
- release v0.13.1 ([#174](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/174))
- release v0.13.0 ([#169](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/169))
- release v0.12.0 ([#143](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/143))
- release v0.11.0 ([#125](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/125))
- release v0.9.0 ([#120](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/120))
- release v0.9.0
- release v0.8.0
- *(deps)* adapt to 8 major dependency bumps, and hold jsonwebtoken at 9.x rather than fork the crypto stack ([#98](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/98))
- release v0.7.0 ([#94](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/94))
- release v0.6.0 ([#83](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/83))
- release v0.4.1 ([#71](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/71))
- force lockstep releases via version_group + exact pins
- fill unit/integration gaps in adapter, envelope, session-bundle, CLI
