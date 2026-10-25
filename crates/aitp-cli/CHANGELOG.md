# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
