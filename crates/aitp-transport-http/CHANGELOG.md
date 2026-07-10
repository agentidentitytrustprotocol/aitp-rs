# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.1](https://github.com/agentidentitytrustprotocol/aitp-rs/compare/aitp-transport-http-v0.4.0...aitp-transport-http-v0.4.1) - 2026-07-10

### Added

- *(metrics)* optional operational metrics facade (R7)

### Fixed

- *(metrics)* allow dead_code in obs — server/client-only emit points

### Other

- force lockstep releases via version_group + exact pins
- proptests, doctests, and drop unused insta dev-dep
