//! AITP conformance test runner.
//!
//! Loads fixtures from `schemas/conformance/` (in the spec repo), executes
//! them against an [`Adapter`], and reports pass/fail.
//!
//! See [`docs/conformance.md`](../../../../docs/conformance.md)
//! for the architectural design.

#![forbid(unsafe_code)]

pub mod adapter;
pub mod fixture;
pub mod ops;
pub mod runner;

pub use adapter::{Adapter, AdapterError, AdapterInfo, OpResult};
pub use fixture::{Fixture, FixtureLoader};
pub use runner::{FixtureResult, Runner};
