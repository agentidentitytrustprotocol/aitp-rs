//! Fixture loading and parsing.

mod loader;
mod placeholder;
mod spiffe;
mod types;

pub use loader::FixtureLoader;
pub(crate) use placeholder::strip_claims_companions;
pub use placeholder::{RunnerContext, REFERENCE_NOW};
pub use types::{
    Fixture, FixtureExpected, FixtureInput, FixtureInputVariant, FixtureStatus, SequenceStep,
};
