//! Fixture loading and parsing.

mod loader;
mod placeholder;
mod types;

pub use loader::FixtureLoader;
pub use placeholder::{RunnerContext, REFERENCE_NOW};
pub use types::{Fixture, FixtureExpected, FixtureInput, FixtureInputVariant, SequenceStep};
