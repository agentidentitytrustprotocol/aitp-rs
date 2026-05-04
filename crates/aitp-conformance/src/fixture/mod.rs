//! Fixture loading and parsing.

mod loader;
mod types;

pub use loader::FixtureLoader;
pub use types::{Fixture, FixtureExpected, FixtureInput, FixtureInputVariant, SequenceStep};
