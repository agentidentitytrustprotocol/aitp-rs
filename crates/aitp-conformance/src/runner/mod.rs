//! Fixture executor and output formatters.

mod executor;
mod output;

pub use executor::{FixtureResult, Runner};
pub use output::{render_json, render_summary, render_tap, render_text, OutputFormat};
