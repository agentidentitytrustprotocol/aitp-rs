//! AITP Python SDK — Agent Identity & Trust Protocol.
//!
//! Thin PyO3 binding over the pure-Rust AITP protocol crates. Every
//! method consumes and produces JSON strings that are HTTP request /
//! response bodies, so agent code never sees a Rust type across the
//! boundary.
//!
//! `#![forbid(unsafe_code)]` is intentionally omitted: the PyO3 export
//! macros expand to `unsafe` glue. The underlying protocol crates keep
//! the forbid attribute.

// The PyO3 `#[pymethods]` macro expands to a result conversion that
// clippy's `useless_conversion` lint flags against the return-type
// span — a macro-expansion false positive, not our code.
#![allow(clippy::useless_conversion)]

mod agent;
mod delegation;
mod helpers;
mod session;
mod tct;

use pyo3::prelude::*;
use pyo3::wrap_pyfunction;

/// The `aitp` Python module.
#[pymodule]
fn aitp(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<agent::PyAitpAgent>()?;
    m.add_class::<session::PyInitiatorSession>()?;
    m.add_class::<session::PyResponderSession>()?;
    m.add_class::<tct::PyTctIdentity>()?;
    m.add_class::<delegation::PyDelegationVerified>()?;
    m.add_function(wrap_pyfunction!(delegation::verify_delegation_py, m)?)?;
    Ok(())
}
