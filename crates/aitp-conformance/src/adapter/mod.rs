//! Adapter trait and implementations.

pub mod subprocess;

#[cfg(feature = "in-process")]
pub mod in_process;

use serde::Deserialize;
use std::collections::HashSet;

/// An adapter that can execute conformance operations against an AITP
/// implementation.
pub trait Adapter {
    /// Initialize the adapter and learn its capabilities.
    fn init(&mut self) -> Result<AdapterInfo, AdapterError>;

    /// Execute one operation. The runner serializes params, the adapter
    /// returns either a successful result or an AITP-defined error.
    fn execute(&mut self, op: &str, params: serde_json::Value) -> Result<OpResult, AdapterError>;

    /// Clean shutdown.
    fn shutdown(&mut self) -> Result<(), AdapterError>;
}

/// Adapter capability declaration (returned from `init`).
#[derive(Debug, Clone, Deserialize)]
pub struct AdapterInfo {
    /// Human-readable implementation name.
    pub implementation: String,
    /// Implementation version.
    pub version: String,
    /// Set of operation names this adapter supports.
    pub supported_ops: HashSet<String>,
    /// Set of optional features this adapter supports.
    pub supported_features: HashSet<String>,
}

/// Result of one operation.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum OpResult {
    /// Operation succeeded with a JSON result body.
    Ok { ok: bool, result: serde_json::Value },
    /// Operation failed with an AITP error code.
    Err {
        ok: bool,
        error_code: String,
        message: String,
    },
}

/// Errors from talking to an adapter.
#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    /// Subprocess died unexpectedly.
    #[error("adapter process exited unexpectedly: {0}")]
    ProcessDied(String),
    /// Response body was malformed.
    #[error("adapter returned malformed response: {0}")]
    MalformedResponse(String),
    /// Operation not supported by this adapter.
    #[error("operation '{0}' not supported by this adapter")]
    OpNotSupported(String),
    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Timeout waiting for adapter response.
    #[error("timeout waiting for adapter response")]
    Timeout,
}
