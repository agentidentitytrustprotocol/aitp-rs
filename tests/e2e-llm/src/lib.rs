//! Harness for AITP tier-3 e2e tests: real LLM agents over a real
//! four-message AITP handshake, with the worker's capability endpoint
//! authenticated by a TCT.
//!
//! The package is excluded from the workspace; see this directory's
//! `README.md` for the gating story and the rationale.

pub mod llm;
pub mod planner;
pub mod worker;

use std::sync::Once;

/// Returns `Some(reason)` if the current process is not configured to
/// run live LLM tests, otherwise `None`. Callers should print the
/// reason to stderr and return early — the test still passes.
///
/// We deliberately do **not** panic on missing config: skip-by-default
/// is the whole point of the tier-3 gate.
pub fn should_skip() -> Option<String> {
    if std::env::var("AITP_RUN_LLM_TESTS").as_deref() != Ok("1") {
        return Some(
            "AITP_RUN_LLM_TESTS is not \"1\" — set it in tests/e2e-llm/.env to enable".into(),
        );
    }
    if std::env::var("ANTHROPIC_API_KEY").ok().is_none()
        && std::env::var("OPENAI_API_KEY").ok().is_none()
    {
        return Some(
            "neither ANTHROPIC_API_KEY nor OPENAI_API_KEY is set — provide at least one".into(),
        );
    }
    None
}

/// Load `.env` from the package root, if present. Called by every
/// test. Missing file is fine — env vars set on the shell still win.
pub fn load_env() {
    let _ = dotenvy::from_filename(concat!(env!("CARGO_MANIFEST_DIR"), "/.env"));
}

/// Install a tracing subscriber once per process. Subsequent calls are
/// no-ops; safe to invoke from every test.
pub fn init_tracing() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .with_test_writer()
            .try_init();
    });
}

/// Expand a short ASCII seed phrase into a 32-byte key seed by
/// tiling. Matches the convention used by `examples/two-agents`.
pub fn expand_seed(s: &str) -> [u8; 32] {
    let bytes = s.as_bytes();
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = bytes[i % bytes.len()];
    }
    out
}
