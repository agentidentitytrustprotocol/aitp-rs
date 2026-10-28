//! Single-use challenge nonces for pinned-key admission (proposal
//! agentidentitytrustprotocol#72 Item 7d).
//!
//! The store is [`crate::core::nonce_store`]; this module re-exports it
//! under the 0.14 paths.

pub use crate::core::nonce_store::{
    ConsumeOutcome, InMemoryNonceStore, IssuedNonce, Nonce, NonceStore, NonceStoreError,
};

/// Lock, recovering from poisoning: every critical section leaves the
/// map consistent, so a panic elsewhere never corrupts it.
pub(crate) fn lock<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}
