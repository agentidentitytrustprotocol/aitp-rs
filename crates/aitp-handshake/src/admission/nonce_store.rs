//! Single-use challenge nonces for pinned-key admission (proposal
//! agentidentitytrustprotocol#72 Item 7d).
//!
//! The store moved to [`aitp_core::nonce_store`] in 0.15 so the TCT
//! renewal replay guard (`aitp-tct`) can share it; this module keeps the
//! 0.14 paths compiling.

pub use aitp_core::nonce_store::{
    ConsumeOutcome, InMemoryNonceStore, IssuedNonce, Nonce, NonceStore, NonceStoreError,
};

const _: () = assert!(aitp_core::nonce_store::NONCE_LEN == crate::POP_NONCE_LEN);

/// Lock, recovering from poisoning: every critical section leaves the
/// map consistent, so a panic elsewhere never corrupts it.
pub(crate) fn lock<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}
