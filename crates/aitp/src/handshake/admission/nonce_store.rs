//! Lock helper shared by the admission stores. The single-use challenge
//! nonce store is [`crate::core::nonce_store`].

/// Lock, recovering from poisoning: every critical section leaves the
/// map consistent, so a panic elsewhere never corrupts it.
pub(crate) fn lock<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}
