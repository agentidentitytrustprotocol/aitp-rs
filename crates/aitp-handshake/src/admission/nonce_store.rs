//! Single-use challenge nonces for pinned-key admission (proposal
//! agentidentitytrustprotocol#72 Item 7d).

use aitp_core::{Aid, Timestamp};
use aitp_crypto::signer::{BoxError, BoxFuture};
use std::collections::HashMap;
use std::hash::BuildHasher;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// A challenge nonce: 16 bytes from a CSPRNG (RFC-AITP-0002 §3.1).
pub type Nonce = [u8; crate::POP_NONCE_LEN];

/// One outstanding challenge, as the store records it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct IssuedNonce {
    /// The nonce.
    pub nonce: Nonce,
    /// The verifier the nonce is bound to. A presentation addressed to
    /// any other verifier does not consume it.
    pub verifier: Aid,
    /// Opaque caller-chosen source (a client IP, a tenant id). Stores MAY
    /// use it for per-source quotas; the library never interprets it.
    pub source: String,
    /// When the challenge was issued. Stores sweep expired records
    /// relative to this, so tests can run on a fixed clock.
    pub issued_at: Timestamp,
    /// Last second at which the nonce is still valid (inclusive).
    pub expires_at: Timestamp,
}

impl IssuedNonce {
    /// Build a record.
    pub fn new(
        nonce: Nonce,
        verifier: Aid,
        source: impl Into<String>,
        issued_at: Timestamp,
        expires_at: Timestamp,
    ) -> Self {
        Self {
            nonce,
            verifier,
            source: source.into(),
            issued_at,
            expires_at,
        }
    }
}

/// Result of [`NonceStore::consume`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConsumeOutcome {
    /// The nonce was outstanding for this verifier and is now gone. Only
    /// one concurrent caller ever sees this for a given nonce.
    Consumed,
    /// Never issued, already consumed, or issued for another verifier.
    Unknown,
    /// Issued for this verifier but past `expires_at`. Removed.
    Expired,
}

/// Why a store refused to record a new challenge.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NonceStoreError {
    /// The store holds its maximum number of outstanding nonces. Stores
    /// MUST refuse rather than evict a live nonce: eviction would let a
    /// flood of challenges invalidate an honest client's nonce.
    #[error("nonce store at capacity ({capacity} outstanding)")]
    AtCapacity {
        /// The configured bound.
        capacity: usize,
    },
    /// The same nonce is already outstanding (a CSPRNG failure, or a
    /// caller re-issuing a nonce).
    #[error("nonce already outstanding")]
    Duplicate,
    /// The backing service failed (Redis down, DynamoDB throttled…).
    #[error("nonce store backend: {0}")]
    Backend(#[source] BoxError),
}

/// Storage for outstanding challenge nonces.
///
/// Implementations back this with process memory
/// ([`InMemoryNonceStore`]), Redis (`SET NX PX` + `GETDEL`), DynamoDB
/// (conditional put + conditional delete) or similar. Contract:
///
/// - [`issue`](Self::issue) records a nonce, refusing at capacity
///   ([`NonceStoreError::AtCapacity`]) instead of evicting. Expired
///   records do not count against capacity.
/// - [`consume`](Self::consume) is atomic: for one nonce, at most one
///   caller across all replicas gets [`ConsumeOutcome::Consumed`].
/// - Both are cancel-safe: dropping the future leaves the store either
///   untouched or with the operation fully applied.
pub trait NonceStore: Send + Sync {
    /// Record `nonce` as outstanding.
    fn issue<'a>(&'a self, nonce: &'a IssuedNonce) -> BoxFuture<'a, Result<(), NonceStoreError>>;

    /// Atomically remove `nonce` if it is outstanding for `verifier`.
    fn consume<'a>(
        &'a self,
        nonce: &'a Nonce,
        verifier: &'a Aid,
        now: Timestamp,
    ) -> BoxFuture<'a, Result<ConsumeOutcome, NonceStoreError>>;
}

impl<T: NonceStore + ?Sized> NonceStore for std::sync::Arc<T> {
    fn issue<'a>(&'a self, nonce: &'a IssuedNonce) -> BoxFuture<'a, Result<(), NonceStoreError>> {
        (**self).issue(nonce)
    }
    fn consume<'a>(
        &'a self,
        nonce: &'a Nonce,
        verifier: &'a Aid,
        now: Timestamp,
    ) -> BoxFuture<'a, Result<ConsumeOutcome, NonceStoreError>> {
        (**self).consume(nonce, verifier, now)
    }
}

struct Entry {
    verifier: Aid,
    expires_at: Timestamp,
}

/// A process-local [`NonceStore`]: `shards` mutex-guarded maps, a
/// global outstanding-count bound, no eviction of live nonces.
///
/// Correct for a single replica. Behind a load balancer, either pin
/// challenge and presentation to one replica or use a shared store.
pub struct InMemoryNonceStore {
    shards: Box<[Mutex<HashMap<Nonce, Entry>>]>,
    capacity: usize,
    outstanding: AtomicUsize,
    hasher: std::collections::hash_map::RandomState,
}

impl InMemoryNonceStore {
    /// Default bound on outstanding nonces.
    pub const DEFAULT_CAPACITY: usize = 100_000;

    /// A store bounded at `capacity` outstanding nonces.
    pub fn new(capacity: usize) -> Self {
        let shards = std::thread::available_parallelism()
            .map(|n| (n.get() * 4).next_power_of_two())
            .unwrap_or(16)
            .clamp(1, 256);
        Self::with_shards(capacity, shards)
    }

    /// As [`Self::new`] with an explicit shard count (at least 1).
    pub fn with_shards(capacity: usize, shards: usize) -> Self {
        Self {
            shards: (0..shards.max(1))
                .map(|_| Mutex::new(HashMap::new()))
                .collect(),
            capacity,
            outstanding: AtomicUsize::new(0),
            hasher: Default::default(),
        }
    }

    /// Number of records held, expired ones included until swept.
    pub fn len(&self) -> usize {
        self.outstanding.load(Ordering::Acquire)
    }

    /// True when no records are held.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Drop every record expired at `now`. Returns how many were removed.
    /// [`issue`](NonceStore::issue) calls this itself when at capacity.
    pub fn sweep(&self, now: Timestamp) -> usize {
        let mut removed = 0;
        for shard in self.shards.iter() {
            let mut map = lock(shard);
            let before = map.len();
            map.retain(|_, e| !e.expires_at.is_in_the_past(now));
            removed += before - map.len();
        }
        self.outstanding.fetch_sub(removed, Ordering::AcqRel);
        removed
    }

    fn shard(&self, nonce: &Nonce) -> &Mutex<HashMap<Nonce, Entry>> {
        &self.shards[(self.hasher.hash_one(nonce) as usize) % self.shards.len()]
    }

    /// Reserve one slot of capacity, sweeping once if full.
    fn reserve(&self, now: Timestamp) -> Result<(), NonceStoreError> {
        for attempt in 0..2 {
            let reserved = self
                .outstanding
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                    (n < self.capacity).then_some(n + 1)
                })
                .is_ok();
            if reserved {
                return Ok(());
            }
            if attempt == 0 {
                self.sweep(now);
            }
        }
        Err(NonceStoreError::AtCapacity {
            capacity: self.capacity,
        })
    }

    fn issue_sync(&self, rec: &IssuedNonce) -> Result<(), NonceStoreError> {
        self.reserve(rec.issued_at)?;
        let mut map = lock(self.shard(&rec.nonce));
        if map.contains_key(&rec.nonce) {
            drop(map);
            self.outstanding.fetch_sub(1, Ordering::AcqRel);
            return Err(NonceStoreError::Duplicate);
        }
        map.insert(
            rec.nonce,
            Entry {
                verifier: rec.verifier.clone(),
                expires_at: rec.expires_at,
            },
        );
        Ok(())
    }

    fn consume_sync(&self, nonce: &Nonce, verifier: &Aid, now: Timestamp) -> ConsumeOutcome {
        let mut map = lock(self.shard(nonce));
        match map.get(nonce) {
            None => ConsumeOutcome::Unknown,
            // Another verifier's nonce stays outstanding for it.
            Some(e) if e.verifier != *verifier => ConsumeOutcome::Unknown,
            Some(e) => {
                let expired = e.expires_at.is_in_the_past(now);
                map.remove(nonce);
                drop(map);
                self.outstanding.fetch_sub(1, Ordering::AcqRel);
                if expired {
                    ConsumeOutcome::Expired
                } else {
                    ConsumeOutcome::Consumed
                }
            }
        }
    }
}

impl Default for InMemoryNonceStore {
    fn default() -> Self {
        Self::new(Self::DEFAULT_CAPACITY)
    }
}

impl NonceStore for InMemoryNonceStore {
    fn issue<'a>(&'a self, nonce: &'a IssuedNonce) -> BoxFuture<'a, Result<(), NonceStoreError>> {
        let r = self.issue_sync(nonce);
        Box::pin(async move { r })
    }

    fn consume<'a>(
        &'a self,
        nonce: &'a Nonce,
        verifier: &'a Aid,
        now: Timestamp,
    ) -> BoxFuture<'a, Result<ConsumeOutcome, NonceStoreError>> {
        let r = self.consume_sync(nonce, verifier, now);
        Box::pin(async move { Ok(r) })
    }
}

/// Lock, recovering from poisoning: every critical section leaves the
/// map consistent, so a panic elsewhere never corrupts it.
pub(crate) fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}
