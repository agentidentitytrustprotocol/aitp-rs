//! Single-use challenge nonces for pinned-key admission (proposal
//! agentidentitytrustprotocol#72 Item 7d).

use aitp_core::{Aid, Timestamp};
use aitp_crypto::signer::{BoxError, BoxFuture};
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::hash::BuildHasher;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

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
    /// The requester, as [`ChallengeSource`](super::ChallengeSource)'s
    /// `Display` renders it (transport key, then any label). Stores MAY
    /// use it for audit or quotas; the library never reads it back.
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
        /// When a slot is expected to free up (the earliest outstanding
        /// expiry), if the store knows. Surfaces as
        /// `ChallengeRefused::retry_after`.
        retry_after: Option<Duration>,
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

/// One shard: the records, plus a min-heap of `(expires_at, nonce)` so
/// expired records are found without a scan. A consumed record leaves a
/// stale heap entry behind, skipped when popped; the heap is rebuilt
/// when stale entries outnumber live ones, which keeps it O(live).
#[derive(Default)]
struct Shard {
    map: HashMap<Nonce, Entry>,
    expiry: BinaryHeap<Reverse<(i64, Nonce)>>,
}

impl Shard {
    /// Pop every record expired at `now`. Amortised O(log n) per record
    /// ever issued: each heap entry is popped once.
    fn purge(&mut self, now: Timestamp) -> usize {
        let mut removed = 0;
        while let Some(&Reverse((exp, nonce))) = self.expiry.peek() {
            if !Timestamp(exp).is_in_the_past(now) {
                break;
            }
            self.expiry.pop();
            if self.map.get(&nonce).is_some_and(|e| e.expires_at.0 == exp) {
                self.map.remove(&nonce);
                removed += 1;
            }
        }
        removed
    }

    fn compact(&mut self) {
        if self.expiry.len() > 2 * self.map.len() + 64 {
            self.expiry = self
                .map
                .iter()
                .map(|(n, e)| Reverse((e.expires_at.0, *n)))
                .collect();
        }
    }

    /// Earliest expiry still in the heap. A stale entry can make this
    /// early, never late, so a `Retry-After` drawn from it is safe.
    fn earliest(&self) -> Option<i64> {
        self.expiry.peek().map(|Reverse((exp, _))| *exp)
    }
}

/// A process-local [`NonceStore`]: `shards` mutex-guarded maps, a
/// global outstanding-count bound, no eviction of live nonces.
///
/// Expiry costs amortised O(log n) per nonce: each shard keeps an expiry
/// heap and drops its expired records whenever it is touched. At
/// capacity a full sweep runs at most once per second of the caller's
/// clock, so a flood of refused challenges is O(1) each, not a scan.
///
/// Correct for a single replica. Behind a load balancer, either pin
/// challenge and presentation to one replica or use a shared store.
pub struct InMemoryNonceStore {
    shards: Box<[Mutex<Shard>]>,
    capacity: usize,
    outstanding: AtomicUsize,
    /// Second of the last at-capacity full sweep.
    last_sweep: AtomicI64,
    /// Lower bound on the earliest outstanding expiry; `i64::MAX` when
    /// nothing is outstanding.
    next_expiry: AtomicI64,
    full_sweeps: AtomicUsize,
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
            shards: (0..shards.max(1)).map(|_| Mutex::default()).collect(),
            capacity,
            outstanding: AtomicUsize::new(0),
            last_sweep: AtomicI64::new(i64::MIN),
            next_expiry: AtomicI64::new(i64::MAX),
            full_sweeps: AtomicUsize::new(0),
            hasher: Default::default(),
        }
    }

    /// Number of records held. An expired record counts until its shard
    /// is next touched or [`Self::sweep`] runs.
    pub fn len(&self) -> usize {
        self.outstanding.load(Ordering::Acquire)
    }

    /// True when no records are held.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The configured bound.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Drop every record expired at `now`. Returns how many were removed.
    /// O(shards + expired records). [`issue`](NonceStore::issue) calls
    /// this itself, at most once per second, when at capacity.
    pub fn sweep(&self, now: Timestamp) -> usize {
        let mut removed = 0;
        let mut earliest = i64::MAX;
        for shard in self.shards.iter() {
            let mut sh = lock(shard);
            removed += sh.purge(now);
            sh.compact();
            if let Some(e) = sh.earliest() {
                earliest = earliest.min(e);
            }
        }
        self.release(removed);
        // A concurrent issue may lower it again; that only makes it earlier.
        self.next_expiry.store(earliest, Ordering::Release);
        removed
    }

    fn release(&self, n: usize) {
        if n > 0 {
            self.outstanding.fetch_sub(n, Ordering::AcqRel);
            gauge_outstanding(self.len());
        }
    }

    fn shard(&self, nonce: &Nonce) -> &Mutex<Shard> {
        &self.shards[(self.hasher.hash_one(nonce) as usize) % self.shards.len()]
    }

    fn try_reserve(&self) -> bool {
        self.outstanding
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < self.capacity).then_some(n + 1)
            })
            .is_ok()
    }

    /// Reserve one slot of capacity. When full, sweep, but only if no
    /// sweep has run yet in this second of `now`.
    fn reserve(&self, now: Timestamp) -> Result<(), NonceStoreError> {
        if self.try_reserve() {
            return Ok(());
        }
        if self.last_sweep.fetch_max(now.0, Ordering::AcqRel) < now.0 {
            self.full_sweeps.fetch_add(1, Ordering::Relaxed);
            self.sweep(now);
            if self.try_reserve() {
                return Ok(());
            }
        }
        Err(NonceStoreError::AtCapacity {
            capacity: self.capacity,
            retry_after: self.retry_after(now),
        })
    }

    /// Time until the earliest outstanding nonce stops counting:
    /// `expires_at` is inclusive, so the second after it.
    fn retry_after(&self, now: Timestamp) -> Option<Duration> {
        match self.next_expiry.load(Ordering::Acquire) {
            i64::MAX => None,
            exp => Some(Duration::from_secs(
                exp.saturating_add(1).saturating_sub(now.0).max(1) as u64,
            )),
        }
    }

    fn issue_sync(&self, rec: &IssuedNonce) -> Result<(), NonceStoreError> {
        let now = rec.issued_at;
        let freed = lock(self.shard(&rec.nonce)).purge(now);
        self.release(freed);
        self.reserve(now)?;
        let mut sh = lock(self.shard(&rec.nonce));
        if sh.map.contains_key(&rec.nonce) {
            drop(sh);
            self.release(1);
            return Err(NonceStoreError::Duplicate);
        }
        sh.map.insert(
            rec.nonce,
            Entry {
                verifier: rec.verifier.clone(),
                expires_at: rec.expires_at,
            },
        );
        sh.expiry.push(Reverse((rec.expires_at.0, rec.nonce)));
        sh.compact();
        drop(sh);
        self.next_expiry
            .fetch_min(rec.expires_at.0, Ordering::AcqRel);
        gauge_outstanding(self.len());
        Ok(())
    }

    fn consume_sync(&self, nonce: &Nonce, verifier: &Aid, now: Timestamp) -> ConsumeOutcome {
        let mut sh = lock(self.shard(nonce));
        let outcome = match sh.map.get(nonce) {
            None => ConsumeOutcome::Unknown,
            // Another verifier's nonce stays outstanding for it.
            Some(e) if e.verifier != *verifier => ConsumeOutcome::Unknown,
            Some(e) => {
                let expired = e.expires_at.is_in_the_past(now);
                sh.map.remove(nonce);
                sh.compact();
                drop(sh);
                self.release(1);
                return if expired {
                    ConsumeOutcome::Expired
                } else {
                    ConsumeOutcome::Consumed
                };
            }
        };
        let freed = sh.purge(now);
        drop(sh);
        self.release(freed);
        outcome
    }
}

#[cfg(feature = "metrics")]
fn gauge_outstanding(n: usize) {
    metrics::gauge!(super::metrics_names::NONCES_OUTSTANDING).set(n as f64);
}

#[cfg(not(feature = "metrics"))]
fn gauge_outstanding(_n: usize) {}

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

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(store_nonce: u8, exp: i64, now: i64) -> IssuedNonce {
        let aid = aitp_crypto::AitpSigningKey::from_ed25519_seed(&[1; 32])
            .aid()
            .clone();
        IssuedNonce::new(
            [store_nonce; crate::POP_NONCE_LEN],
            aid,
            "t",
            Timestamp(now),
            Timestamp(exp),
        )
    }

    fn issue(s: &InMemoryNonceStore, r: &IssuedNonce) -> Result<(), NonceStoreError> {
        s.issue_sync(r)
    }

    /// A flood of refused issues within one second costs one full sweep.
    #[test]
    fn at_capacity_flood_sweeps_once_per_second() {
        let s = InMemoryNonceStore::with_shards(4, 4);
        for i in 0..4 {
            issue(&s, &rec(i, 1_000, 0)).unwrap();
        }
        for i in 0..1_000u32 {
            let r = rec((4 + i % 200) as u8, 1_000, 10);
            assert!(matches!(
                issue(&s, &r),
                Err(NonceStoreError::AtCapacity { .. })
            ));
        }
        assert_eq!(s.full_sweeps.load(Ordering::Relaxed), 1);
        // The next second may sweep again.
        let _ = issue(&s, &rec(250, 1_000, 11));
        assert_eq!(s.full_sweeps.load(Ordering::Relaxed), 2);
    }

    /// Expiry need not be issue-ordered (the TTL is per call).
    #[test]
    fn out_of_order_expiry_is_purged() {
        let s = InMemoryNonceStore::with_shards(2, 1);
        issue(&s, &rec(1, 100, 0)).unwrap();
        issue(&s, &rec(2, 50, 0)).unwrap();
        // At 60 only nonce 2 has expired; it frees its slot.
        issue(&s, &rec(3, 200, 60)).unwrap();
        assert_eq!(s.len(), 2);
        let aid = rec(0, 0, 0).verifier;
        assert_eq!(
            s.consume_sync(&[1; crate::POP_NONCE_LEN], &aid, Timestamp(60)),
            ConsumeOutcome::Consumed
        );
    }

    /// Consumed records leave stale heap entries; compaction bounds them.
    #[test]
    fn stale_heap_entries_stay_bounded() {
        let s = InMemoryNonceStore::with_shards(10, 1);
        let aid = rec(0, 0, 0).verifier;
        for i in 0..10_000u32 {
            let mut n = [0u8; crate::POP_NONCE_LEN];
            n[..4].copy_from_slice(&i.to_be_bytes());
            let r = IssuedNonce::new(n, aid.clone(), "t", Timestamp(0), Timestamp(1_000));
            issue(&s, &r).unwrap();
            assert_eq!(
                s.consume_sync(&n, &aid, Timestamp(0)),
                ConsumeOutcome::Consumed
            );
        }
        let sh = lock(&s.shards[0]);
        assert!(sh.map.is_empty());
        assert!(sh.expiry.len() <= 64 + 1, "{}", sh.expiry.len());
    }

    #[test]
    fn retry_after_tracks_earliest_expiry() {
        let s = InMemoryNonceStore::with_shards(2, 2);
        issue(&s, &rec(1, 300, 0)).unwrap();
        issue(&s, &rec(2, 120, 0)).unwrap();
        match issue(&s, &rec(3, 400, 20)) {
            Err(NonceStoreError::AtCapacity { retry_after, .. }) => {
                assert_eq!(retry_after, Some(Duration::from_secs(101)))
            }
            other => panic!("{other:?}"),
        }
    }
}
