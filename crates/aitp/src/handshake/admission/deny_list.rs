//! The `message_id` deny list of pinned-key admission (RFC-AITP-0002
//! §3.4 check order, step 1; RFC-AITP-0001 §5.5).

use super::nonce_store::lock;
use crate::core::Timestamp;
use crate::core::{BoxError, BoxFuture};
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::hash::BuildHasher;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use uuid::Uuid;

/// Why a deny list could not answer or record.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DenyListError {
    /// The list holds its maximum number of live records. Lists MUST
    /// refuse rather than evict a live record: eviction would reopen
    /// that `message_id` to replay.
    #[error("message_id deny list at capacity ({capacity} records)")]
    AtCapacity {
        /// The configured bound.
        capacity: usize,
    },
    /// The backing service failed.
    #[error("message_id deny list backend: {0}")]
    Backend(#[source] BoxError),
}

/// The `message_id`s of admitted presentations, each kept until its
/// envelope timestamp leaves the tolerance window (after that the
/// timestamp check rejects a replay on its own).
///
/// Implementations back this with process memory
/// ([`InMemoryMessageIdDenyList`]), Redis (`EXISTS`, then `SET NX
/// EXAT`) or similar. Contract:
///
/// - [`contains`](Self::contains) answers for records whose `until` is
///   not in the past at `now`.
/// - [`insert`](Self::insert) is atomic: for one `message_id`, at most
///   one caller across all replicas gets `Ok(true)`. A record already
///   live returns `Ok(false)`.
/// - Both are cancel-safe.
pub trait MessageIdDenyList: Send + Sync {
    /// Whether `message_id` is on the list at `now`.
    fn contains<'a>(
        &'a self,
        message_id: &'a Uuid,
        now: Timestamp,
    ) -> BoxFuture<'a, Result<bool, DenyListError>>;

    /// Record `message_id` until `until` (inclusive). `Ok(false)` when it
    /// was already live.
    fn insert<'a>(
        &'a self,
        message_id: &'a Uuid,
        until: Timestamp,
        now: Timestamp,
    ) -> BoxFuture<'a, Result<bool, DenyListError>>;
}

impl<T: MessageIdDenyList + ?Sized> MessageIdDenyList for std::sync::Arc<T> {
    fn contains<'a>(
        &'a self,
        message_id: &'a Uuid,
        now: Timestamp,
    ) -> BoxFuture<'a, Result<bool, DenyListError>> {
        (**self).contains(message_id, now)
    }
    fn insert<'a>(
        &'a self,
        message_id: &'a Uuid,
        until: Timestamp,
        now: Timestamp,
    ) -> BoxFuture<'a, Result<bool, DenyListError>> {
        (**self).insert(message_id, until, now)
    }
}

#[derive(Default)]
struct Shard {
    map: HashMap<Uuid, i64>,
    expiry: BinaryHeap<Reverse<(i64, Uuid)>>,
}

impl Shard {
    fn purge(&mut self, now: Timestamp) -> usize {
        let mut removed = 0;
        while let Some(&Reverse((until, id))) = self.expiry.peek() {
            if !Timestamp(until).is_in_the_past(now) {
                break;
            }
            self.expiry.pop();
            if self.map.get(&id) == Some(&until) {
                self.map.remove(&id);
                removed += 1;
            }
        }
        removed
    }
}

/// A process-local [`MessageIdDenyList`]: sharded maps with an expiry
/// heap each, bounded at `capacity` live records, no eviction.
///
/// Only admitted presentations are recorded, and a record lives at most
/// twice the timestamp tolerance, so the bound is reached only by a
/// sustained admission rate of `capacity / 600` per second.
///
/// Correct for a single replica; behind a load balancer use a shared
/// list.
pub struct InMemoryMessageIdDenyList {
    shards: Box<[Mutex<Shard>]>,
    capacity: usize,
    live: AtomicUsize,
    hasher: std::collections::hash_map::RandomState,
}

impl std::fmt::Debug for InMemoryMessageIdDenyList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryMessageIdDenyList")
            .field("capacity", &self.capacity)
            .field("live", &self.live)
            .finish_non_exhaustive()
    }
}

impl InMemoryMessageIdDenyList {
    /// Default bound on live records.
    pub const DEFAULT_CAPACITY: usize = 100_000;

    /// A list bounded at `capacity` live records.
    pub fn new(capacity: usize) -> Self {
        let shards = std::thread::available_parallelism()
            .map(|n| (n.get() * 4).next_power_of_two())
            .unwrap_or(16)
            .clamp(1, 256);
        Self {
            shards: (0..shards).map(|_| Mutex::default()).collect(),
            capacity,
            live: AtomicUsize::new(0),
            hasher: Default::default(),
        }
    }

    /// Records held, including expired ones not yet reclaimed.
    pub fn len(&self) -> usize {
        self.live.load(Ordering::Acquire)
    }

    /// True when no records are held.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Drop every record expired at `now`. Returns how many were removed.
    pub fn sweep(&self, now: Timestamp) -> usize {
        let removed: usize = self.shards.iter().map(|s| lock(s).purge(now)).sum();
        self.live.fetch_sub(removed, Ordering::AcqRel);
        removed
    }

    fn shard(&self, id: &Uuid) -> &Mutex<Shard> {
        let i = self.hasher.hash_one(id) as usize % self.shards.len();
        &self.shards[i]
    }

    fn contains_sync(&self, id: &Uuid, now: Timestamp) -> bool {
        let mut sh = lock(self.shard(id));
        let removed = sh.purge(now);
        self.live.fetch_sub(removed, Ordering::AcqRel);
        sh.map.contains_key(id)
    }

    fn insert_sync(
        &self,
        id: &Uuid,
        until: Timestamp,
        now: Timestamp,
    ) -> Result<bool, DenyListError> {
        let mut sh = lock(self.shard(id));
        let removed = sh.purge(now);
        self.live.fetch_sub(removed, Ordering::AcqRel);
        if sh.map.contains_key(id) {
            return Ok(false);
        }
        if self.len() >= self.capacity {
            drop(sh);
            self.sweep(now);
            if self.len() >= self.capacity {
                return Err(DenyListError::AtCapacity {
                    capacity: self.capacity,
                });
            }
            sh = lock(self.shard(id));
            if sh.map.contains_key(id) {
                return Ok(false);
            }
        }
        sh.map.insert(*id, until.0);
        sh.expiry.push(Reverse((until.0, *id)));
        self.live.fetch_add(1, Ordering::AcqRel);
        Ok(true)
    }
}

impl Default for InMemoryMessageIdDenyList {
    fn default() -> Self {
        Self::new(Self::DEFAULT_CAPACITY)
    }
}

impl MessageIdDenyList for InMemoryMessageIdDenyList {
    fn contains<'a>(
        &'a self,
        message_id: &'a Uuid,
        now: Timestamp,
    ) -> BoxFuture<'a, Result<bool, DenyListError>> {
        let r = self.contains_sync(message_id, now);
        Box::pin(async move { Ok(r) })
    }

    fn insert<'a>(
        &'a self,
        message_id: &'a Uuid,
        until: Timestamp,
        now: Timestamp,
    ) -> BoxFuture<'a, Result<bool, DenyListError>> {
        let r = self.insert_sync(message_id, until, now);
        Box::pin(async move { r })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> Uuid {
        Uuid::from_bytes([n; 16])
    }

    #[test]
    fn records_until_inclusive_then_forgets() {
        let l = InMemoryMessageIdDenyList::new(8);
        assert!(l.insert_sync(&id(1), Timestamp(100), Timestamp(0)).unwrap());
        assert!(!l
            .insert_sync(&id(1), Timestamp(100), Timestamp(50))
            .unwrap());
        assert!(l.contains_sync(&id(1), Timestamp(100)));
        assert!(!l.contains_sync(&id(1), Timestamp(101)));
        assert!(l.is_empty());
    }

    #[test]
    fn refuses_at_capacity_and_frees_on_expiry() {
        let l = InMemoryMessageIdDenyList::new(2);
        l.insert_sync(&id(1), Timestamp(10), Timestamp(0)).unwrap();
        l.insert_sync(&id(2), Timestamp(20), Timestamp(0)).unwrap();
        assert!(matches!(
            l.insert_sync(&id(3), Timestamp(30), Timestamp(5)),
            Err(DenyListError::AtCapacity { capacity: 2 })
        ));
        // Live records are never evicted to make room.
        assert!(l.contains_sync(&id(1), Timestamp(5)));
        assert!(l.insert_sync(&id(3), Timestamp(30), Timestamp(11)).unwrap());
        assert!(!l.contains_sync(&id(1), Timestamp(11)));
    }
}
