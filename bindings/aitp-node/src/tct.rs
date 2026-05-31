//! TCT verification binding.

use aitp_core::{Aid, Timestamp};
use aitp_crypto::{AitpSigningKey, AitpVerifyingKey};
use aitp_tct::{verify_tct, TctEnvelope, TctVerifyContext};
use napi::bindgen_prelude::*;
use napi_derive::napi;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

/// The verified peer identity carried by a TCT.
#[napi(object)]
pub struct JsTctIdentity {
    /// AID of the agent that issued (and is bound by) the TCT.
    pub peer_aid: String,
    /// Capability grants the TCT authorizes.
    pub grants: Vec<String>,
    /// Expiry, Unix seconds.
    pub expires_at: f64,
    /// TCT unique identifier (`jti`).
    pub jti: String,
}

/// Verify `tct_json`, requiring `required_grant`.
///
/// The audience check is controlled by `expected_audience`:
/// - `None`: use `our_key.aid()` — the **holder-receipt** model from
///   RFC-AITP-0005 §9, where the holder verifies a TCT it received as its
///   own receipt.
/// - `Some(aid)`: use the supplied AID — the **presented-TCT** model used by
///   resource servers verifying a TCT a peer presents in `X-AITP-TCT`.
///
/// The signature check is the security gate in either mode: the TCT is
/// verified against `tct.issuer`'s pubkey.
pub fn js_verify_tct(
    our_key: &AitpSigningKey,
    tct_json: &str,
    required_grant: &str,
    expected_audience: Option<&str>,
) -> Result<JsTctIdentity> {
    let envelope: TctEnvelope = serde_json::from_str(tct_json)
        .map_err(|e| Error::from_reason(format!("invalid TCT JSON: {e}")))?;

    let issuer_pk = AitpVerifyingKey::from_aid(&envelope.tct.issuer)
        .map_err(|e| Error::from_reason(format!("bad issuer AID: {e}")))?;

    let audience_owned: Aid;
    let aud_ref: &Aid = match expected_audience {
        Some(s) => {
            audience_owned = Aid::parse(s)
                .map_err(|e| Error::from_reason(format!("bad expected_audience AID '{s}': {e}")))?;
            &audience_owned
        }
        None => our_key.aid(),
    };

    let ctx = TctVerifyContext {
        expected_audience: aud_ref,
        issuer_pubkey: &issuer_pk,
        now: Timestamp::now(),
        issuer_manifest_expires_at: None,
        revocation_check: None,
    };

    let tct = verify_tct(&envelope.tct, &ctx)
        .map_err(|e| Error::from_reason(format!("TCT verification failed: {e}")))?;

    if !tct.grants.iter().any(|g| g == required_grant) {
        return Err(Error::from_reason(format!(
            "TCT does not grant '{required_grant}'; grants: {:?}",
            tct.grants
        )));
    }

    Ok(JsTctIdentity {
        peer_aid: tct.issuer.to_string(),
        grants: tct.grants.clone(),
        expires_at: tct.expires_at.0 as f64,
        jti: tct.jti.to_string(),
    })
}

/// A cached, already-verified TCT.
#[derive(Clone)]
struct CachedVerification {
    peer_aid: String,
    grants: Vec<String>,
    expires_at: f64,
    jti: String,
    audience: String,
}

struct TctStoreInner {
    map: HashMap<[u8; 32], CachedVerification>,
    order: VecDeque<[u8; 32]>,
}

/// A bounded, in-memory cache of **successful** TCT verifications, keyed by
/// the SHA-256 of the exact TCT envelope JSON bytes.
///
/// Purpose: a high-throughput verifier (e.g. a writer agent checking a
/// capability on every request) that repeatedly sees the *same* TCT can skip
/// the Ed25519/P-256 signature verification after the first time.
///
/// **Safety.** The key is a cryptographic hash of the exact signed bytes, so
/// only a byte-identical envelope — whose signature was already verified once
/// — can hit. A tampered token hashes differently, misses, and is fully
/// verified. The cheap policy checks (expiry, audience, required grant) are
/// re-run on **every** hit; only the signature check is elided. Eviction is
/// FIFO once `maxEntries` is reached.
#[napi(js_name = "TctStore")]
pub struct JsTctStore {
    inner: Mutex<TctStoreInner>,
    max_entries: usize,
}

#[napi]
impl JsTctStore {
    /// Create a cache holding at most `maxEntries` verified TCTs (FIFO
    /// eviction). `maxEntries` must be >= 1.
    #[napi(constructor)]
    pub fn new(max_entries: u32) -> Result<Self> {
        if max_entries == 0 {
            return Err(Error::from_reason("maxEntries must be >= 1"));
        }
        Ok(Self {
            inner: Mutex::new(TctStoreInner {
                map: HashMap::new(),
                order: VecDeque::new(),
            }),
            max_entries: max_entries as usize,
        })
    }

    /// Number of cached verifications currently held.
    #[napi]
    pub fn len(&self) -> u32 {
        self.inner.lock().expect("tct store mutex").map.len() as u32
    }

    /// Drop all cached entries.
    #[napi]
    pub fn clear(&self) {
        let mut g = self.inner.lock().expect("tct store mutex");
        g.map.clear();
        g.order.clear();
    }
}

impl JsTctStore {
    fn get(&self, key: &[u8; 32]) -> Option<CachedVerification> {
        self.inner
            .lock()
            .expect("tct store mutex")
            .map
            .get(key)
            .cloned()
    }

    fn insert(&self, key: [u8; 32], v: CachedVerification) {
        let mut g = self.inner.lock().expect("tct store mutex");
        if g.map.insert(key, v).is_some() {
            return; // key already present — value refreshed, order unchanged.
        }
        g.order.push_back(key);
        while g.map.len() > self.max_entries {
            if let Some(old) = g.order.pop_front() {
                g.map.remove(&old);
            } else {
                break;
            }
        }
    }
}

/// SHA-256 of the exact TCT envelope JSON bytes — the cache key.
fn tct_envelope_key(tct_json: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(tct_json.as_bytes());
    h.finalize().into()
}

/// Verify `tct_json` like [`js_verify_tct`], but consult `store` first: on a
/// byte-identical, already-verified, still-valid TCT this skips the signature
/// check. See [`JsTctStore`] for the safety argument.
pub fn js_verify_tct_cached(
    our_key: &AitpSigningKey,
    tct_json: &str,
    required_grant: &str,
    store: &JsTctStore,
    expected_audience: Option<&str>,
) -> Result<JsTctIdentity> {
    let key = tct_envelope_key(tct_json);
    let effective_aud: String = match expected_audience {
        Some(s) => s.to_string(),
        None => our_key.aid().to_string(),
    };

    // Fast path: exact bytes verified before AND policy still holds.
    if let Some(c) = store.get(&key) {
        let now = Timestamp::now().0 as f64;
        if c.audience == effective_aud
            && c.expires_at > now
            && c.grants.iter().any(|g| g == required_grant)
        {
            return Ok(JsTctIdentity {
                peer_aid: c.peer_aid,
                grants: c.grants,
                expires_at: c.expires_at,
                jti: c.jti,
            });
        }
    }

    // Slow path: full verification (signature + every policy check).
    let identity = js_verify_tct(our_key, tct_json, required_grant, expected_audience)?;
    // Capture the TCT's own audience for future fast-path policy re-checks.
    let envelope: TctEnvelope = serde_json::from_str(tct_json)
        .map_err(|e| Error::from_reason(format!("invalid TCT JSON: {e}")))?;
    store.insert(
        key,
        CachedVerification {
            peer_aid: identity.peer_aid.clone(),
            grants: identity.grants.clone(),
            expires_at: identity.expires_at,
            jti: identity.jti.clone(),
            audience: envelope.tct.audience.to_string(),
        },
    );
    Ok(identity)
}
