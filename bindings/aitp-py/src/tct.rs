//! TCT verification binding.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Mutex;

use aitp_core::Aid;
use aitp_core::Timestamp;
use aitp_crypto::jws::decode_payload_unverified;
use aitp_crypto::AitpSigningKey;
use aitp_tct::{verify_tct, TctClaims, TctVerifyContext};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// An owned revocation-lookup closure: `true` if a `jti` is revoked.
type RevocationClosure = Box<dyn Fn(&Uuid) -> bool>;

/// The verified peer identity carried by a TCT.
#[pyclass(name = "TctIdentity", frozen)]
pub struct PyTctIdentity {
    /// AID of the agent that issued (and is bound by) the TCT.
    #[pyo3(get)]
    pub peer_aid: String,
    /// Capability grants the TCT authorizes.
    #[pyo3(get)]
    pub grants: Vec<String>,
    /// Expiry, Unix seconds.
    #[pyo3(get)]
    pub expires_at: i64,
    /// TCT unique identifier (`jti`).
    #[pyo3(get)]
    pub jti: String,
}

/// Decode the *unverified* claims of a compact-JWS TCT.
///
/// Used only to learn the issuer AID before verification: `verify_tct`
/// re-establishes the verifying key cryptographically from that AID
/// (the AID encodes the pubkey), so a confused/forged `iss` cannot steer
/// key resolution — a token whose signature does not match the key its
/// own `iss` AID encodes is rejected.
fn decode_tct_claims_unverified(tct_token: &str) -> PyResult<TctClaims> {
    let payload = decode_payload_unverified(tct_token)
        .map_err(|e| PyValueError::new_err(format!("malformed TCT compact JWS: {e}")))?;
    serde_json::from_slice::<TctClaims>(&payload)
        .map_err(|e| PyValueError::new_err(format!("invalid TCT claims: {e}")))
}

/// Verify `tct_token` (a compact-JWS string), requiring `required_grant`
/// to be present in its grants.
///
/// The audience check is controlled by `expected_audience`:
/// - `None` (default): use `our_key.aid()` — the **holder-receipt** model
///   from RFC-AITP-0005 §9, where the holder verifies a TCT it received as
///   its own receipt.
/// - `Some(aid)`: use the supplied AID — the **presented-TCT** model used
///   by resource servers verifying a TCT a peer presents in
///   `X-AITP-TCT`. The caller is responsible for asserting the
///   presenter's AID (typically by reading the TCT's own `aud`
///   claim, which in v0.2 must equal `sub`).
///
/// The signature check is the security gate in either mode: the TCT is
/// verified against the key its `iss` AID encodes.
///
/// `revoked_jtis` is an OPTIONAL set of revoked TCT `jti` strings
/// (RFC-AITP-0008). When supplied, a TCT whose `jti` is in the set is
/// rejected *after* every signature check passes. **Verifiers SHOULD
/// supply this** — omitting it silently honors a revoked-but-unexpired
/// TCT.
pub fn py_verify_tct(
    our_key: &AitpSigningKey,
    tct_token: &str,
    required_grant: &str,
    expected_audience: Option<&str>,
    revoked_jtis: Option<&HashSet<String>>,
) -> PyResult<PyTctIdentity> {
    let unverified = decode_tct_claims_unverified(tct_token)?;

    let audience_owned: Aid;
    let aud_ref: &Aid = match expected_audience {
        Some(s) => {
            audience_owned = Aid::parse(s).map_err(|e| {
                PyValueError::new_err(format!("bad expected_audience AID '{s}': {e}"))
            })?;
            &audience_owned
        }
        None => our_key.aid(),
    };

    // F-1: a `jti` set captured by value so the closure is `Fn` and lives
    // entirely in Rust — no Python re-entrancy under the verify call.
    let revocation_closure: Option<RevocationClosure> = revoked_jtis.map(|set| {
        let owned: HashSet<String> = set.clone();
        let f: RevocationClosure = Box::new(move |jti: &Uuid| owned.contains(&jti.to_string()));
        f
    });

    // Strict builder (aitp-tct 0.4). Behavior is preserved: revocation is
    // consulted only when the caller supplied `revoked_jtis`, otherwise
    // explicitly waived. The issuer-Manifest expiry cap is still waived
    // here — threading an `issuer_manifest_expires_at` parameter through
    // the SDK surface is the remaining half of F-1.
    let builder = TctVerifyContext::builder(aud_ref, &unverified.iss, Timestamp::now())
        .skip_manifest_expiry_cap_dangerous();
    let builder = match revocation_closure.as_deref() {
        Some(b) => builder.revocation_check(b as &dyn Fn(&Uuid) -> bool),
        None => builder.accept_unchecked_revocation_dangerous(),
    };
    let ctx = builder
        .build()
        .map_err(|e| PyRuntimeError::new_err(format!("verify context: {e}")))?;

    let verified = verify_tct(tct_token, &ctx)
        .map_err(|e| PyRuntimeError::new_err(format!("TCT verification failed: {e}")))?;
    let claims = verified.claims;

    if !claims.grants.iter().any(|g| g == required_grant) {
        return Err(PyRuntimeError::new_err(format!(
            "TCT does not grant '{required_grant}'; grants: {:?}",
            claims.grants
        )));
    }

    Ok(PyTctIdentity {
        peer_aid: claims.iss.to_string(),
        grants: claims.grants.clone(),
        expires_at: claims.exp.0,
        jti: claims.jti.to_string(),
    })
}

/// A cached, already-verified TCT.
#[derive(Clone)]
struct CachedVerification {
    peer_aid: String,
    grants: Vec<String>,
    expires_at: i64,
    jti: String,
    audience: String,
}

struct TctStoreInner {
    map: HashMap<[u8; 32], CachedVerification>,
    order: VecDeque<[u8; 32]>,
}

/// A bounded, in-memory cache of **successful** TCT verifications, keyed by
/// the SHA-256 of the exact TCT compact-JWS bytes.
///
/// Purpose: a high-throughput verifier (e.g. a writer agent checking a
/// capability on every request) that repeatedly sees the *same* TCT can skip
/// the Ed25519/P-256 signature verification after the first time.
///
/// **Safety.** The key is a cryptographic hash of the exact signed bytes, so
/// only a byte-identical token — whose signature was already verified once
/// — can hit. A tampered token hashes differently, misses, and is fully
/// verified. The cheap policy checks (expiry, audience, required grant) are
/// re-run on **every** hit; only the signature check is elided. Eviction is
/// FIFO once `max_entries` is reached.
#[pyclass(name = "TctStore")]
pub struct PyTctStore {
    inner: Mutex<TctStoreInner>,
    max_entries: usize,
}

#[pymethods]
impl PyTctStore {
    /// Create a cache holding at most `max_entries` verified TCTs
    /// (FIFO eviction). `max_entries` must be >= 1.
    #[new]
    fn new(max_entries: usize) -> PyResult<Self> {
        if max_entries == 0 {
            return Err(PyValueError::new_err("max_entries must be >= 1"));
        }
        Ok(Self {
            inner: Mutex::new(TctStoreInner {
                map: HashMap::new(),
                order: VecDeque::new(),
            }),
            max_entries,
        })
    }

    /// Number of cached verifications currently held.
    fn len(&self) -> usize {
        self.inner.lock().expect("tct store mutex").map.len()
    }

    /// Drop all cached entries.
    fn clear(&self) {
        let mut g = self.inner.lock().expect("tct store mutex");
        g.map.clear();
        g.order.clear();
    }
}

impl PyTctStore {
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

/// SHA-256 of the exact TCT compact-JWS bytes — the cache key.
fn tct_token_key(tct_token: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(tct_token.as_bytes());
    h.finalize().into()
}

/// Verify `tct_token` like [`py_verify_tct`], but consult `store` first: on a
/// byte-identical, already-verified, still-valid TCT this skips the signature
/// check. See [`PyTctStore`] for the safety argument.
///
/// `revoked_jtis` (F-1) is consulted on **every** call — including cache
/// hits — so a freshly-revoked TCT stops verifying immediately even if its
/// signature was cached.
pub fn py_verify_tct_cached(
    our_key: &AitpSigningKey,
    tct_token: &str,
    required_grant: &str,
    store: &PyTctStore,
    expected_audience: Option<&str>,
    revoked_jtis: Option<&HashSet<String>>,
) -> PyResult<PyTctIdentity> {
    let key = tct_token_key(tct_token);
    let effective_aud: String = match expected_audience {
        Some(s) => s.to_string(),
        None => our_key.aid().to_string(),
    };

    // Fast path: exact bytes verified before AND policy still holds.
    if let Some(c) = store.get(&key) {
        let now = Timestamp::now().0;
        let revoked = revoked_jtis.is_some_and(|set| set.contains(&c.jti));
        if !revoked
            && c.audience == effective_aud
            && c.expires_at > now
            && c.grants.iter().any(|g| g == required_grant)
        {
            return Ok(PyTctIdentity {
                peer_aid: c.peer_aid,
                grants: c.grants,
                expires_at: c.expires_at,
                jti: c.jti,
            });
        }
    }

    // Slow path: full verification (signature + every policy check).
    let identity = py_verify_tct(
        our_key,
        tct_token,
        required_grant,
        expected_audience,
        revoked_jtis,
    )?;
    // Capture the TCT's own audience for future fast-path policy re-checks.
    let claims = decode_tct_claims_unverified(tct_token)?;
    store.insert(
        key,
        CachedVerification {
            peer_aid: identity.peer_aid.clone(),
            grants: identity.grants.clone(),
            expires_at: identity.expires_at,
            jti: identity.jti.clone(),
            audience: claims.aud.to_string(),
        },
    );
    Ok(identity)
}
