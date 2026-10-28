//! TCT verification binding.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Mutex;

use aitp::core::Aid;
use aitp::core::Timestamp;
use aitp::crypto::jws::decode_payload_unverified;
use aitp::crypto::AitpSigningKey;
use aitp::tct::{verify_tct, PopChallenge, PopResponse, TctClaims, TctVerifyContext};
use pyo3::exceptions::{PyRuntimeError, PyValueError};

use crate::helpers::{binding_revocation, runtime_error, tct_revocation_code, BindingRevocation};
use pyo3::prelude::*;
use sha2::{Digest, Sha256};
use uuid::Uuid;

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
pub(crate) fn decode_tct_claims_unverified(tct_token: &str) -> PyResult<TctClaims> {
    let payload = decode_payload_unverified(tct_token)
        .map_err(|e| PyValueError::new_err(format!("malformed TCT compact JWS: {e}")))?;
    serde_json::from_slice::<TctClaims>(&payload)
        .map_err(|e| PyValueError::new_err(format!("invalid TCT claims: {e}")))
}

/// A caller's `pop=(challenge_json, response_json)` argument, parsed.
pub type PopArg<'a> = Option<(&'a str, &'a str)>;

/// Resolve the audience for a verify call. With `pop`, the audience is
/// the TCT's `sub`: the PoP response must then prove possession of that
/// key, so the audience is never taken on the token's word alone.
/// `pop` and `expected_audience` are mutually exclusive.
fn pop_audience(
    tct_token: &str,
    expected_audience: Option<&str>,
    pop: PopArg<'_>,
) -> PyResult<Option<(String, PopChallenge, PopResponse)>> {
    let Some((challenge_json, response_json)) = pop else {
        return Ok(None);
    };
    if expected_audience.is_some() {
        return Err(PyValueError::new_err(
            "pass either expected_audience or pop, not both: pop pins the audience to the proven holder AID",
        ));
    }
    let challenge = crate::pop::parse_challenge(challenge_json)?;
    let response = crate::pop::parse_response(response_json)?;
    let sub = decode_tct_claims_unverified(tct_token)?.sub.to_string();
    Ok(Some((sub, challenge, response)))
}

/// After the TCT bytes passed signature verification, check the PoP
/// response against its (now trusted) claims.
fn finish_pop(tct_token: &str, pop: Option<(String, PopChallenge, PopResponse)>) -> PyResult<()> {
    if let Some((_, challenge, response)) = pop {
        let claims = decode_tct_claims_unverified(tct_token)?;
        crate::pop::verify_against(&challenge, &response, &claims)?;
    }
    Ok(())
}

/// Verify `tct_token` (a compact-JWS string), requiring `required_grant`
/// to be present in its grants.
///
/// `pop=(challenge_json, response_json)` is the **presented-TCT** path: a
/// downstream PoP exchange (RFC-AITP-0005 §6) proves the presenter holds
/// the key `sub` encodes, and the audience is pinned to that proven AID.
/// The TCT checks run first, then every §6.2 step; a PoP failure raises
/// with `code` `POP_CHALLENGE_INVALID` or `POP_RESPONSE_INVALID`. It is
/// mutually exclusive with `expected_audience`.
///
/// Otherwise the audience check is controlled by `expected_audience`:
/// - `None` (default): use `our_key.aid()` — the **holder-receipt** model
///   from RFC-AITP-0005 §9, where the holder verifies a TCT it received as
///   its own receipt.
/// - `Some(aid)`: use the supplied AID — the **presented-TCT** model used
///   by resource servers verifying a TCT a peer presents in
///   `X-AITP-TCT`. The caller MUST take the presenter's AID from an
///   authenticated source, never from the token: a downstream PoP
///   response (RFC-AITP-0005 §6.1/§6.2) whose `pop_signature` verifies
///   against the key `sub` encodes, or an equivalent channel binding.
///   Passing the TCT's own `aud` back makes the audience check vacuous.
///
/// The signature check is the security gate in either mode: the TCT is
/// verified against the key its `iss` AID encodes.
///
/// `revoked_jtis` is the issuer's deny list, a set of revoked TCT `jti`
/// strings (RFC-AITP-0008): a TCT whose `jti` is in it is rejected *after*
/// every signature check passes. Revocation is `fail_closed`: without
/// `revoked_jtis` every TCT is rejected with `code == "TCT_REVOKED"` and a
/// "revocation source unavailable" message, unless `revocation` is
/// `"fail_open"`. The set is a lookup key, so entries are normalized (see
/// [`parse_revoked`]); an entry that is not a UUID raises `ValueError`.
pub fn py_verify_tct(
    our_key: &AitpSigningKey,
    tct_token: &str,
    required_grant: &str,
    expected_audience: Option<&str>,
    revoked_jtis: Option<&HashSet<String>>,
    revocation: Option<&str>,
    pop: PopArg<'_>,
) -> PyResult<PyTctIdentity> {
    let revoked = parse_revoked(revoked_jtis, revocation)?;
    let pop = pop_audience(tct_token, expected_audience, pop)?;
    let identity = verify_tct_parsed(
        our_key,
        tct_token,
        required_grant,
        pop.as_ref()
            .map_or(expected_audience, |p| Some(p.0.as_str())),
        revoked,
    )?;
    finish_pop(tct_token, pop)?;
    Ok(identity)
}

/// Parse a caller's revoked-`jti` set and `revocation` mode. Entries in
/// any RFC 9562 text form (uppercase, braced, `urn:uuid:`, unhyphenated)
/// match the canonical `jti`, and an entry that is not a UUID raises
/// `ValueError` rather than silently never matching.
fn parse_revoked(
    revoked_jtis: Option<&HashSet<String>>,
    revocation: Option<&str>,
) -> PyResult<BindingRevocation> {
    binding_revocation(
        revoked_jtis.map(|s| s.iter().map(String::as_str)),
        revocation,
    )
    .map_err(PyValueError::new_err)
}

/// [`py_verify_tct`] after the revoked set is parsed.
fn verify_tct_parsed(
    our_key: &AitpSigningKey,
    tct_token: &str,
    required_grant: &str,
    expected_audience: Option<&str>,
    revocation: BindingRevocation,
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

    // The deny list lives entirely in Rust — no Python re-entrancy under
    // the verify call. Only the explicit `fail_open` opt-out waives the
    // check; no list under `fail_closed` reports the status unavailable.
    // The issuer-Manifest expiry cap is still waived here — threading an
    // `issuer_manifest_expires_at` parameter through the SDK surface is
    // the remaining half of F-1.
    let revocation_check = |q: &aitp::tct::RevocationQuery<'_>| revocation.status(q);
    let builder = TctVerifyContext::builder(aud_ref, &unverified.iss, Timestamp::now())
        .skip_manifest_expiry_cap_dangerous();
    let builder = builder.revocation(revocation.source(&revocation_check));
    let ctx = builder
        .build()
        .map_err(|e| PyRuntimeError::new_err(format!("verify context: {e}")))?;

    let verified = verify_tct(tct_token, &ctx).map_err(|e| {
        runtime_error(
            format!("TCT verification failed: {e}"),
            tct_revocation_code(&e),
        )
    })?;
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
///
/// RFC-AITP-0001 §5.4.3 forbids raw bytes, or their hash, as an object's
/// *identity* (replay, dedup, caching, audit), because one signed object
/// can arrive as several byte strings. This key is not an identity: it
/// memoizes "these exact bytes already passed signature verification", so
/// it must cover the signature. Keying on the content without the
/// signature would let a token with a forged signature hit the cache. A
/// re-encoded copy of a valid token only misses and is fully verified.
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
/// signature was cached. `pop` behaves as in [`py_verify_tct`] and is
/// checked on every call: a challenge is single use, so it is never cached.
#[allow(clippy::too_many_arguments)]
pub fn py_verify_tct_cached(
    our_key: &AitpSigningKey,
    tct_token: &str,
    required_grant: &str,
    store: &PyTctStore,
    expected_audience: Option<&str>,
    revoked_jtis: Option<&HashSet<String>>,
    revocation: Option<&str>,
    pop: PopArg<'_>,
) -> PyResult<PyTctIdentity> {
    let pop = pop_audience(tct_token, expected_audience, pop)?;
    let expected_audience = pop
        .as_ref()
        .map_or(expected_audience, |p| Some(p.0.as_str()));
    let identity = verify_tct_cached_inner(
        our_key,
        tct_token,
        required_grant,
        store,
        expected_audience,
        revoked_jtis,
        revocation,
    )?;
    finish_pop(tct_token, pop)?;
    Ok(identity)
}

/// [`py_verify_tct_cached`] without the PoP step.
fn verify_tct_cached_inner(
    our_key: &AitpSigningKey,
    tct_token: &str,
    required_grant: &str,
    store: &PyTctStore,
    expected_audience: Option<&str>,
    revoked_jtis: Option<&HashSet<String>>,
    revocation: Option<&str>,
) -> PyResult<PyTctIdentity> {
    let key = tct_token_key(tct_token);
    let effective_aud: String = match expected_audience {
        Some(s) => s.to_string(),
        None => our_key.aid().to_string(),
    };

    let revocation_mode = parse_revoked(revoked_jtis, revocation)?;

    // Fast path: exact bytes verified before AND policy still holds. The
    // revocation status is re-checked on every hit; an unavailable status
    // (no list under `fail_closed`) falls through to the slow path, which
    // rejects with the coded error.
    if let Some(c) = store.get(&key) {
        let now = Timestamp::now().0;
        let cleared = Uuid::parse_str(&c.jti).is_ok_and(|jti| {
            matches!(
                revocation_mode.jti_status(&jti),
                Ok(aitp::tct::RevocationStatus::Clear)
            )
        });
        if cleared
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
    let identity = verify_tct_parsed(
        our_key,
        tct_token,
        required_grant,
        expected_audience,
        revocation_mode,
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
