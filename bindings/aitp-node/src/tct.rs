//! TCT verification binding.
//!
//! In AITP v0.2 a TCT is an **opaque compact-JWS string** (`typ:
//! aitp-tct+jwt`), not a JSON envelope. The binding receives the token
//! verbatim, peeks at the unverified payload to learn the issuer AID,
//! then re-establishes the issuer key from that AID inside `verify_tct`.

use std::collections::HashSet;

use aitp_core::{Aid, Timestamp};
use aitp_crypto::jws::decode_payload_unverified;
use aitp_crypto::AitpSigningKey;
use aitp_tct::{verify_tct, TctClaims, TctVerifyContext};
use napi::bindgen_prelude::*;
use napi_derive::napi;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use uuid::Uuid;

/// The verified peer identity carried by a TCT.
#[napi(object)]
pub struct JsTctIdentity {
    /// AID of the agent that issued (and is bound by) the TCT (`iss`).
    pub peer_aid: String,
    /// Capability grants the TCT authorizes.
    pub grants: Vec<String>,
    /// Expiry, Unix seconds (`exp`).
    pub expires_at: f64,
    /// TCT unique identifier (`jti`).
    pub jti: String,
}

/// Decode the unverified payload of a compact-JWS TCT into its claims.
///
/// This is a structural peek **only** — it does no signature check. We
/// use it to learn the issuer AID (`iss`) so `verify_tct` can
/// re-establish the verifying key; every field is then re-validated by
/// `verify_tct` under that key.
fn peek_tct_claims(token: &str) -> Result<TctClaims> {
    let payload = decode_payload_unverified(token)
        .map_err(|e| Error::from_reason(format!("invalid TCT (not a compact JWS): {e}")))?;
    serde_json::from_slice::<TctClaims>(&payload)
        .map_err(|e| Error::from_reason(format!("invalid TCT claims: {e}")))
}

/// Build the `TctVerifyContext.revocation_check` closure from a list of
/// revoked `jti` strings supplied by the JS caller.
///
/// **F-1 (SDK revocation callback).** Rather than calling back into the
/// JS runtime per-`jti` (which is unsound under napi threading
/// constraints), the JS caller passes the *set* of revoked `jti`s
/// up-front. The closure returns `true` for any `jti` in the set, which
/// `verify_tct` treats as a revoked-and-rejected TCT. Malformed `jti`
/// strings in the list are ignored (they can never match a real UUID).
fn parse_revoked_set(revoked: Option<Vec<String>>) -> HashSet<Uuid> {
    revoked
        .unwrap_or_default()
        .into_iter()
        .filter_map(|s| Uuid::parse_str(&s).ok())
        .collect()
}

/// Verify a compact-JWS `tct_token`, requiring `required_grant`.
///
/// The audience check is controlled by `expected_audience`:
/// - `None`: use `our_key.aid()` — the **holder-receipt** model from
///   RFC-AITP-0005 §9, where the holder verifies a TCT it received as its
///   own receipt.
/// - `Some(aid)`: use the supplied AID — the **presented-TCT** model used
///   by resource servers verifying a TCT a peer presents in `X-AITP-TCT`.
///
/// `revoked_jtis` is an optional list of revoked TCT `jti` strings (F-1):
/// any TCT whose `jti` is in the set is rejected even if otherwise valid
/// and unexpired. `None`/omitted disables the revocation gate.
///
/// The signature check is the security gate in either mode: the TCT is
/// verified against the issuer AID's pubkey, which is re-derived from the
/// (now-trusted, post-verification) `iss` claim.
pub fn js_verify_tct(
    our_key: &AitpSigningKey,
    tct_token: &str,
    required_grant: &str,
    expected_audience: Option<&str>,
    revoked_jtis: Option<Vec<String>>,
) -> Result<JsTctIdentity> {
    let peek = peek_tct_claims(tct_token)?;

    let audience_owned: Aid;
    let aud_ref: &Aid = match expected_audience {
        Some(s) => {
            audience_owned = Aid::parse(s)
                .map_err(|e| Error::from_reason(format!("bad expected_audience AID '{s}': {e}")))?;
            &audience_owned
        }
        None => our_key.aid(),
    };

    let revoked = parse_revoked_set(revoked_jtis);
    let revocation_closure = |jti: &Uuid| revoked.contains(jti);

    let ctx = TctVerifyContext {
        expected_audience: aud_ref,
        issuer: &peek.iss,
        now: Timestamp::now(),
        issuer_manifest_expires_at: None,
        revocation_check: if revoked.is_empty() {
            None
        } else {
            Some(&revocation_closure)
        },
    };

    let verified = verify_tct(tct_token, &ctx)
        .map_err(|e| Error::from_reason(format!("TCT verification failed: {e}")))?;
    let claims = &verified.claims;

    if !claims.grants.iter().any(|g| g == required_grant) {
        return Err(Error::from_reason(format!(
            "TCT does not grant '{required_grant}'; grants: {:?}",
            claims.grants
        )));
    }

    Ok(JsTctIdentity {
        peer_aid: claims.iss.to_string(),
        grants: claims.grants.clone(),
        expires_at: claims.exp.0 as f64,
        jti: claims.jti.to_string(),
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
/// the SHA-256 of the exact compact-JWS TCT token bytes.
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

/// SHA-256 of the exact compact-JWS TCT token bytes — the cache key.
fn tct_token_key(tct_token: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(tct_token.as_bytes());
    h.finalize().into()
}

/// Verify `tct_token` like [`js_verify_tct`], but consult `store` first: on a
/// byte-identical, already-verified, still-valid TCT this skips the signature
/// check. See [`JsTctStore`] for the safety argument.
///
/// `revoked_jtis` (F-1) is applied on **both** the fast and slow paths: a
/// cache hit whose `jti` is in the revoked set is rejected and falls through
/// to a full re-verification (which then also fails the revocation gate).
pub fn js_verify_tct_cached(
    our_key: &AitpSigningKey,
    tct_token: &str,
    required_grant: &str,
    store: &JsTctStore,
    expected_audience: Option<&str>,
    revoked_jtis: Option<Vec<String>>,
) -> Result<JsTctIdentity> {
    let key = tct_token_key(tct_token);
    let effective_aud: String = match expected_audience {
        Some(s) => s.to_string(),
        None => our_key.aid().to_string(),
    };
    let revoked = parse_revoked_set(revoked_jtis.clone());

    // Fast path: exact bytes verified before AND policy still holds.
    if let Some(c) = store.get(&key) {
        let now = Timestamp::now().0 as f64;
        let jti_revoked = Uuid::parse_str(&c.jti)
            .map(|u| revoked.contains(&u))
            .unwrap_or(false);
        if !jti_revoked
            && c.audience == effective_aud
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

    // Slow path: full verification (signature + every policy check, incl.
    // the F-1 revocation gate).
    let identity = js_verify_tct(
        our_key,
        tct_token,
        required_grant,
        expected_audience,
        revoked_jtis,
    )?;
    // Capture the TCT's own audience for future fast-path policy re-checks.
    // The `aud` claim is read from the now-verified token's payload.
    let claims = peek_tct_claims(tct_token)?;
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
