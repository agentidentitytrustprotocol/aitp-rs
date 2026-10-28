//! TCT verification binding.
//!
//! Since AITP v0.2 a TCT is an **opaque compact-JWS string** (`typ:
//! aitp-tct+jwt`), not a JSON envelope. The binding receives the token
//! verbatim, peeks at the unverified payload to learn the issuer AID,
//! then re-establishes the issuer key from that AID inside `verify_tct`.

use aitp::core::{Aid, Timestamp};
use aitp::crypto::jws::decode_payload_unverified;
use aitp::crypto::AitpSigningKey;
use aitp::tct::{verify_tct, PopChallenge, PopResponse, TctClaims, TctVerifyContext};
use napi::bindgen_prelude::*;
use napi::Env;
use napi_derive::napi;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use uuid::Uuid;

use crate::helpers::{coded_error, tct_revocation_code, BindingRevocation};
use crate::pop::PopExchange;

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

/// A TCT this agent just minted for someone else — the return shape of
/// `issueTctForDelegatee` (and, in an experimental build,
/// `processRenewalRequest`). Mirrors the Python
/// SDK's `{"tct", "grant_voucher"}` JSON object.
#[napi(object)]
pub struct JsIssuedTct {
    /// The fresh TCT as an opaque compact-JWS string. Deliver it to the
    /// holder verbatim.
    pub tct: String,
    /// The companion grant voucher (compact JWS, RFC-AITP-0005 §8), or
    /// `null` when issuance policy declined to mint one — the holder then
    /// cannot delegate. Deliver it alongside `tct`.
    pub grant_voucher: Option<String>,
}

impl From<aitp::tct::IssuedTct> for JsIssuedTct {
    fn from(issued: aitp::tct::IssuedTct) -> Self {
        Self {
            tct: issued.token,
            grant_voucher: issued.voucher,
        }
    }
}

/// Decode the unverified payload of a compact-JWS TCT into its claims.
///
/// This is a structural peek **only** — it does no signature check. We
/// use it to learn the issuer AID (`iss`) so `verify_tct` can
/// re-establish the verifying key; every field is then re-validated by
/// `verify_tct` under that key.
pub(crate) fn peek_tct_claims(token: &str) -> Result<TctClaims> {
    let payload = decode_payload_unverified(token)
        .map_err(|e| Error::from_reason(format!("invalid TCT (not a compact JWS): {e}")))?;
    serde_json::from_slice::<TctClaims>(&payload)
        .map_err(|e| Error::from_reason(format!("invalid TCT claims: {e}")))
}

/// Parse the JS caller's `revokedJtis` and `revocation` arguments.
///
/// **F-1 (SDK revocation callback).** Rather than calling back into the
/// JS runtime per-`jti` (which is unsound under napi threading
/// constraints), the JS caller passes the *set* of revoked `jti`s
/// up-front.
///
/// The set is a lookup key, so entries are normalized: any RFC 9562 text
/// form (uppercase, braced, `urn:uuid:`, unhyphenated) matches the
/// canonical `jti`. An entry that is not a UUID at all is an error rather
/// than silently ignored, so a malformed list cannot quietly disable the
/// revocation gate.
fn parse_revocation(
    revoked: Option<&[String]>,
    revocation: Option<&str>,
) -> Result<BindingRevocation> {
    crate::helpers::js_revocation(revoked, revocation)
}

/// A parsed `pop` argument: the proven-holder candidate (the TCT's `sub`)
/// plus the challenge and response to check once the TCT verifies.
type ParsedPop = (String, PopChallenge, PopResponse);

/// Resolve the audience for a verify call. With `pop`, the audience is
/// the TCT's `sub`, and [`finish_pop`] later proves the presenter holds
/// its key. `pop` and `expected_audience` are mutually exclusive.
fn pop_audience(
    env: Env,
    tct_token: &str,
    expected_audience: Option<&str>,
    pop: Option<&PopExchange>,
) -> Result<Option<ParsedPop>> {
    let Some(pop) = pop else {
        return Ok(None);
    };
    if expected_audience.is_some() {
        return Err(Error::new(
            Status::InvalidArg,
            "pass either expectedAudience or pop, not both: pop pins the audience to the proven holder AID",
        ));
    }
    let challenge = crate::pop::parse_challenge(env, &pop.challenge)?;
    let response = crate::pop::parse_response(env, &pop.response)?;
    let sub = peek_tct_claims(tct_token)?.sub.to_string();
    Ok(Some((sub, challenge, response)))
}

/// Run the RFC-AITP-0005 §6.2 checks against the now-verified TCT.
fn finish_pop(env: Env, tct_token: &str, pop: Option<ParsedPop>) -> Result<()> {
    if let Some((_, challenge, response)) = pop {
        let claims = peek_tct_claims(tct_token)?;
        crate::pop::verify_against(env, &challenge, &response, &claims)?;
    }
    Ok(())
}

/// Verify a compact-JWS `tct_token`, requiring `required_grant`.
///
/// The audience check is controlled by `expected_audience`:
/// - `None`: use `our_key.aid()` — the **holder-receipt** model from
///   RFC-AITP-0005 §9, where the holder verifies a TCT it received as its
///   own receipt.
/// - `Some(aid)`: use the supplied AID. The caller must have authenticated
///   that AID itself; see `pop` for the presented-TCT path.
///
/// `pop` is the **presented-TCT** model used by resource servers verifying
/// a TCT a peer presents in `X-AITP-TCT`: the audience is pinned to the
/// TCT's `sub`, and after the TCT verifies the PoP response must pass every
/// RFC-AITP-0005 §6.2 check against it. It excludes `expected_audience`.
///
/// `revoked_jtis` is the issuer's deny list of revoked TCT `jti` strings
/// (F-1): any TCT whose `jti` is in it is rejected even if otherwise valid
/// and unexpired. Revocation is `fail_closed`: with no list every TCT is
/// rejected as status-unavailable, unless `revocation` is `"fail_open"`.
/// Both rejections throw with `code === 'TCT_REVOKED'`.
///
/// The signature check is the security gate in either mode: the TCT is
/// verified against the issuer AID's pubkey, which is re-derived from the
/// (now-trusted, post-verification) `iss` claim.
#[allow(clippy::too_many_arguments)]
pub fn js_verify_tct(
    env: Env,
    our_key: &AitpSigningKey,
    tct_token: &str,
    required_grant: &str,
    expected_audience: Option<&str>,
    revoked_jtis: Option<Vec<String>>,
    revocation: Option<String>,
    pop: Option<&PopExchange>,
) -> Result<JsTctIdentity> {
    let pop = pop_audience(env, tct_token, expected_audience, pop)?;
    let expected_audience = pop
        .as_ref()
        .map(|(sub, ..)| sub.as_str())
        .or(expected_audience);
    let revocation = parse_revocation(revoked_jtis.as_deref(), revocation.as_deref())?;
    let identity = verify_tct_with(
        env,
        our_key,
        tct_token,
        required_grant,
        expected_audience,
        &revocation,
    )?;
    finish_pop(env, tct_token, pop)?;
    Ok(identity)
}

/// [`js_verify_tct`] with the revocation arguments already parsed.
fn verify_tct_with(
    env: Env,
    our_key: &AitpSigningKey,
    tct_token: &str,
    required_grant: &str,
    expected_audience: Option<&str>,
    revocation: &BindingRevocation,
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

    // Only the explicit `fail_open` opt-out waives the check; no list
    // under `fail_closed` reports the status unavailable. The
    // issuer-Manifest expiry cap is still waived here — threading an
    // `issuerManifestExpiresAt` parameter through the SDK surface is the
    // remaining half of F-1.
    let revocation_check = |q: &aitp::tct::RevocationQuery<'_>| revocation.status(q);
    let builder = TctVerifyContext::builder(aud_ref, &peek.iss, Timestamp::now())
        .skip_manifest_expiry_cap_dangerous();
    let builder = builder.revocation(revocation.source(&revocation_check));
    let ctx = builder
        .build()
        .map_err(|e| Error::from_reason(format!("verify context: {e}")))?;

    let verified = verify_tct(tct_token, &ctx).map_err(|e| {
        coded_error(
            env,
            tct_revocation_code(&e),
            format!("TCT verification failed: {e}"),
        )
    })?;
    let claims = &verified.claims();

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

/// Verify `tct_token` like [`js_verify_tct`], but consult `store` first: on a
/// byte-identical, already-verified, still-valid TCT this skips the signature
/// check. See [`JsTctStore`] for the safety argument.
///
/// Revocation (F-1, `fail_closed`) is applied on **both** the fast and slow
/// paths: a cache hit whose `jti` is revoked, or whose status is
/// unavailable, falls through to a full re-verification, which then fails
/// the revocation gate with its coded error.
///
/// `pop` behaves as in [`js_verify_tct`] and is checked on every call,
/// whether or not the signature was cached.
#[allow(clippy::too_many_arguments)]
pub fn js_verify_tct_cached(
    env: Env,
    our_key: &AitpSigningKey,
    tct_token: &str,
    required_grant: &str,
    store: &JsTctStore,
    expected_audience: Option<&str>,
    revoked_jtis: Option<Vec<String>>,
    revocation: Option<String>,
    pop: Option<&PopExchange>,
) -> Result<JsTctIdentity> {
    let pop = pop_audience(env, tct_token, expected_audience, pop)?;
    let expected_audience = pop
        .as_ref()
        .map(|(sub, ..)| sub.as_str())
        .or(expected_audience);
    let identity = verify_tct_cached_inner(
        env,
        our_key,
        tct_token,
        required_grant,
        store,
        expected_audience,
        revoked_jtis,
        revocation,
    )?;
    finish_pop(env, tct_token, pop)?;
    Ok(identity)
}

/// [`js_verify_tct_cached`] without the PoP step.
#[allow(clippy::too_many_arguments)]
fn verify_tct_cached_inner(
    env: Env,
    our_key: &AitpSigningKey,
    tct_token: &str,
    required_grant: &str,
    store: &JsTctStore,
    expected_audience: Option<&str>,
    revoked_jtis: Option<Vec<String>>,
    revocation: Option<String>,
) -> Result<JsTctIdentity> {
    let key = tct_token_key(tct_token);
    let effective_aud: String = match expected_audience {
        Some(s) => s.to_string(),
        None => our_key.aid().to_string(),
    };
    let revocation = parse_revocation(revoked_jtis.as_deref(), revocation.as_deref())?;

    // Fast path: exact bytes verified before AND policy still holds.
    if let Some(c) = store.get(&key) {
        let now = Timestamp::now().0 as f64;
        let cleared = Uuid::parse_str(&c.jti).is_ok_and(|u| {
            matches!(
                revocation.jti_status(&u),
                Ok(aitp::tct::RevocationStatus::Clear)
            )
        });
        if cleared
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
    let identity = verify_tct_with(
        env,
        our_key,
        tct_token,
        required_grant,
        expected_audience,
        &revocation,
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
