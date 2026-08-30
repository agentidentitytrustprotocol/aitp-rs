//! OIDC identity-binding support — RFC-AITP-0002 (Node SDK).
//!
//! Mirrors `bindings/aitp-py/src/oidc.rs`. Exposes a `JwksProvider` class
//! plus an internal helper that wraps a JS function as the OIDC minter
//! callback. JS callbacks fire on the libuv main thread (the same thread
//! the napi method is invoked on), so sync semantics work without a
//! ThreadsafeFunction round-trip.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use aitp_core::Aid;
use aitp_crypto::AitpVerifyingKey;
use aitp_handshake::{JwkPublicKey, JwksResolver, OidcMintJwtFn, ResolveError};
use napi::bindgen_prelude::*;
use napi::{Env, JSON};
use napi_derive::napi;
use serde_json::Value as JsonValue;
use url::Url;

/// Compute the RFC 7638 JWK thumbprint of the public key embedded in
/// an AID — the value an OIDC IdP MUST place in the JWT's `cnf.jkt`
/// claim when proving the key binding (RFC-AITP-0002 §2.2.1).
///
/// Works for both Ed25519 (`aid:pubkey:ed25519:...`) and P-256
/// (`aid:pubkey:p256:...`) AIDs. Use this from your OIDC minter
/// closure so the bound peer correctly verifies the cnf binding —
/// implementing curve arithmetic by hand to derive the thumbprint
/// in JavaScript is both error-prone and a divergence risk.
#[napi(js_name = "computeAidJkt")]
pub fn compute_aid_jkt(aid: String) -> Result<String> {
    let parsed =
        Aid::parse(&aid).map_err(|e| Error::from_reason(format!("invalid AID '{aid}': {e}")))?;
    let vk = AitpVerifyingKey::from_aid(&parsed)
        .map_err(|e| Error::from_reason(format!("AID has invalid key bytes: {e}")))?;
    vk.to_jwk_thumbprint()
        .map_err(|e| Error::from_reason(format!("jkt computation failed: {e}")))
}

/// In-memory OIDC JWKS provider — issuer URL → list of JWK objects.
///
/// The Node caller fetches the JWKS (the SDK has no HTTP client) and
/// hands the parsed objects to this provider. Implements `JwksResolver`
/// internally so the handshake state machine can dispatch through it.
#[napi]
pub struct JwksProvider {
    inner: Arc<JwksMap>,
}

struct JwksMap {
    keys: Mutex<HashMap<String, Vec<JwkPublicKey>>>,
}

// Adapter for the handshake crate's JwksResolver trait (which uses
// ResolveError) over the Mutex-protected map.
struct JwksMapAdapter(Arc<JwksMap>);

impl JwksResolver for JwksMapAdapter {
    fn resolve(&self, issuer: &Url) -> std::result::Result<Vec<JwkPublicKey>, ResolveError> {
        let map = self
            .0
            .keys
            .lock()
            .map_err(|e| ResolveError::NetworkError(format!("jwks mutex poisoned: {e}")))?;
        match map.get(issuer.as_str()) {
            Some(v) if !v.is_empty() => Ok(v.to_vec()),
            _ => Err(ResolveError::NotTrusted(issuer.clone())),
        }
    }
}

#[napi]
impl JwksProvider {
    /// Construct from an object mapping issuer URLs to arrays of JWK
    /// objects. Each JWK must be a standard RFC 7517 representation
    /// (`kty`, `crv`, `x`, ...). Pass `{}` for an empty provider and
    /// `upsert` later.
    #[napi(constructor)]
    pub fn new(env: Env, keys: Option<Unknown<'_>>) -> Result<Self> {
        let inner = Arc::new(JwksMap {
            keys: Mutex::new(HashMap::new()),
        });
        if let Some(unknown) = keys {
            let parsed: JsonValue = unknown_to_json(&env, &unknown)?;
            let map = parsed.as_object().ok_or_else(|| {
                Error::from_reason("JwksProvider constructor expects an object or undefined")
            })?;
            for (issuer, val) in map {
                let arr = val.as_array().ok_or_else(|| {
                    Error::from_reason(format!("JwksProvider['{issuer}'] must be an array"))
                })?;
                let normalized = Url::parse(issuer).map_err(|e| {
                    Error::from_reason(format!("invalid issuer URL '{issuer}': {e}"))
                })?;
                let jwks = parse_jwk_list(arr)?;
                inner
                    .keys
                    .lock()
                    .map_err(|e| Error::from_reason(format!("jwks mutex poisoned: {e}")))?
                    .insert(normalized.as_str().to_string(), jwks);
            }
        }
        Ok(Self { inner })
    }

    /// Add or replace the JWKs for an issuer. `keys` is a JS array of
    /// JWK objects.
    #[napi]
    pub fn upsert(&self, env: Env, issuer: String, keys: Unknown<'_>) -> Result<()> {
        let parsed: JsonValue = unknown_to_json(&env, &keys)?;
        let arr = parsed
            .as_array()
            .ok_or_else(|| Error::from_reason("upsert(keys) must be an array of JWK objects"))?;
        let normalized = Url::parse(&issuer)
            .map_err(|e| Error::from_reason(format!("invalid issuer URL '{issuer}': {e}")))?;
        let jwks = parse_jwk_list(arr)?;
        self.inner
            .keys
            .lock()
            .map_err(|e| Error::from_reason(format!("jwks mutex poisoned: {e}")))?
            .insert(normalized.as_str().to_string(), jwks);
        Ok(())
    }

    /// Drop all keys for an issuer.
    #[napi]
    pub fn remove(&self, issuer: String) -> Result<()> {
        self.inner
            .keys
            .lock()
            .map_err(|e| Error::from_reason(format!("jwks mutex poisoned: {e}")))?
            .remove(&issuer);
        Ok(())
    }

    /// Return the issuer URLs currently registered.
    #[napi]
    pub fn issuers(&self) -> Result<Vec<String>> {
        let map = self
            .inner
            .keys
            .lock()
            .map_err(|e| Error::from_reason(format!("jwks mutex poisoned: {e}")))?;
        Ok(map.keys().cloned().collect())
    }
}

impl JwksProvider {
    /// Crate-private accessor used by `session.rs` to thread the provider
    /// into the handshake `PeerConfig`.
    pub(crate) fn as_resolver(&self) -> Arc<dyn JwksResolver + Send + Sync + 'static> {
        Arc::new(JwksMapAdapter(self.inner.clone()))
    }
}

fn parse_jwk_list(arr: &[JsonValue]) -> Result<Vec<JwkPublicKey>> {
    let mut out = Vec::with_capacity(arr.len());
    for (i, val) in arr.iter().enumerate() {
        let jwk = JwkPublicKey::from_jwk_json(val)
            .map_err(|e| Error::from_reason(format!("JWK at index {i} invalid: {e}")))?;
        out.push(jwk);
    }
    Ok(out)
}

fn unknown_to_json(env: &Env, val: &Unknown<'_>) -> Result<JsonValue> {
    let json: JSON = env.get_global()?.get_named_property_unchecked("JSON")?;
    let s: String = json.stringify(*val)?;
    serde_json::from_str(&s)
        .map_err(|e| Error::from_reason(format!("could not re-parse JSON: {e}")))
}

/// Wrap a JS function as an [`OidcMintJwtFn`] for one handshake step.
///
/// JS callables fire on the libuv main thread (the same thread the
/// `#[napi]` method is invoked on), so this closure is only ever called
/// synchronously inside the same call. `OidcMintJwtFn` is intentionally
/// not `Send + Sync` for exactly this case.
///
/// `js_fn` is a [`FunctionRef`], napi 3's Drop-safe typed function
/// reference — dropping the closure unused (e.g. when the state machine
/// errors before `build_descriptor` runs) is handled cleanly by
/// `FunctionRef`'s own `Drop` impl.
pub(crate) fn make_oidc_minter(
    env: Env,
    js_fn: FunctionRef<String, String>,
) -> Result<Box<OidcMintJwtFn>> {
    let closure = move |nonce: &str| -> std::result::Result<String, String> {
        let f = js_fn
            .borrow_back(&env)
            .map_err(|e| format!("oidc minter: {e}"))?;
        f.call(nonce.to_string())
            .map_err(|e| format!("oidc_mint_jwt raised: {e}"))
    };
    Ok(Box::new(closure))
}
