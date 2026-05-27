//! OIDC identity-binding support — RFC-AITP-0002 (Node SDK).
//!
//! Mirrors `bindings/aitp-py/src/oidc.rs`. Exposes a `JwksProvider` class
//! plus an internal helper that wraps a JS function as the OIDC minter
//! callback. JS callbacks fire on the libuv main thread (the same thread
//! the napi method is invoked on), so sync semantics work without a
//! ThreadsafeFunction round-trip.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use aitp_handshake::{JwkPublicKey, JwksResolver, OidcMintJwtFn, ResolveError};
use jsonwebtoken::{jwk::Jwk, Algorithm, DecodingKey};
use napi::bindgen_prelude::*;
use napi::{Env, JsFunction, JsString, JsUnknown};
use napi_derive::napi;
use serde_json::Value as JsonValue;
use url::Url;

use crate::helpers::JsFnRef;

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
            Some(v) if !v.is_empty() => Ok(v.iter().cloned().collect()),
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
    pub fn new(env: Env, keys: Option<JsUnknown>) -> Result<Self> {
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
    pub fn upsert(&self, env: Env, issuer: String, keys: JsUnknown) -> Result<()> {
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
        let jwk: Jwk = serde_json::from_value(val.clone())
            .map_err(|e| Error::from_reason(format!("JWK at index {i} invalid: {e}")))?;
        let alg = jwk
            .common
            .key_algorithm
            .and_then(|ka| ka.to_string().parse::<Algorithm>().ok())
            .ok_or_else(|| {
                Error::from_reason(format!(
                    "JWK at index {i} is missing or has an unsupported `alg`/`kty` algorithm"
                ))
            })?;
        let key = DecodingKey::from_jwk(&jwk).map_err(|e| {
            Error::from_reason(format!("JWK at index {i} could not be loaded: {e}"))
        })?;
        out.push(JwkPublicKey {
            kid: jwk.common.key_id.clone(),
            alg,
            key,
        });
    }
    Ok(out)
}

fn unknown_to_json(env: &Env, val: &JsUnknown) -> Result<JsonValue> {
    let json = env
        .get_global()?
        .get_named_property::<napi::JsObject>("JSON")?;
    let stringify: JsFunction = json.get_named_property("stringify")?;
    let res: JsUnknown = stringify.call(Some(&json), &[val])?;
    let s: JsString = res.try_into()?;
    let s = s.into_utf8()?;
    serde_json::from_str(s.as_str()?)
        .map_err(|e| Error::from_reason(format!("could not re-parse JSON: {e}")))
}

/// Wrap a JS function as an [`OidcMintJwtFn`] for one handshake step.
///
/// JS callables fire on the libuv main thread (the same thread the
/// `#[napi]` method is invoked on), so this closure is only ever called
/// synchronously inside the same call. `OidcMintJwtFn` is intentionally
/// not `Send + Sync` for exactly this case.
///
/// The closure holds a [`JsFnRef`] guard that unrefs the JS handle on
/// drop, so dropping the closure unused (e.g. when the state machine
/// errors before `build_descriptor` runs) does not panic napi-rs's
/// `Ref` Drop impl.
pub(crate) fn make_oidc_minter(env: Env, js_fn: JsFunction) -> Result<Box<OidcMintJwtFn>> {
    let fn_ref = JsFnRef::new(env, js_fn)?;
    let env_raw = env.raw();
    let closure = move |nonce: &str| -> std::result::Result<String, String> {
        // SAFETY: env_raw is valid for the duration of the enclosing
        // `#[napi]` method call; OidcMintJwtFn is !Send + !Sync so we
        // never cross threads.
        let env = unsafe { Env::from_raw(env_raw) };
        let callable: JsFunction = fn_ref.get().map_err(|e| format!("oidc minter: {e}"))?;
        let js_nonce: JsString = env
            .create_string(nonce)
            .map_err(|e| format!("oidc minter: create_string failed: {e}"))?;
        let res: JsUnknown = callable
            .call(None, &[js_nonce.into_unknown()])
            .map_err(|e| format!("oidc_mint_jwt raised: {e}"))?;
        let res_str: JsString = res
            .try_into()
            .map_err(|e| format!("oidc_mint_jwt must return a string: {e}"))?;
        let s = res_str
            .into_utf8()
            .map_err(|e| format!("oidc_mint_jwt return: utf8 conversion failed: {e}"))?;
        Ok(s.as_str()
            .map_err(|e| format!("oidc_mint_jwt return: not valid utf8: {e}"))?
            .to_string())
    };
    Ok(Box::new(closure))
}
