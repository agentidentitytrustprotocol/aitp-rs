//! OIDC identity-binding support — RFC-AITP-0002.
//!
//! Two types live here:
//!
//! 1. [`PyJwksProvider`] — an in-memory issuer-URL → list-of-JWKs map.
//!    The SDK does no HTTP; callers fetch the JWKS themselves (e.g.
//!    `httpx.get("...jwks.json")`) and pass the parsed dict in. This is
//!    enough for the production pattern of "fetch once at startup, refresh
//!    on rotation."
//!
//! 2. [`OidcMinterCallback`] — a wrapper around a Python callable that
//!    receives the just-generated handshake `pop_nonce` and returns the
//!    freshly-minted JWT. Lives only for the duration of a single
//!    `build_hello` / `process_hello` call.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use aitp_handshake::{JwkPublicKey, JwksResolver, OidcMintJwtFn, ResolveError};
use jsonwebtoken::{jwk::Jwk, Algorithm, DecodingKey};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use serde_json::Value as JsonValue;
use url::Url;

/// In-memory OIDC JWKS provider — issuer URL → list of JWK dicts.
///
/// The Python caller fetches the JWKS (the SDK has no HTTP client) and
/// hands the parsed dicts to this provider. Implements `JwksResolver`
/// internally so the handshake state machine can dispatch through it.
#[pyclass(name = "JwksProvider")]
pub struct PyJwksProvider {
    inner: Arc<JwksMap>,
}

struct JwksMap {
    keys: Mutex<HashMap<String, Vec<JwkPublicKey>>>,
}

impl JwksResolver for JwksMap {
    fn resolve(&self, issuer: &Url) -> Result<Vec<JwkPublicKey>, ResolveError> {
        let map = self
            .keys
            .lock()
            .map_err(|e| ResolveError::NetworkError(format!("jwks mutex poisoned: {e}")))?;
        match map.get(issuer.as_str()) {
            Some(v) if !v.is_empty() => Ok(v.iter().cloned().collect()),
            Some(_) | None => Err(ResolveError::NotTrusted(issuer.clone())),
        }
    }
}

#[pymethods]
impl PyJwksProvider {
    /// Construct from a dict mapping issuer URLs to lists of JWK dicts.
    /// Each JWK dict must be a standard RFC 7517 representation
    /// (`kty`, `crv`, `x`, ...). Pass `{}` for an empty provider and
    /// upsert later.
    #[new]
    #[pyo3(signature = (keys=None))]
    fn new(keys: Option<&Bound<'_, PyDict>>) -> PyResult<Self> {
        let inner = Arc::new(JwksMap {
            keys: Mutex::new(HashMap::new()),
        });
        if let Some(d) = keys {
            for (k, v) in d.iter() {
                let issuer: String = k.extract().map_err(|_| {
                    PyValueError::new_err("JwksProvider keys must be issuer URL strings")
                })?;
                let list = v.downcast::<PyList>().map_err(|_| {
                    PyValueError::new_err(format!("JwksProvider['{issuer}'] must be a list"))
                })?;
                upsert_inner(&inner, &issuer, list)?;
            }
        }
        Ok(Self { inner })
    }

    /// Add or replace the JWKs for an issuer.
    fn upsert(&self, issuer: &str, keys: &Bound<'_, PyList>) -> PyResult<()> {
        upsert_inner(&self.inner, issuer, keys)
    }

    /// Drop all keys for an issuer (no-op if not present).
    fn remove(&self, issuer: &str) -> PyResult<()> {
        let mut map = self
            .inner
            .keys
            .lock()
            .map_err(|e| PyRuntimeError::new_err(format!("jwks mutex poisoned: {e}")))?;
        map.remove(issuer);
        Ok(())
    }

    /// Return the issuer URLs currently registered.
    fn issuers(&self) -> PyResult<Vec<String>> {
        let map = self
            .inner
            .keys
            .lock()
            .map_err(|e| PyRuntimeError::new_err(format!("jwks mutex poisoned: {e}")))?;
        Ok(map.keys().cloned().collect())
    }
}

impl PyJwksProvider {
    /// Crate-private accessor used by `session.rs` to thread the provider
    /// into the handshake `PeerConfig`.
    pub(crate) fn as_resolver(&self) -> Arc<dyn JwksResolver + Send + Sync + 'static> {
        self.inner.clone()
    }
}

fn upsert_inner(inner: &Arc<JwksMap>, issuer: &str, keys: &Bound<'_, PyList>) -> PyResult<()> {
    let normalized = Url::parse(issuer)
        .map_err(|e| PyValueError::new_err(format!("invalid issuer URL '{issuer}': {e}")))?;
    let parsed = parse_jwk_list(keys)?;
    let mut map = inner
        .keys
        .lock()
        .map_err(|e| PyRuntimeError::new_err(format!("jwks mutex poisoned: {e}")))?;
    map.insert(normalized.as_str().to_string(), parsed);
    Ok(())
}

fn parse_jwk_list(keys: &Bound<'_, PyList>) -> PyResult<Vec<JwkPublicKey>> {
    let mut out = Vec::with_capacity(keys.len());
    for (i, item) in keys.iter().enumerate() {
        let d = item
            .downcast::<PyDict>()
            .map_err(|_| PyValueError::new_err(format!("JWK at index {i} must be a dict")))?;
        let as_json = pydict_to_json(d)?;
        let jwk: Jwk = serde_json::from_value(as_json)
            .map_err(|e| PyValueError::new_err(format!("JWK at index {i} invalid: {e}")))?;
        let alg = jwk.common.key_algorithm.and_then(|ka| {
            // jsonwebtoken's KeyAlgorithm → Algorithm conversion
            ka.to_string().parse::<Algorithm>().ok()
        });
        let alg = alg.ok_or_else(|| {
            PyValueError::new_err(format!(
                "JWK at index {i} is missing or has an unsupported `alg`/`kty` algorithm"
            ))
        })?;
        let key = DecodingKey::from_jwk(&jwk).map_err(|e| {
            PyValueError::new_err(format!("JWK at index {i} could not be loaded: {e}"))
        })?;
        out.push(JwkPublicKey {
            kid: jwk.common.key_id.clone(),
            alg,
            key,
        });
    }
    Ok(out)
}

fn pydict_to_json(d: &Bound<'_, PyDict>) -> PyResult<JsonValue> {
    let json_module = d.py().import_bound("json")?;
    let dumps = json_module.getattr("dumps")?;
    let s: String = dumps.call1((d,))?.extract()?;
    serde_json::from_str(&s)
        .map_err(|e| PyRuntimeError::new_err(format!("could not re-parse JWK JSON: {e}")))
}

/// Wrap a Python callable as an [`OidcMintJwtFn`] for one handshake step.
///
/// The callable receives the handshake-generated `pop_nonce` (str) and must
/// return the compact JWT (str) whose `nonce` claim equals that nonce.
/// Exceptions propagate as a `HandshakeError::Identity`.
pub(crate) fn make_oidc_minter(callable: Py<PyAny>) -> Box<OidcMintJwtFn> {
    Box::new(move |nonce: &str| -> Result<String, String> {
        Python::with_gil(|py| {
            let bound = callable.bind(py);
            let res = bound
                .call1((nonce,))
                .map_err(|e| format!("oidc_mint_jwt raised: {e}"))?;
            let s: String = res
                .extract()
                .map_err(|e| format!("oidc_mint_jwt must return str: {e}"))?;
            Ok(s)
        })
    })
}
