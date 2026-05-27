//! Shared helpers: JWKS resolvers, `PeerConfig` construction, and a
//! Drop-aware wrapper around `napi::Ref<JsFunction>` used by the OIDC
//! minter and the session-bundle revocation callback.

use aitp_core::{RawUrl, Timestamp};
use aitp_crypto::AitpSigningKey;
use aitp_handshake::{JwkPublicKey, JwksResolver, PeerConfig, ResolveError};
use aitp_manifest::Manifest;
use napi::{Env, JsFunction, Ref};
use std::cell::RefCell;
use url::Url;

/// Drop-aware wrapper around `napi::Ref<JsFunction>`.
///
/// `napi::Ref::Drop` panics if its underlying handle wasn't explicitly
/// `unref`ed beforehand (the panic surfaces as
/// `Ref count is not equal to 0 while dropping Ref, potential memory leak`).
/// Closures that take a JS callback can be dropped without ever invoking
/// the callback — e.g. the handshake state machine errors out before
/// `mint_jwt` runs, or `verify_session_bundle` rejects the envelope
/// before iterating participants. This guard always unrefs on drop, so
/// neither call site can leak.
pub struct JsFnRef {
    inner: RefCell<Option<Ref<()>>>,
    env_raw: napi::sys::napi_env,
}

impl JsFnRef {
    /// Wrap a `JsFunction` in a Drop-aware reference. The function
    /// survives until this guard is dropped.
    pub fn new(env: Env, js_fn: JsFunction) -> napi::Result<Self> {
        // create_reference takes any napi Value and returns a Ref<()>.
        let r = env.create_reference(js_fn)?;
        Ok(Self {
            inner: RefCell::new(Some(r)),
            env_raw: env.raw(),
        })
    }

    /// Reify the underlying JsFunction. Returns an error if the ref has
    /// already been consumed (shouldn't happen in well-formed code).
    pub fn get(&self) -> napi::Result<JsFunction> {
        let held = self.inner.borrow();
        let r = held
            .as_ref()
            .ok_or_else(|| napi::Error::from_reason("JsFnRef: callback handle already consumed"))?;
        // SAFETY: env_raw was captured during this guard's construction
        // and is valid for the lifetime of the enclosing `#[napi]`
        // method call (we never store JsFnRef across calls).
        let env = unsafe { Env::from_raw(self.env_raw) };
        env.get_reference_value(r)
    }
}

impl Drop for JsFnRef {
    fn drop(&mut self) {
        if let Some(mut r) = self.inner.borrow_mut().take() {
            // SAFETY: same env_raw lifetime guarantee as `get`.
            let env = unsafe { Env::from_raw(self.env_raw) };
            // Best-effort: we're in Drop, can't propagate the Result.
            let _ = r.unref(env);
        }
    }
}

/// A JWKS resolver that always fails. Used for pinned-key-only sessions.
pub struct NoOpJwksResolver;

impl JwksResolver for NoOpJwksResolver {
    fn resolve(&self, _issuer: &Url) -> Result<Vec<JwkPublicKey>, ResolveError> {
        Err(ResolveError::NetworkError(
            "no JWKS resolver configured for this session (pinned-key only)".into(),
        ))
    }
}

/// Build a [`PeerConfig`] with the supplied resolver and trust anchors.
pub fn make_peer_config<'a>(
    key: &'a AitpSigningKey,
    manifest: &'a Manifest,
    jwks: &'a (dyn JwksResolver + 'a),
    trust_anchors: &'a [RawUrl],
) -> PeerConfig<'a> {
    PeerConfig {
        signing_key: key,
        manifest,
        trust_anchors,
        jwks_resolver: jwks,
        pinned_key_store: None,
        grant_policy: None,
        revocation_check: None,
        now: Timestamp::now(),
    }
}
