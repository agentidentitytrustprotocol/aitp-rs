//! `AitpAgent` — an Ed25519 or P-256 identity plus its published Manifest.

use std::sync::Arc;

use aitp_core::RawUrl;
use aitp_crypto::AitpSigningKey;
use aitp_manifest::{IdentityHint, IdentityHintKind, Manifest, ManifestBuilder, ManifestEnvelope};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyList;

use crate::delegation::{
    build_delegation_token_json, issue_tct_for_delegatee_json, PyDelegationVerified,
};
use crate::oidc::PyJwksProvider;
#[cfg(feature = "experimental-renewal")]
use crate::renewal::{build_renewal_request_py, process_renewal_request_py};
use crate::revocation::sign_revocation_list_py;
use crate::session::{PyInitiatorSession, PyResponderSession, SessionContext};
use crate::tct::{py_verify_tct, PyTctIdentity};

/// An AITP agent: an Ed25519 or P-256 signing key plus (once built) its
/// Manifest.
#[pyclass(name = "AitpAgent")]
pub struct PyAitpAgent {
    key: Arc<AitpSigningKey>,
    manifest: Option<Manifest>,
}

#[pymethods]
impl PyAitpAgent {
    /// Generate an agent with a fresh random key.
    ///
    /// `suite` selects the signing algorithm:
    /// - `"ed25519"` (default) — the v0.1 algorithm; smaller AIDs.
    /// - `"p256"` — RFC-AITP-0001 §5.4.3 P-256 ECDSA suite. Produces
    ///   `aid:pubkey:p256:<44>` AIDs and `p256.<86b64u>` signatures.
    #[staticmethod]
    #[pyo3(signature = (suite = "ed25519"))]
    fn generate(suite: &str) -> PyResult<Self> {
        let key = match suite {
            "ed25519" => AitpSigningKey::generate_ed25519(),
            "p256" => AitpSigningKey::generate_p256(),
            other => {
                return Err(PyValueError::new_err(format!(
                    "unknown suite '{other}': expected 'ed25519' or 'p256'"
                )))
            }
        };
        Ok(Self {
            key: Arc::new(key),
            manifest: None,
        })
    }

    /// Construct an agent from a 32-byte seed (deterministic). `suite`
    /// matches [`Self::generate`].
    ///
    /// For `"p256"`, a very small fraction of 32-byte seeds are not valid
    /// P-256 private scalars (zero or ≥ curve order); those raise.
    #[staticmethod]
    #[pyo3(signature = (seed, suite = "ed25519"))]
    fn from_seed(seed: &[u8], suite: &str) -> PyResult<Self> {
        let arr: [u8; 32] = seed
            .try_into()
            .map_err(|_| PyValueError::new_err("seed must be exactly 32 bytes"))?;
        let key = match suite {
            "ed25519" => AitpSigningKey::from_ed25519_seed(&arr),
            "p256" => AitpSigningKey::from_p256_seed(&arr)
                .map_err(|e| PyValueError::new_err(format!("invalid P-256 seed: {e}")))?,
            other => {
                return Err(PyValueError::new_err(format!(
                    "unknown suite '{other}': expected 'ed25519' or 'p256'"
                )))
            }
        };
        Ok(Self {
            key: Arc::new(key),
            manifest: None,
        })
    }

    /// The agent's AID string (`aid:pubkey:...`).
    #[getter]
    fn aid(&self) -> String {
        self.key.aid().to_string()
    }

    /// Build and sign the agent's Manifest. Returns `ManifestEnvelope`
    /// JSON and caches the Manifest for use by `new_session` /
    /// `new_responder`.
    ///
    /// `identity_type` selects how this agent will present its identity
    /// in the handshake:
    /// - `"pinned_key"` (default, RFC-AITP-0002 §3.2) — the AID's pubkey
    ///   is bound directly. The identity_hint embeds the raw pubkey.
    /// - `"oidc"` (RFC-AITP-0002 §2) — identity is asserted via a JWT
    ///   minted by `oidc_issuer` with `oidc_subject` as the `sub` claim.
    ///   Both `oidc_issuer` and `oidc_subject` are required when
    ///   `identity_type="oidc"`. The agent's accepted trust anchors are
    ///   set to `[oidc_issuer]` so the peer's OIDC presentation against
    ///   the same issuer round-trips out of the box; pass
    ///   `accepted_trust_anchors` to override.
    #[pyo3(signature = (
        display_name,
        handshake_endpoint,
        offered_caps,
        required_caps=None,
        ttl_secs=None,
        identity_type="pinned_key",
        oidc_issuer=None,
        oidc_subject=None,
        accepted_trust_anchors=None,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn build_manifest(
        &mut self,
        display_name: &str,
        handshake_endpoint: &str,
        offered_caps: Vec<String>,
        required_caps: Option<Vec<String>>,
        ttl_secs: Option<i64>,
        identity_type: &str,
        oidc_issuer: Option<&str>,
        oidc_subject: Option<&str>,
        accepted_trust_anchors: Option<Vec<String>>,
    ) -> PyResult<String> {
        let endpoint: url::Url = handshake_endpoint
            .parse()
            .map_err(|e| PyValueError::new_err(format!("invalid handshake_endpoint URL: {e}")))?;

        let (hint, accepted_type, default_anchors): (IdentityHint, &'static str, Vec<url::Url>) =
            match identity_type {
                "pinned_key" => {
                    let pk = self.key.verifying_key();
                    // try_to_ed25519_bytes() is the non-panicking
                    // accessor; None signals the agent uses a P-256
                    // key, which the pinned-key wire shape cannot
                    // encode in v0.1.
                    let pk_bytes = pk.try_to_ed25519_bytes().ok_or_else(|| {
                        PyRuntimeError::new_err(
                            "pinned_key identity_hint with a P-256 agent key is not supported; \
                         the manifest's identity_hint.public_key is Ed25519-only in v0.1",
                        )
                    })?;
                    (
                        IdentityHint {
                            kind: IdentityHintKind::PinnedKey,
                            subject: display_name.to_string(),
                            issuer: None,
                            public_key: Some(aitp_core::base64url::encode(&pk_bytes)),
                        },
                        "pinned_key",
                        vec![],
                    )
                }
                "oidc" => {
                    let iss_str = oidc_issuer.ok_or_else(|| {
                        PyValueError::new_err("oidc_issuer is required when identity_type='oidc'")
                    })?;
                    let sub = oidc_subject.ok_or_else(|| {
                        PyValueError::new_err("oidc_subject is required when identity_type='oidc'")
                    })?;
                    let iss: url::Url = iss_str.parse().map_err(|e| {
                        PyValueError::new_err(format!("invalid oidc_issuer URL: {e}"))
                    })?;
                    (
                        IdentityHint {
                            kind: IdentityHintKind::Oidc,
                            subject: sub.to_string(),
                            issuer: Some(RawUrl::from(iss.clone())),
                            public_key: None,
                        },
                        "oidc",
                        vec![iss],
                    )
                }
                other => {
                    return Err(PyValueError::new_err(format!(
                        "unknown identity_type '{other}': expected 'pinned_key' or 'oidc'"
                    )))
                }
            };

        let mut builder = ManifestBuilder::new(&self.key)
            .display_name(display_name)
            .handshake_endpoint(endpoint)
            .identity_hint(hint)
            .accept_identity_type(accepted_type)
            .ttl_secs(ttl_secs.unwrap_or(3600));

        let anchors: Vec<url::Url> = match accepted_trust_anchors {
            Some(list) => list
                .into_iter()
                .map(|s| s.parse::<url::Url>())
                .collect::<Result<_, _>>()
                .map_err(|e| {
                    PyValueError::new_err(format!("invalid accepted_trust_anchors URL: {e}"))
                })?,
            None => default_anchors,
        };
        for a in anchors {
            builder = builder.accept_trust_anchor(a);
        }

        for cap in offered_caps {
            builder = builder.offer(cap);
        }
        for cap in required_caps.unwrap_or_default() {
            builder = builder.require(cap);
        }

        let manifest = builder
            .build()
            .map_err(|e| PyRuntimeError::new_err(format!("manifest build failed: {e}")))?;
        self.manifest = Some(manifest.clone());

        serde_json::to_string(&ManifestEnvelope { manifest })
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }

    /// Create a new outbound (initiator) handshake session.
    ///
    /// `jwks` is an optional [`JwksProvider`] used when the peer's
    /// manifest advertises an OIDC identity. `trust_anchors` overrides
    /// the agent manifest's accepted_trust_anchors for verification
    /// purposes; pass `None` to reuse the manifest's list (typical).
    #[pyo3(signature = (jwks=None, trust_anchors=None))]
    fn new_session(
        &self,
        jwks: Option<&PyJwksProvider>,
        trust_anchors: Option<Vec<String>>,
    ) -> PyResult<PyInitiatorSession> {
        let manifest = self.cached_manifest()?;
        let ctx = build_session_context(&manifest, jwks, trust_anchors)?;
        Ok(PyInitiatorSession::new(self.key.clone(), manifest, ctx))
    }

    /// Create a new inbound (responder) handshake session. Mirror of
    /// [`Self::new_session`].
    #[pyo3(signature = (jwks=None, trust_anchors=None))]
    fn new_responder(
        &self,
        jwks: Option<&PyJwksProvider>,
        trust_anchors: Option<Vec<String>>,
    ) -> PyResult<PyResponderSession> {
        let manifest = self.cached_manifest()?;
        let ctx = build_session_context(&manifest, jwks, trust_anchors)?;
        Ok(PyResponderSession::new(self.key.clone(), manifest, ctx))
    }

    /// Verify a TCT JSON string and require `required_grant`. Raises on
    /// an invalid, mis-audienced, expired, or under-scoped TCT.
    ///
    /// `expected_audience` defaults to `None`, which means "verify as the
    /// holder" (RFC-AITP-0005 §9 receipt model — `our_key.aid()` is used).
    /// Resource servers verifying a TCT presented by a peer should pass
    /// the TCT's own `audience` field as `expected_audience` (in v0.1
    /// this equals `subject`); the signature check then proves the TCT
    /// was issued by us, which is the real security gate for that
    /// direction.
    #[pyo3(signature = (tct_json, required_grant, expected_audience=None))]
    fn verify_tct(
        &self,
        tct_json: &str,
        required_grant: &str,
        expected_audience: Option<&str>,
    ) -> PyResult<PyTctIdentity> {
        py_verify_tct(&self.key, tct_json, required_grant, expected_audience)
    }

    /// Build a `DelegationEnvelope` JSON from a held TCT (RFC-AITP-0006).
    ///
    /// The caller (delegator B) signs the resulting token; the audience is
    /// fixed to the held TCT's issuer (A). The recipient (C) is identified
    /// by `delegatee_aid` and bound by `delegatee_pubkey_b64u` (raw Ed25519
    /// public key, base64url 43 chars).
    #[pyo3(signature = (held_tct_envelope_json, delegatee_aid, delegatee_pubkey_b64u, scope, ttl_secs = None))]
    fn build_delegation(
        &self,
        held_tct_envelope_json: &str,
        delegatee_aid: &str,
        delegatee_pubkey_b64u: &str,
        scope: Vec<String>,
        ttl_secs: Option<i64>,
    ) -> PyResult<String> {
        build_delegation_token_json(
            &self.key,
            held_tct_envelope_json,
            delegatee_aid,
            delegatee_pubkey_b64u,
            scope,
            ttl_secs,
        )
    }

    /// Mint a fresh `TctEnvelope` JSON for a delegatee after the verifier has
    /// confirmed the delegation. The subject_pubkey binding is taken from the
    /// verified token's `cnf` field.
    #[pyo3(signature = (verified, ttl_secs = None))]
    fn issue_tct_for_delegatee(
        &self,
        verified: &PyDelegationVerified,
        ttl_secs: Option<i64>,
    ) -> PyResult<String> {
        issue_tct_for_delegatee_json(&self.key, verified, ttl_secs)
    }

    /// Sign a `RevocationList` with this agent's key. `entries` is a list of
    /// dicts with keys `jti` (UUID string, required), `revoked_at` (int unix
    /// seconds, optional — defaults to now), and `reason` (str, optional).
    /// `expires_in_secs` defaults to 3600. Returns the on-wire
    /// `RevocationListEnvelope` JSON.
    #[pyo3(signature = (entries, expires_in_secs = None))]
    fn sign_revocation_list(
        &self,
        entries: &Bound<'_, PyList>,
        expires_in_secs: Option<i64>,
    ) -> PyResult<String> {
        sign_revocation_list_py(&self.key, entries, expires_in_secs)
    }

    /// Holder side: build a `TctRenewalPayload` JSON for an in-band
    /// renewal of `current_tct_envelope_json` (RFC-AITP-0005 §10).
    ///
    /// **Gated by the `experimental-renewal` Cargo feature.** Off in the
    /// default wheel; build with `maturin develop --features
    /// experimental-renewal` (or `--features experimental` for the
    /// umbrella) to enable.
    #[cfg(feature = "experimental-renewal")]
    fn build_renewal_request(&self, current_tct_envelope_json: &str) -> PyResult<String> {
        build_renewal_request_py(&self.key, current_tct_envelope_json)
    }

    /// Issuer side: verify a `TctRenewalPayload` JSON request and mint a
    /// fresh `TctEnvelope` JSON.
    ///
    /// `manifest_exp_unix_secs` bounds the new TCT's expiry to the
    /// issuer's manifest window; `new_ttl_secs` is the requested
    /// lifetime (capped by the bound).
    ///
    /// **Gated by the `experimental-renewal` Cargo feature.**
    #[cfg(feature = "experimental-renewal")]
    fn process_renewal_request(
        &self,
        request_payload_json: &str,
        manifest_exp_unix_secs: i64,
        new_ttl_secs: i64,
    ) -> PyResult<String> {
        process_renewal_request_py(
            &self.key,
            request_payload_json,
            manifest_exp_unix_secs,
            new_ttl_secs,
        )
    }
}

impl PyAitpAgent {
    /// Crate-internal accessor used by bundle / renewal modules that
    /// need to sign with the agent's long-term key.
    pub(crate) fn signing_key(&self) -> Arc<AitpSigningKey> {
        self.key.clone()
    }

    fn cached_manifest(&self) -> PyResult<Arc<Manifest>> {
        self.manifest.clone().map(Arc::new).ok_or_else(|| {
            PyRuntimeError::new_err("call build_manifest() before creating a session")
        })
    }
}

/// Build the per-session OIDC/trust-anchor context.
///
/// - `jwks`: caller-supplied JWKS provider; `None` ⇒ no JWKS resolver
///   wired in (pinned-key-only sessions).
/// - `trust_anchors`: overrides the manifest's accepted_trust_anchors for
///   verification; `None` reuses the manifest's list.
fn build_session_context(
    manifest: &Manifest,
    jwks: Option<&PyJwksProvider>,
    trust_anchors: Option<Vec<String>>,
) -> PyResult<SessionContext> {
    let anchors: Vec<RawUrl> = match trust_anchors {
        Some(list) => list
            .into_iter()
            .map(|s| {
                s.parse::<url::Url>()
                    .map(RawUrl::from)
                    .map_err(|e| PyValueError::new_err(format!("invalid trust anchor URL: {e}")))
            })
            .collect::<PyResult<_>>()?,
        None => manifest.accepted_trust_anchors.clone(),
    };
    Ok(SessionContext {
        jwks: jwks.map(|p| p.as_resolver()),
        trust_anchors: anchors,
        identity_kind: manifest.identity_hint.kind,
        identity_subject: manifest.identity_hint.subject.clone(),
        identity_issuer: manifest.identity_hint.issuer.clone(),
    })
}
