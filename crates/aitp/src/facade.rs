//! High-level helpers (alpha.5 P15) — one-call drivers for the Mutual
//! Handshake and TCT renewal flows.
//!
//! These wrap [`aitp_handshake`] + [`aitp_transport_http`] so callers
//! that don't need the per-step state machine can drive a full
//! handshake from a Manifest URL in a single call.

use crate::core::{AitpEnvelope, MessageType, Timestamp};
use crate::crypto::{AitpSigningKey, AitpVerifyingKey};
use crate::handshake::{
    Initiator, JwksResolver, MutualCommitAckPayload, MutualHelloAckPayload, PeerConfig,
    PinnedKeyStore, PresentedIdentity,
};
use crate::manifest::Manifest;
#[cfg(feature = "experimental-renewal")]
use crate::tct::{build_renewal_request, TctRenewalPayload};
use crate::tct::{Tct, TctEnvelope};
use crate::transport::{
    sign_envelope_with, verify_envelope_signature, FetchError, ManifestFetcher,
};
use std::time::Duration;
use uuid::Uuid;

/// Explicit trust posture for the high-level [`run_initiator_handshake`].
///
/// Pre-v0.1.0-rc.2 the facade silently accepted any pinned-key peer that
/// proved possession of the key matching its AID — no "is this key one
/// I trust?" gate. RFC-AITP-0002 §3.2 step 1 requires that gate. This
/// enum forces callers to choose explicitly:
///
/// - [`TrustMode::PinnedKeys`] — production pinned-key deployments;
///   peers MUST appear in the supplied [`PinnedKeyStore`].
/// - [`TrustMode::Oidc`] — production OIDC deployments; peers are
///   authenticated by an issuer in `trust_anchors` whose JWKS is
///   resolved by `jwks_resolver`.
/// - [`TrustMode::UnsafeNoTrustEnforcement`] — development/testing only.
///   The name is intentionally long and alarming so it shows up in code
///   review.
pub enum TrustMode<'a> {
    /// Require all pinned-key peers to appear in this store.
    PinnedKeys(&'a dyn PinnedKeyStore),
    /// Accept peers authenticated by any issuer in `trust_anchors`,
    /// with JWKS resolved by `jwks_resolver`.
    Oidc {
        /// Trust anchors (issuer URLs) the verifying peer accepts.
        trust_anchors: &'a [aitp_core::RawUrl],
        /// Resolver for issuer JWKS (typically a
        /// [`aitp_transport_http::key_resolution::KeyResolutionPolicy`]).
        jwks_resolver: &'a dyn JwksResolver,
    },
    /// Skip pinned-key trust enforcement. **INSECURE** — development
    /// and testing only. A peer using any Ed25519 key whose hash
    /// matches its AID will be accepted.
    UnsafeNoTrustEnforcement,
}

/// No-op JWKS resolver. Used for the pinned-key trust mode where OIDC
/// resolution is never invoked.
struct NoOpJwksResolver;

impl JwksResolver for NoOpJwksResolver {
    fn resolve(
        &self,
        _issuer: &url::Url,
    ) -> Result<Vec<crate::handshake::JwkPublicKey>, crate::handshake::ResolveError> {
        Err(crate::handshake::ResolveError::NetworkError(
            "no JWKS resolver configured (TrustMode::PinnedKeys / UnsafeNoTrustEnforcement)".into(),
        ))
    }
}

/// Output of [`run_initiator_handshake`] — the peer's AID, the
/// peer-issued TCT we now hold, and the peer's verifying key (so the
/// caller can use the held TCT for downstream PoP without re-fetching
/// the peer Manifest).
#[derive(Debug, Clone)]
pub struct SessionContext {
    /// Peer's AID — `held_tct.issuer == peer_aid`.
    pub peer_aid: aitp_core::Aid,
    /// Peer's verifying key (for downstream PoP verification).
    pub peer_pubkey: AitpVerifyingKey,
    /// TCT the peer issued to us.
    pub held_tct: Tct,
}

/// Errors from the high-level helpers.
#[derive(Debug, thiserror::Error)]
pub enum FacadeError {
    /// Manifest fetch failure.
    #[error("manifest fetch failed: {0}")]
    Manifest(#[from] FetchError),
    /// Handshake-level error.
    #[error("handshake failed: {0}")]
    Handshake(#[from] aitp_handshake::HandshakeError),
    /// HTTP transport error.
    #[error("HTTP error: {0}")]
    Http(String),
    /// JSON serialization error.
    #[error("serialization: {0}")]
    Serde(#[from] serde_json::Error),
    /// Renewal-specific error.
    #[error("renewal failed: {0}")]
    Renewal(#[from] aitp_tct::TctError),
    /// Manifest-level rejection (e.g.
    /// [`aitp_manifest::ManifestError::IncompatibleIdentityType`] when
    /// the peer Manifest's `accepted_identity_types` doesn't include
    /// the type we'd present — RFC-AITP-0003 §3.2 / §5 step 5).
    #[error("manifest verification: {0}")]
    ManifestVerify(#[from] aitp_manifest::ManifestError),
}

/// Drive a complete initiator-side Mutual Handshake against a peer
/// reachable over HTTPS.
///
/// 1. Fetches the peer Manifest from `peer_origin/.well-known/aitp-manifest`.
/// 2. Builds a `MutualHelloPayload`, POSTs it.
/// 3. Drives the state machine through HELLO_ACK → COMMIT → COMMIT_ACK.
/// 4. Returns the [`SessionContext`] with the peer-issued TCT.
///
/// Identity is presented as pinned-key by default — the caller's
/// signing key is bound. Callers wanting OIDC should drive the lower-
/// level [`Initiator`] state machine directly.
pub async fn run_initiator_handshake(
    config: InitiatorConfig<'_>,
) -> Result<SessionContext, FacadeError> {
    let manifest_fetcher = ManifestFetcher::new();
    let peer_manifest = manifest_fetcher.fetch(&config.peer_origin).await?;
    // RFC-AITP-0003 §3.2 / §5 step 5: refuse to drive the handshake
    // if the peer doesn't accept the type we'd present. The high-
    // level facade always presents pinned-key (see `Initiator::start`
    // call below). Skipping the round trip here produces a cleaner
    // error than letting the responder reject the HELLO.
    aitp_manifest::check_identity_type_compatibility(&peer_manifest, "pinned_key")?;
    let no_op_resolver = NoOpJwksResolver;
    let empty_anchors: &[aitp_core::RawUrl] = &[];
    let (trust_anchors, jwks_resolver, pinned_key_store): (
        &[aitp_core::RawUrl],
        &dyn JwksResolver,
        Option<&dyn PinnedKeyStore>,
    ) = match &config.trust_mode {
        TrustMode::PinnedKeys(store) => (empty_anchors, &no_op_resolver, Some(*store)),
        TrustMode::Oidc {
            trust_anchors,
            jwks_resolver,
        } => (*trust_anchors, *jwks_resolver, None),
        TrustMode::UnsafeNoTrustEnforcement => (empty_anchors, &no_op_resolver, None),
    };
    let cfg = PeerConfig {
        signing_key: config.signing_key,
        manifest: config.own_manifest,
        trust_anchors,
        jwks_resolver,
        pinned_key_store,
        grant_policy: None,
        revocation_check: None,
        now: Timestamp::now(),
    };

    let mid = Uuid::new_v4();
    let ts = Timestamp::now();
    let (mut initiator, hello) = Initiator::start(
        &cfg,
        PresentedIdentity::PinnedKey {
            subject: config
                .own_manifest
                .display_name
                .clone()
                .unwrap_or_else(|| "initiator".into()),
        },
        &peer_manifest.aid,
        &mid,
        ts,
        config.requested_grants.clone(),
    )?;
    let hello_envelope = sign_envelope_with(
        config.signing_key,
        MessageType::MutualHello,
        serde_json::to_value(&hello).unwrap(),
        mid,
        ts,
    )
    .map_err(FacadeError::Http)?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| FacadeError::Http(e.to_string()))?;

    let endpoint_url = peer_manifest
        .handshake_endpoint
        .parse_url()
        .map_err(|e| FacadeError::Http(format!("handshake_endpoint not a URL: {e}")))?;
    let hello_url = endpoint_url.join("hello").unwrap();
    let resp = client
        .post(hello_url)
        .json(&hello_envelope)
        .send()
        .await
        .map_err(|e| FacadeError::Http(e.to_string()))?;
    let session_header = resp
        .headers()
        .get("x-aitp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .unwrap_or_default();
    let hello_ack_envelope: AitpEnvelope = resp
        .json()
        .await
        .map_err(|e| FacadeError::Http(e.to_string()))?;
    let peer_pk = AitpVerifyingKey::from_aid(&hello_ack_envelope.sender.agent_id)
        .map_err(|e| FacadeError::Http(e.to_string()))?;
    verify_envelope_signature(&hello_ack_envelope, &peer_pk)
        .map_err(|e| FacadeError::Http(e.to_string()))?;
    let hello_ack: MutualHelloAckPayload =
        serde_json::from_value(hello_ack_envelope.payload.clone())?;
    let commit = initiator.on_hello_ack(&hello_ack_envelope, &hello_ack, &cfg)?;

    let commit_envelope = sign_envelope_with(
        config.signing_key,
        MessageType::MutualCommit,
        serde_json::to_value(&commit).unwrap(),
        Uuid::new_v4(),
        Timestamp::now(),
    )
    .map_err(FacadeError::Http)?;

    let commit_url = endpoint_url.join("commit").unwrap();
    let commit_ack_envelope: AitpEnvelope = client
        .post(commit_url)
        .header("x-aitp-session-id", session_header)
        .json(&commit_envelope)
        .send()
        .await
        .map_err(|e| FacadeError::Http(e.to_string()))?
        .json()
        .await
        .map_err(|e| FacadeError::Http(e.to_string()))?;
    verify_envelope_signature(&commit_ack_envelope, &peer_pk)
        .map_err(|e| FacadeError::Http(e.to_string()))?;
    let commit_ack: MutualCommitAckPayload =
        serde_json::from_value(commit_ack_envelope.payload.clone())?;
    let held_tct = initiator.on_commit_ack(&commit_ack_envelope, &commit_ack, &cfg)?;

    Ok(SessionContext {
        peer_aid: peer_manifest.aid.clone(),
        peer_pubkey: peer_pk,
        held_tct,
    })
}

/// Configuration for [`run_initiator_handshake`].
///
/// Trust posture is supplied via [`TrustMode`] — the facade refuses to
/// silently default to "no trust enforcement". See [`TrustMode`] for the
/// three available modes.
pub struct InitiatorConfig<'a> {
    /// Our long-term signing key.
    pub signing_key: &'a AitpSigningKey,
    /// Our published Manifest.
    pub own_manifest: &'a Manifest,
    /// Peer's origin URL — `peer_origin/.well-known/aitp-manifest` will
    /// be fetched.
    pub peer_origin: url::Url,
    /// Trust posture for the peer (RFC-AITP-0002 §3.2 step 1 +
    /// RFC-AITP-0007). Choose [`TrustMode::PinnedKeys`] for production
    /// pinned-key, [`TrustMode::Oidc`] for OIDC, or
    /// [`TrustMode::UnsafeNoTrustEnforcement`] only for tests.
    pub trust_mode: TrustMode<'a>,
    /// Capabilities to request from the peer.
    pub requested_grants: Vec<String>,
}

/// Send a TCT renewal request to a peer's `/aitp/handshake/renew`.
/// Gated behind the `experimental-renewal` Cargo feature.
///
/// Returns the freshly-issued [`TctEnvelope`].
#[cfg(feature = "experimental-renewal")]
pub async fn renew_tct(
    holder_key: &AitpSigningKey,
    current: TctEnvelope,
    peer_handshake_endpoint: &url::Url,
) -> Result<TctEnvelope, FacadeError> {
    let pop_nonce = aitp_core::base64url::encode(&rand_bytes_16());
    let request: TctRenewalPayload = build_renewal_request(holder_key, current, pop_nonce)?;

    let url = peer_handshake_endpoint.join("renew").unwrap();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| FacadeError::Http(e.to_string()))?;
    let envelope: TctEnvelope = client
        .post(url)
        .json(&request)
        .send()
        .await
        .map_err(|e| FacadeError::Http(e.to_string()))?
        .json()
        .await
        .map_err(|e| FacadeError::Http(e.to_string()))?;
    Ok(envelope)
}

#[cfg(feature = "experimental-renewal")]
fn rand_bytes_16() -> [u8; 16] {
    use rand::RngCore;
    let mut buf = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf
}

// ── TctStore ────────────────────────────────────────────────────────────

/// In-memory store for held TCTs, keyed by peer (issuer) AID.
///
/// `TctStore` provides the auto-refresh discipline P15.3 calls for: a
/// background-friendly `needs_refresh` predicate fires when remaining
/// TTL drops below a configurable fraction of the original TTL
/// (default 20 %). Callers can then drive `renew_tct` and stash the
/// fresh TCT back via `insert`.
///
/// The store is cheap to clone (`Arc<RwLock<...>>` inside) and safe to
/// share across tasks.
#[derive(Clone)]
pub struct TctStore {
    inner: std::sync::Arc<std::sync::RwLock<std::collections::HashMap<aitp_core::Aid, Stored>>>,
    refresh_threshold: f64,
}

#[derive(Clone)]
struct Stored {
    envelope: TctEnvelope,
    /// Original TTL at issuance — `expires_at - issued_at`.
    /// Used to compute the refresh threshold relative to *this*
    /// TCT's lifespan rather than a fixed wall-clock window.
    original_ttl_secs: i64,
}

impl Default for TctStore {
    fn default() -> Self {
        Self::new(0.20)
    }
}

impl TctStore {
    /// Build a store with a custom refresh threshold (fraction of
    /// the original TTL remaining at which `needs_refresh` flips).
    /// Default is 0.20 (20 %).
    pub fn new(refresh_threshold: f64) -> Self {
        Self {
            inner: std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            refresh_threshold,
        }
    }

    /// Insert a freshly-received TCT, indexed by its issuer AID.
    pub fn insert(&self, envelope: TctEnvelope) {
        let issuer = envelope.tct.issuer.clone();
        let original_ttl_secs = envelope.tct.expires_at.0 - envelope.tct.issued_at.0;
        if let Ok(mut map) = self.inner.write() {
            map.insert(
                issuer,
                Stored {
                    envelope,
                    original_ttl_secs,
                },
            );
        }
    }

    /// Fetch a stored TCT for `peer_aid`, if any.
    pub fn get(&self, peer_aid: &aitp_core::Aid) -> Option<TctEnvelope> {
        self.inner
            .read()
            .ok()?
            .get(peer_aid)
            .map(|s| s.envelope.clone())
    }

    /// Remove a stored TCT (e.g. after revocation).
    pub fn remove(&self, peer_aid: &aitp_core::Aid) {
        if let Ok(mut map) = self.inner.write() {
            map.remove(peer_aid);
        }
    }

    /// Whether the held TCT for `peer_aid` is approaching expiry and
    /// SHOULD be refreshed by the caller. Returns `false` when no TCT
    /// is stored.
    pub fn needs_refresh(&self, peer_aid: &aitp_core::Aid, now: Timestamp) -> bool {
        let Ok(map) = self.inner.read() else {
            return false;
        };
        let Some(entry) = map.get(peer_aid) else {
            return false;
        };
        if entry.original_ttl_secs <= 0 {
            return true;
        }
        let remaining = entry.envelope.tct.expires_at.0 - now.0;
        if remaining <= 0 {
            return true;
        }
        let frac = remaining as f64 / entry.original_ttl_secs as f64;
        frac < self.refresh_threshold
    }

    /// Snapshot of every stored peer AID (e.g. for a periodic refresh
    /// scan).
    pub fn peer_aids(&self) -> Vec<aitp_core::Aid> {
        self.inner
            .read()
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tct_store_tests {
    use super::*;
    use aitp_crypto::AitpSigningKey;
    use aitp_tct::TctBuilder;

    fn build_tct(issued_at: Timestamp, ttl_secs: i64) -> TctEnvelope {
        let issuer = AitpSigningKey::from_seed(&[1u8; 32]);
        let holder = AitpSigningKey::from_seed(&[2u8; 32]);
        let tct = TctBuilder::new(&issuer)
            .subject(holder.aid().clone())
            .audience(holder.aid().clone())
            .grants(["demo.echo"])
            .ttl_secs(ttl_secs)
            .subject_pubkey(holder.verifying_key())
            .issued_at(issued_at)
            .build()
            .unwrap();
        TctEnvelope { tct }
    }

    #[test]
    fn fresh_tct_does_not_need_refresh() {
        let store = TctStore::default();
        let now = Timestamp(1_700_000_000);
        let env = build_tct(now, 3600);
        let issuer = env.tct.issuer.clone();
        store.insert(env);
        assert!(!store.needs_refresh(&issuer, now));
    }

    #[test]
    fn near_expiry_needs_refresh() {
        let store = TctStore::default();
        let now = Timestamp(1_700_000_000);
        let env = build_tct(now, 3600);
        let issuer = env.tct.issuer.clone();
        store.insert(env);
        // 90% of TTL elapsed → only 10% remaining < 20% threshold.
        let later = Timestamp(now.0 + 3240);
        assert!(store.needs_refresh(&issuer, later));
    }

    #[test]
    fn expired_needs_refresh() {
        let store = TctStore::default();
        let now = Timestamp(1_700_000_000);
        let env = build_tct(now, 3600);
        let issuer = env.tct.issuer.clone();
        store.insert(env);
        let past_expiry = Timestamp(now.0 + 7200);
        assert!(store.needs_refresh(&issuer, past_expiry));
    }

    #[test]
    fn unknown_peer_does_not_need_refresh() {
        let store = TctStore::default();
        let key = AitpSigningKey::from_seed(&[9u8; 32]);
        assert!(!store.needs_refresh(key.aid(), Timestamp(1_700_000_000)));
    }

    #[test]
    fn remove_deletes_entry() {
        let store = TctStore::default();
        let env = build_tct(Timestamp(1_700_000_000), 3600);
        let issuer = env.tct.issuer.clone();
        store.insert(env);
        assert!(store.get(&issuer).is_some());
        store.remove(&issuer);
        assert!(store.get(&issuer).is_none());
    }
}
