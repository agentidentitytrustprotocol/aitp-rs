//! High-level helpers (alpha.5 P15) — one-call drivers for the Mutual
//! Handshake.
//!
//! These wrap [`crate::handshake`] + [`crate::transport`] so callers
//! that don't need the per-step state machine can drive a full
//! handshake from a Manifest URL in a single call.

use crate::core::{
    check_members, from_serde_error, parse_envelope_wire, AitpEnvelope, CheckedJson,
    EnvelopeParseError, MessageType, Timestamp,
};
use crate::crypto::{AitpSigner, AitpVerifyingKey};
use crate::envelope::{sign_envelope_with, verify_envelope_signature};
use crate::handshake::{
    HandshakeError, Initiator, JwksResolver, MutualCommitAckPayload, MutualHelloAckPayload,
    NoPinnedKeys, OidcMintJwtFn, PeerConfig, PinnedKeyStore, PresentedIdentity,
    MUTUAL_COMMIT_ACK_PAYLOAD_MEMBERS, MUTUAL_HELLO_ACK_PAYLOAD_MEMBERS,
};
use crate::manifest::Manifest;
use crate::tct::VerifiedTct;
use crate::transport::{
    FetchError, HostGuard, ManifestFetcher, RevocationFetcher, RevocationPolicy,
};
use std::time::Duration;
use uuid::Uuid;

/// Explicit trust posture for the high-level [`run_initiator_handshake`].
///
/// RFC-AITP-0002 §3.2 step 3 requires every pinned-key peer to be in a
/// local trust store. This enum makes the caller choose explicitly:
///
/// - [`TrustMode::PinnedKeys`]: pinned-key peers MUST appear in the
///   supplied [`PinnedKeyStore`], keyed by `(algorithm, key)`.
/// - [`TrustMode::Oidc`]: peers are authenticated by an issuer in
///   `trust_anchors` whose JWKS is resolved by `jwks_resolver`. A
///   pinned-key peer is rejected.
///
/// 0.14.0 removed the possession-only `UnsafeNoTrustEnforcement`
/// variant (proposal agentidentitytrustprotocol#72, resolved
/// 2026-10-16). Tests use [`TrustMode::PinnedKeys`] with a
/// [`crate::handshake::StaticPinnedKeyStore`].
#[non_exhaustive]
pub enum TrustMode<'a> {
    /// Require all pinned-key peers to appear in this store.
    PinnedKeys(&'a dyn PinnedKeyStore),
    /// Accept peers authenticated by any issuer in `trust_anchors`,
    /// with JWKS resolved by `jwks_resolver`.
    Oidc {
        /// Trust anchors (issuer URLs) the verifying peer accepts.
        trust_anchors: &'a [crate::core::RawUrl],
        /// Resolver for issuer JWKS (typically a
        /// [`crate::transport::key_resolution::KeyResolutionPolicy`]).
        jwks_resolver: &'a dyn JwksResolver,
    },
}

/// Identity this initiator *presents* to the peer during the handshake.
///
/// Orthogonal to [`TrustMode`]: `TrustMode` configures how the
/// initiator *verifies* the peer, while `IdentityMode` configures what
/// the initiator *presents*. A deployment may verify peers via OIDC
/// while presenting a pinned key, or any other combination.
///
/// Pre-v0.1.0-rc.2 the facade always presented a pinned-key identity
/// regardless of configuration, so an OIDC-only peer
/// (`accepted_identity_types: ["oidc"]`) rejected the HELLO. The facade
/// now presents the configured type and pre-checks it against the peer
/// Manifest's `accepted_identity_types` before the handshake starts.
#[non_exhaustive]
pub enum IdentityMode {
    /// Present a pinned-key identity: the facade self-signs a
    /// proof-of-possession over the outbound HELLO envelope.
    PinnedKey {
        /// Subject identifier — MUST equal the initiator Manifest's
        /// `identity_hint.subject` (the responder's `bootstrap_verify_peer`
        /// rejects a mismatch).
        subject: String,
    },
    /// Present an OIDC identity, minting the JWT **after** the handshake
    /// `pop_nonce` is generated. The facade generates the nonce, invokes
    /// `mint(pop_nonce)`, and binds the returned JWT into the HELLO
    /// proof.
    ///
    /// The callback
    /// MUST return a compact JWT whose `nonce` claim equals the supplied
    /// `pop_nonce`; the receiving peer's `verify_oidc` enforces this. A
    /// callback error is surfaced as a handshake failure before any HTTP
    /// is sent.
    Oidc {
        /// OIDC issuer URI — MUST match the initiator Manifest's
        /// `identity_hint.issuer`.
        issuer: url::Url,
        /// Subject identifier at the issuer.
        subject: String,
        /// Callback receiving the handshake-generated `pop_nonce` and
        /// returning a freshly-minted compact JWT (or an error string).
        /// Lowered directly to [`PresentedIdentity::OidcMinter`].
        mint: Box<OidcMintJwtFn>,
    },
}

impl IdentityMode {
    /// Wire identity-type string (`"pinned_key"` / `"oidc"`) used for
    /// the `accepted_identity_types` compatibility check
    /// (RFC-AITP-0003 §3.2).
    fn presented_type(&self) -> &'static str {
        match self {
            IdentityMode::PinnedKey { .. } => "pinned_key",
            IdentityMode::Oidc { .. } => "oidc",
        }
    }

    /// Lower into the handshake-layer [`PresentedIdentity`], consuming
    /// `self` so the [`IdentityMode::Oidc`] closure can be
    /// moved into [`PresentedIdentity::OidcMinter`] rather than cloned.
    fn into_presented_identity(self) -> PresentedIdentity {
        match self {
            IdentityMode::PinnedKey { subject } => PresentedIdentity::PinnedKey { subject },
            IdentityMode::Oidc {
                issuer,
                subject,
                mint,
            } => PresentedIdentity::OidcMinter {
                issuer,
                subject,
                mint_jwt: mint,
            },
        }
    }
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
            "no JWKS resolver configured (TrustMode::PinnedKeys)".into(),
        ))
    }
}

/// Output of [`run_initiator_handshake`] — the peer's AID, the
/// peer-issued TCT we now hold (verbatim token + trusted claims), the
/// companion grant voucher (when the peer's policy allows delegation),
/// and the peer's verifying key (so the caller can use the held TCT for
/// downstream PoP without re-fetching the peer Manifest).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SessionContext {
    /// Peer's AID — `held_tct.claims.iss == peer_aid`.
    pub peer_aid: crate::core::Aid,
    /// Peer's verifying key (for downstream PoP verification).
    pub peer_pubkey: AitpVerifyingKey,
    /// TCT the peer issued to us: forward `held_tct.token`, read
    /// `held_tct.claims`.
    pub held_tct: VerifiedTct,
    /// Companion grant voucher compact JWS — present when the peer's
    /// policy allows us to delegate (RFC-AITP-0005 §8).
    pub grant_voucher: Option<String>,
}

/// Errors from the high-level helpers.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FacadeError {
    /// Manifest fetch failure.
    #[error("manifest fetch failed: {0}")]
    Manifest(#[from] FetchError),
    /// Handshake-level error.
    #[error("handshake failed: {0}")]
    Handshake(#[from] crate::handshake::HandshakeError),
    /// HTTP transport error — connection failure, non-AITP error
    /// status, wrong Content-Type, oversized body, or malformed JSON.
    #[error("HTTP error: {0}")]
    Http(String),
    /// The peer returned an AITP error envelope (`{"error": {...}}`) —
    /// a protocol-level rejection (e.g. `IDENTITY_FAILED`,
    /// `POLICY_VIOLATION`) rather than a transport failure. Callers can
    /// branch on `code` to distinguish "the peer rejected us" from
    /// "the network/HTTP layer failed".
    #[error("peer returned AITP error {code}: {message}")]
    Protocol {
        /// Registered AITP error code from the peer's `error.code`.
        code: String,
        /// Human-readable detail from the peer's `error.message`.
        message: String,
    },
    /// JSON serialization error.
    #[error("serialization: {0}")]
    Serde(#[from] serde_json::Error),
    /// Manifest-level rejection (e.g.
    /// [`crate::manifest::ManifestError::IncompatibleIdentityType`] when
    /// the peer Manifest's `accepted_identity_types` doesn't include
    /// the type we'd present — RFC-AITP-0003 §3.2 / §5 step 5).
    #[error("manifest verification: {0}")]
    ManifestVerify(#[from] crate::manifest::ManifestError),
}

/// Maximum size of a handshake response body the facade
/// will accept. AITP handshake payloads and TCTs are small; 256 KB
/// matches the server's `DEFAULT_MAX_BODY_BYTES` ceiling.
const MAX_RESPONSE_BYTES: usize = 256 * 1024;

/// Shape of an AITP error envelope — `{"error": {"code", "message"}}`
/// (RFC-AITP-0001 §6). Used to recognize a peer's protocol-level
/// rejection inside a non-2xx response body.
#[derive(serde::Deserialize)]
struct AitpErrorEnvelope {
    error: AitpErrorBody,
}

#[derive(serde::Deserialize)]
struct AitpErrorBody {
    code: String,
    message: String,
}

/// Shared status / Content-Type / size validation for an AITP JSON
/// response, common to the test-only `interpret_aitp_response` and
/// [`interpret_aitp_envelope_response`]. Returns once the body is known
/// to be a 2xx JSON response worth attempting to deserialize.
///
/// - oversized body → [`FacadeError::Http`]
/// - non-2xx carrying an AITP `error` envelope → [`FacadeError::Protocol`]
/// - other non-2xx → [`FacadeError::Http`] with status + body excerpt
/// - 2xx with a non-JSON Content-Type → [`FacadeError::Http`]
fn validate_aitp_response_shape(
    status: reqwest::StatusCode,
    content_type: &str,
    body: &[u8],
    max_bytes: usize,
) -> Result<(), FacadeError> {
    if body.len() > max_bytes {
        return Err(FacadeError::Http(format!(
            "response body {} bytes exceeds {max_bytes}-byte limit",
            body.len()
        )));
    }
    if !status.is_success() {
        // A conformant AITP peer rejecting the request returns a
        // registered error envelope; surface its code distinctly so
        // callers can tell a protocol rejection from a transport fault.
        if let Ok(env) = serde_json::from_slice::<AitpErrorEnvelope>(body) {
            return Err(FacadeError::Protocol {
                code: env.error.code,
                message: env.error.message,
            });
        }
        let excerpt: String = String::from_utf8_lossy(body).chars().take(256).collect();
        return Err(FacadeError::Http(format!(
            "HTTP {} from peer: {excerpt}",
            status.as_u16()
        )));
    }
    if !content_type
        .to_ascii_lowercase()
        .contains("application/json")
    {
        return Err(FacadeError::Http(format!(
            "unexpected Content-Type `{content_type}` on a 2xx response (expected application/json)"
        )));
    }
    Ok(())
}

/// Interpret an HTTP response's status, Content-Type and body as a
/// plain AITP JSON body: [`validate_aitp_response_shape`], then
/// `serde_json::from_slice::<T>`. Test-only: it exercises the shared
/// prelude without an HTTP round trip. See
/// [`interpret_aitp_envelope_response`] for the production path.
#[cfg(test)]
fn interpret_aitp_response<T: serde::de::DeserializeOwned>(
    status: reqwest::StatusCode,
    content_type: &str,
    body: &[u8],
    max_bytes: usize,
) -> Result<T, FacadeError> {
    validate_aitp_response_shape(status, content_type, body, max_bytes)?;
    serde_json::from_slice(body)
        .map_err(|e| FacadeError::Http(format!("malformed JSON in response body: {e}")))
}

/// Same contract as [`interpret_aitp_response`], specialized to
/// [`AitpEnvelope`]: the final parse routes through
/// [`parse_envelope_wire`] so a peer response carrying an unknown
/// top-level member is reported as `UNKNOWN_FIELD` rather than an opaque
/// `deny_unknown_fields` serde error. This is a client-side diagnostic
/// improvement only — a response that previously failed to deserialize
/// (an unknown member already caused a bare `from_slice::<AitpEnvelope>`
/// to fail its `deny_unknown_fields` check) still fails here; only the
/// error text/class changes, never accept vs. reject.
fn interpret_aitp_envelope_response(
    status: reqwest::StatusCode,
    content_type: &str,
    body: &[u8],
    max_bytes: usize,
) -> Result<AitpEnvelope, FacadeError> {
    validate_aitp_response_shape(status, content_type, body, max_bytes)?;
    // RFC-AITP-0001 §5.4.5 / issue #140: same rationale as the server
    // side's `receive_envelope` — a duplicate key anywhere in the
    // response body (top level or nested inside `payload`) must be
    // rejected against the ORIGINAL bytes, before a `Value` (which would
    // already have silently collapsed it) is ever built.
    // `CheckedJson::from_slice` runs that check before building the value.
    let value = CheckedJson::from_slice(body)
        .map_err(|e| FacadeError::Http(format!("malformed JSON in response body: {e}")))?;
    parse_envelope_wire(&value).map_err(|e| match e {
        EnvelopeParseError::UnknownVersion(v) => {
            FacadeError::Http(format!("unknown protocol version {v} in response envelope"))
        }
        EnvelopeParseError::UnknownField(field) => {
            FacadeError::Http(format!("unknown field `{field}` in response envelope"))
        }
        EnvelopeParseError::Malformed(msg) => {
            FacadeError::Http(format!("malformed JSON in response body: {msg}"))
        }
    })
}

/// Drain a `reqwest::Response` body under a hard size cap, returning the
/// status, Content-Type header and raw bytes for
/// [`interpret_aitp_envelope_response`] to validate and parse.
///
/// A `Content-Length` declaring more than `max_bytes` is rejected before a
/// single byte is read, and the streaming read aborts the moment the
/// running total exceeds the cap. This stops a malicious handshake peer
/// from exhausting initiator memory with an unbounded (or
/// Content-Length-lying) response.
async fn read_aitp_response_body(
    resp: reqwest::Response,
    max_bytes: usize,
) -> Result<(reqwest::StatusCode, String, Vec<u8>), FacadeError> {
    let status = resp.status();
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    // Fast-path: reject a declared-oversize body before reading it.
    if let Some(declared) = resp.content_length() {
        if declared > max_bytes as u64 {
            return Err(FacadeError::Http(format!(
                "response Content-Length {declared} exceeds {max_bytes}-byte limit"
            )));
        }
    }
    // Stream the body, aborting as soon as the running total exceeds
    // the cap — `Content-Length` may be absent (chunked) or untrue.
    let mut resp = resp;
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| FacadeError::Http(e.to_string()))?
    {
        if body.len() + chunk.len() > max_bytes {
            return Err(FacadeError::Http(format!(
                "response body exceeds {max_bytes}-byte limit"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok((status, content_type, body))
}

/// Read and validate an AITP envelope response: status, Content-Type
/// and size are checked by [`interpret_aitp_envelope_response`] so an
/// unknown top-level member in a peer's handshake response is reported
/// as `UNKNOWN_FIELD` rather than a bare malformed-JSON error.
async fn read_aitp_envelope_response(
    resp: reqwest::Response,
    max_bytes: usize,
) -> Result<AitpEnvelope, FacadeError> {
    let (status, content_type, body) = read_aitp_response_body(resp, max_bytes).await?;
    interpret_aitp_envelope_response(status, &content_type, &body, max_bytes)
}

/// Drive a complete initiator-side Mutual Handshake against a peer
/// reachable over HTTPS.
///
/// 1. Fetches the peer Manifest from `peer_origin/.well-known/aitp-manifest`.
/// 2. Builds a `MutualHelloPayload`, POSTs it.
/// 3. Drives the state machine through HELLO_ACK → COMMIT → COMMIT_ACK.
/// 4. Returns the [`SessionContext`] with the peer-issued TCT.
///
/// Build an HTTP client for POSTing to a peer-manifest-supplied
/// handshake endpoint. The endpoint host is chosen by the peer (a
/// signed Manifest only proves the peer *claims* that endpoint — a
/// malicious peer can legitimately point it at an internal address),
/// so it is SSRF-guarded exactly like the Manifest/JWKS fetch paths:
/// redirects rejected, resolved addresses classified by a default
/// [`HostGuard`] (link-local/metadata always denied; private ranges
/// warn), and for domain hosts the vetted addresses pinned into the
/// client to close the DNS-rebinding window.
///
/// The `guard` and `timeout` come from [`InitiatorConfig`] on the
/// handshake path (default `WarnPrivate` + 10s, so the local two-agent
/// demo over `http://localhost` works once it opts in with
/// [`InitiatorConfig::with_insecure_localhost`]).
async fn build_guarded_client(
    endpoint: &url::Url,
    timeout: Duration,
    guard: &HostGuard,
) -> Result<reqwest::Client, FacadeError> {
    let addrs = guard
        .resolve_checked(endpoint)
        .await
        .map_err(|e| FacadeError::Http(format!("handshake endpoint rejected: {e}")))?;
    let mut builder = reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none());
    if let Some(url::Host::Domain(domain)) = endpoint.host() {
        builder = builder.resolve_to_addrs(domain, &addrs);
    }
    builder
        .build()
        .map_err(|e| FacadeError::Http(e.to_string()))
}

/// The identity presented to the peer is selected by
/// [`InitiatorConfig::identity_mode`]; the type is checked against the
/// peer Manifest's `accepted_identity_types` before the handshake
/// starts. See [`IdentityMode`] for the OIDC nonce constraint.
pub async fn run_initiator_handshake(
    config: InitiatorConfig<'_>,
) -> Result<SessionContext, FacadeError> {
    let manifest_fetcher = ManifestFetcher::new()
        .with_timeout(config.http_timeout)
        .with_host_guard(config.host_guard.clone())
        .with_insecure_localhost(config.allow_insecure_localhost);
    let peer_manifest = manifest_fetcher.fetch(&config.peer_origin).await?;
    // RFC-AITP-0003 §3.2 / §5 step 5: refuse to drive the handshake if
    // the peer doesn't accept the identity type we'd present. Checking
    // here — right after the Manifest fetch, before the HELLO — yields
    // a cleaner error than letting the responder reject the HELLO.
    let presented_type = config.identity_mode.presented_type();
    crate::manifest::check_identity_type_compatibility(&peer_manifest, presented_type)?;
    let no_op_resolver = NoOpJwksResolver;
    let empty_anchors: &[crate::core::RawUrl] = &[];
    let (trust_anchors, jwks_resolver, pinned_key_store): (
        &[crate::core::RawUrl],
        &dyn JwksResolver,
        &dyn PinnedKeyStore,
    ) = match &config.trust_mode {
        TrustMode::PinnedKeys(store) => (empty_anchors, &no_op_resolver, *store),
        TrustMode::Oidc {
            trust_anchors,
            jwks_resolver,
        } => (*trust_anchors, *jwks_resolver, &NoPinnedKeys),
    };
    // Rebuilt before each state-machine step so `now` tracks the wall
    // clock across the (multi-round-trip) handshake. A single snapshot
    // taken at HELLO would, on a slow link or loaded host, lag behind the
    // peer's clock by the time COMMIT_ACK arrives — the peer-issued TCT's
    // `issued_at` then lands strictly after our stale `now` and the
    // verifier rejects an otherwise-valid TCT as `Tct(Expired)`.
    //
    // No TCT arrives before MUTUAL_COMMIT_ACK, so the steps before it
    // never consult the revocation source; COMMIT_ACK gets the real one.
    let no_tct_yet = |_: &crate::core::Aid, _: &Uuid| {
        Err(HandshakeError::Tct(
            crate::tct::TctError::RevocationUnavailable(
                "no revocation lookup before MUTUAL_COMMIT_ACK".into(),
            ),
        ))
    };
    let make_cfg = || {
        PeerConfig::new(
            config.signing_key,
            config.own_manifest,
            jwks_resolver,
            pinned_key_store,
            crate::handshake::RevocationSource::Check(&no_tct_yet),
            Timestamp::now(),
        )
        .with_trust_anchors(trust_anchors)
    };
    let cfg = make_cfg();

    let mid = Uuid::new_v4();
    let ts = Timestamp::now();
    let (mut initiator, hello) = Initiator::start(
        &cfg,
        config.identity_mode.into_presented_identity(),
        &peer_manifest.aid,
        &mid,
        ts,
        config.requested_grants.clone(),
    )?;
    let hello_payload = serde_json::to_value(&hello)
        .map_err(|e| FacadeError::Http(format!("serialize hello: {e}")))?;
    let hello_envelope = sign_envelope_with(
        config.signing_key,
        MessageType::MutualHello,
        hello_payload,
        mid,
        ts,
    )
    .map_err(FacadeError::Http)?;

    let endpoint_url = peer_manifest
        .handshake_endpoint
        .parse_url()
        .map_err(|e| FacadeError::Http(format!("handshake_endpoint not a URL: {e}")))?;
    // SSRF-guard the peer-chosen handshake endpoint before any POST.
    let client =
        build_guarded_client(&endpoint_url, config.http_timeout, &config.host_guard).await?;

    let hello_url = endpoint_url
        .join("hello")
        .map_err(|e| FacadeError::Http(format!("build hello URL: {e}")))?;
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
    let hello_ack_envelope: AitpEnvelope =
        read_aitp_envelope_response(resp, MAX_RESPONSE_BYTES).await?;
    let peer_pk = AitpVerifyingKey::from_aid(&hello_ack_envelope.sender.agent_id)
        .map_err(|e| FacadeError::Http(e.to_string()))?;
    verify_envelope_signature(&hello_ack_envelope, &peer_pk)
        .map_err(|e| FacadeError::Http(e.to_string()))?;
    // RFC-AITP-0001 §7: same member-set discipline the server side
    // applies to an inbound MUTUAL_HELLO_ACK, applied here to the
    // response we received as its peer. Diagnostic only — a payload
    // that fails this check already fails the plain
    // `serde_json::from_value` below via `deny_unknown_fields`; this
    // only improves which `FacadeError` variant reports it.
    if let Err(e) = check_members(
        "MutualHelloAckPayload",
        &hello_ack_envelope.payload,
        MUTUAL_HELLO_ACK_PAYLOAD_MEMBERS,
    ) {
        return Err(FacadeError::Handshake(HandshakeError::UnknownField(
            e.field,
        )));
    }
    let hello_ack: MutualHelloAckPayload =
        serde_json::from_value(hello_ack_envelope.payload.clone()).map_err(|e| {
            if let Some(field) = from_serde_error(&e) {
                FacadeError::Handshake(HandshakeError::UnknownField(field))
            } else {
                FacadeError::Serde(e)
            }
        })?;
    let cfg = make_cfg();
    let commit = initiator.on_hello_ack(&hello_ack_envelope, &hello_ack, &cfg)?;

    let commit_payload = serde_json::to_value(&commit)
        .map_err(|e| FacadeError::Http(format!("serialize commit: {e}")))?;
    let commit_envelope = sign_envelope_with(
        config.signing_key,
        MessageType::MutualCommit,
        commit_payload,
        Uuid::new_v4(),
        Timestamp::now(),
    )
    .map_err(FacadeError::Http)?;

    let commit_url = endpoint_url
        .join("commit")
        .map_err(|e| FacadeError::Http(format!("build commit URL: {e}")))?;
    let commit_resp = client
        .post(commit_url)
        .header("x-aitp-session-id", session_header)
        .json(&commit_envelope)
        .send()
        .await
        .map_err(|e| FacadeError::Http(e.to_string()))?;
    let commit_ack_envelope: AitpEnvelope =
        read_aitp_envelope_response(commit_resp, MAX_RESPONSE_BYTES).await?;
    verify_envelope_signature(&commit_ack_envelope, &peer_pk)
        .map_err(|e| FacadeError::Http(e.to_string()))?;
    // See the MUTUAL_HELLO_ACK member-set check above — same rationale.
    if let Err(e) = check_members(
        "MutualCommitAckPayload",
        &commit_ack_envelope.payload,
        MUTUAL_COMMIT_ACK_PAYLOAD_MEMBERS,
    ) {
        return Err(FacadeError::Handshake(HandshakeError::UnknownField(
            e.field,
        )));
    }
    let commit_ack: MutualCommitAckPayload =
        serde_json::from_value(commit_ack_envelope.payload.clone()).map_err(|e| {
            if let Some(field) = from_serde_error(&e) {
                FacadeError::Handshake(HandshakeError::UnknownField(field))
            } else {
                FacadeError::Serde(e)
            }
        })?;
    // RFC-AITP-0008: fetch the peer's revocation snapshot from the URL
    // its handshake-bound Manifest advertises, then check the peer's TCT
    // against it under `config.revocation_policy` (fail_closed default).
    let fetcher = RevocationFetcher::new(config.revocation_policy.clone())
        .with_host_guard(config.host_guard.clone())
        .with_insecure_localhost(config.allow_insecure_localhost);
    let prepared = fetcher
        .prepare(
            &peer_manifest.aid,
            initiator.peer_revocation_list_uri(),
            Timestamp::now(),
        )
        .await;
    let revocation_check = move |iss: &crate::core::Aid, jti: &Uuid| prepared.decide(iss, jti);
    let cfg = PeerConfig::new(
        config.signing_key,
        config.own_manifest,
        jwks_resolver,
        pinned_key_store,
        crate::handshake::RevocationSource::Check(&revocation_check),
        Timestamp::now(),
    )
    .with_trust_anchors(trust_anchors);
    let completed = initiator.on_commit_ack(&commit_ack_envelope, &commit_ack, &cfg)?;

    Ok(SessionContext {
        peer_aid: peer_manifest.aid.clone(),
        peer_pubkey: peer_pk,
        held_tct: completed.tct,
        grant_voucher: completed.grant_voucher,
    })
}

/// Configuration for [`run_initiator_handshake`].
///
/// Trust posture is supplied via [`TrustMode`] — the facade refuses to
/// silently default to "no trust enforcement". See [`TrustMode`] for the
/// three available modes.
///
/// Construct with [`InitiatorConfig::new`] and adjust the optional knobs
/// with the `with_*` methods; the struct is `#[non_exhaustive]` so future
/// knobs can be added without breaking callers. A struct literal does not
/// compile outside this crate:
///
/// ```compile_fail
/// # use std::time::Duration;
/// # use aitp::facade::{InitiatorConfig, TrustMode, IdentityMode};
/// # use aitp::transport::HostGuard;
/// # fn demo<'a>(
/// #     key: &'a aitp::crypto::AitpSigningKey,
/// #     manifest: &'a aitp::manifest::Manifest,
/// #     trusted: &'a aitp::handshake::StaticPinnedKeyStore,
/// # ) -> InitiatorConfig<'a> {
/// InitiatorConfig {
///     signing_key: key,
///     own_manifest: manifest,
///     peer_origin: "https://peer.example".parse().unwrap(),
///     trust_mode: TrustMode::PinnedKeys(trusted),
///     identity_mode: IdentityMode::PinnedKey { subject: "alice".into() },
///     requested_grants: vec![],
///     http_timeout: Duration::from_secs(10),
///     host_guard: HostGuard::default(),
///     allow_insecure_localhost: false,
///     revocation_policy: Default::default(),
/// }
/// # }
/// ```
#[non_exhaustive]
pub struct InitiatorConfig<'a> {
    /// Our long-term signing key. Accepts any [`AitpSigner`] (in-process
    /// key, KMS, HSM); a backend failure surfaces as
    /// `FacadeError::Handshake(HandshakeError::Crypto(CryptoError::Signer(_)))`,
    /// or `FacadeError::Http("signing backend failed: ...")` when signing
    /// an outbound envelope.
    pub signing_key: &'a dyn AitpSigner,
    /// Our published Manifest.
    pub own_manifest: &'a Manifest,
    /// Peer's origin URL — `peer_origin/.well-known/aitp-manifest` will
    /// be fetched.
    pub peer_origin: url::Url,
    /// Trust posture for the peer (RFC-AITP-0002 §3.2 step 1 +
    /// RFC-AITP-0007). Choose [`TrustMode::PinnedKeys`] for pinned-key
    /// peers or [`TrustMode::Oidc`] for OIDC peers.
    pub trust_mode: TrustMode<'a>,
    /// Identity this initiator presents to the peer
    /// ([`IdentityMode::PinnedKey`], [`IdentityMode::Oidc`], or the
    /// production OIDC path [`IdentityMode::Oidc`]).
    /// Independent of `trust_mode`: presentation and verification are
    /// configured separately.
    pub identity_mode: IdentityMode,
    /// Capabilities to request from the peer.
    pub requested_grants: Vec<String>,
    /// Per-request HTTP timeout for the Manifest fetch and the handshake
    /// POSTs. Default 10s ([`InitiatorConfig::new`]); override with
    /// [`InitiatorConfig::with_http_timeout`].
    pub http_timeout: Duration,
    /// SSRF guard applied to the peer-derived Manifest origin and
    /// handshake endpoint. Default [`HostGuard::default`] (`WarnPrivate`)
    /// so the local demo keeps working; internet-facing callers should
    /// pass [`HostGuard::strict`] via
    /// [`InitiatorConfig::with_host_guard`].
    pub host_guard: HostGuard,
    /// Accept an `http://localhost` / `http://127.0.0.1` peer origin for
    /// the Manifest fetch (local dev only). Default `false`; enable with
    /// [`InitiatorConfig::with_insecure_localhost`]. See
    /// [`ManifestFetcher::with_insecure_localhost`].
    pub allow_insecure_localhost: bool,
    /// How the peer-issued TCT's revocation status is checked
    /// (RFC-AITP-0008). Default `fail_closed`: a peer whose Manifest
    /// advertises no reachable, valid `ListRevoked` snapshot is refused
    /// with `TctError::RevocationUnavailable`. Override with
    /// [`InitiatorConfig::with_revocation_policy`].
    pub revocation_policy: RevocationPolicy,
}

impl<'a> InitiatorConfig<'a> {
    /// Construct a config with default transport knobs (10s HTTP
    /// timeout, [`HostGuard::default`]). Adjust with the `with_*`
    /// methods.
    ///
    /// ```no_run
    /// use std::time::Duration;
    /// use aitp::facade::{InitiatorConfig, TrustMode, IdentityMode};
    /// use aitp::handshake::StaticPinnedKeyStore;
    /// use aitp::transport::HostGuard;
    /// # fn demo(
    /// #     key: &aitp::crypto::AitpSigningKey,
    /// #     manifest: &aitp::manifest::Manifest,
    /// #     peer_aid: &aitp::core::Aid,
    /// # ) {
    /// // Trust exactly the peer's pinned key (Ed25519 or P-256).
    /// let trusted = StaticPinnedKeyStore::from_aids([peer_aid]).unwrap();
    /// let config = InitiatorConfig::new(
    ///     key,
    ///     manifest,
    ///     "https://peer.example".parse().unwrap(),
    ///     TrustMode::PinnedKeys(&trusted),
    ///     IdentityMode::PinnedKey { subject: "alice".into() },
    ///     vec!["demo.echo".into()],
    /// )
    /// // Internet-facing: reject peers that resolve to private space,
    /// // and cap the handshake at 5s.
    /// .with_host_guard(HostGuard::strict())
    /// .with_http_timeout(Duration::from_secs(5));
    /// # let _ = config;
    /// # }
    /// ```
    ///
    /// `signing_key` accepts any [`AitpSigner`] (in-process key, KMS,
    /// HSM); see [`InitiatorConfig::signing_key`] for the error.
    pub fn new(
        signing_key: &'a dyn AitpSigner,
        own_manifest: &'a Manifest,
        peer_origin: url::Url,
        trust_mode: TrustMode<'a>,
        identity_mode: IdentityMode,
        requested_grants: Vec<String>,
    ) -> Self {
        Self {
            signing_key,
            own_manifest,
            peer_origin,
            trust_mode,
            identity_mode,
            requested_grants,
            http_timeout: Duration::from_secs(10),
            host_guard: HostGuard::default(),
            allow_insecure_localhost: false,
            revocation_policy: RevocationPolicy::default(),
        }
    }

    /// Override the per-request HTTP timeout (default 10s).
    pub fn with_http_timeout(mut self, timeout: Duration) -> Self {
        self.http_timeout = timeout;
        self
    }

    /// Override the SSRF [`HostGuard`] applied to peer-derived hosts.
    /// Use [`HostGuard::strict`] for internet-facing deployments.
    pub fn with_host_guard(mut self, guard: HostGuard) -> Self {
        self.host_guard = guard;
        self
    }

    /// Accept an `http://localhost` / `http://127.0.0.1` peer origin
    /// (default `false`). For local demos and tests only; RFC-AITP-0003
    /// §4.1 requires HTTPS for the Manifest endpoint.
    pub fn with_insecure_localhost(mut self, allow: bool) -> Self {
        self.allow_insecure_localhost = allow;
        self
    }

    /// Override the revocation policy (default `fail_closed`). Pass
    /// [`RevocationFailMode::FailOpen`](crate::transport::RevocationFailMode::FailOpen)
    /// to accept a peer whose revocation status cannot be determined.
    pub fn with_revocation_policy(mut self, policy: RevocationPolicy) -> Self {
        self.revocation_policy = policy;
        self
    }
}

// ── TctStore ────────────────────────────────────────────────────────────

/// In-memory store for held TCTs, keyed by peer (issuer) AID.
///
/// `TctStore` provides an auto-refresh discipline: a
/// background-friendly `needs_refresh` predicate fires when remaining
/// TTL drops below a configurable fraction of the original TTL
/// (default 20 %). Callers then obtain a fresh TCT and store it back
/// via `insert`.
///
/// The store is cheap to clone (`Arc<RwLock<...>>` inside) and safe to
/// share across tasks.
#[derive(Clone)]
pub struct TctStore {
    inner: std::sync::Arc<parking_lot::RwLock<std::collections::HashMap<crate::core::Aid, Stored>>>,
    refresh_threshold: f64,
}

#[derive(Clone)]
struct Stored {
    tct: VerifiedTct,
    /// Companion grant voucher, when delivered.
    grant_voucher: Option<String>,
    /// Original TTL at issuance — `exp - iat`. Used to compute the
    /// refresh threshold relative to *this* TCT's lifespan rather than
    /// a fixed wall-clock window.
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
            inner: std::sync::Arc::new(parking_lot::RwLock::new(std::collections::HashMap::new())),
            refresh_threshold,
        }
    }

    /// Insert a freshly-received (verified) TCT and its companion
    /// voucher, indexed by the issuer AID.
    pub fn insert(&self, tct: VerifiedTct, grant_voucher: Option<String>) {
        let issuer = tct.claims.iss.clone();
        let original_ttl_secs = tct.claims.exp.0 - tct.claims.iat.0;
        let mut map = self.inner.write();
        map.insert(
            issuer,
            Stored {
                tct,
                grant_voucher,
                original_ttl_secs,
            },
        );
    }

    /// Fetch a stored TCT for `peer_aid`, if any.
    pub fn get(&self, peer_aid: &crate::core::Aid) -> Option<VerifiedTct> {
        self.inner.read().get(peer_aid).map(|s| s.tct.clone())
    }

    /// Fetch the stored grant voucher for `peer_aid`, if any was
    /// delivered with the TCT.
    pub fn get_voucher(&self, peer_aid: &crate::core::Aid) -> Option<String> {
        self.inner
            .read()
            .get(peer_aid)
            .and_then(|s| s.grant_voucher.clone())
    }

    /// Remove a stored TCT (e.g. after revocation).
    pub fn remove(&self, peer_aid: &crate::core::Aid) {
        self.inner.write().remove(peer_aid);
    }

    /// Whether the held TCT for `peer_aid` is approaching expiry and
    /// SHOULD be refreshed by the caller. Returns `false` when no TCT
    /// is stored.
    pub fn needs_refresh(&self, peer_aid: &crate::core::Aid, now: Timestamp) -> bool {
        let map = self.inner.read();
        let Some(entry) = map.get(peer_aid) else {
            return false;
        };
        if entry.original_ttl_secs <= 0 {
            return true;
        }
        let remaining = entry.tct.claims.exp.0 - now.0;
        if remaining <= 0 {
            return true;
        }
        let frac = remaining as f64 / entry.original_ttl_secs as f64;
        frac < self.refresh_threshold
    }

    /// Snapshot of every stored peer AID (e.g. for a periodic refresh
    /// scan).
    pub fn peer_aids(&self) -> Vec<crate::core::Aid> {
        self.inner.read().keys().cloned().collect()
    }
}

#[cfg(test)]
mod tct_store_tests {
    use super::*;
    use crate::crypto::AitpSigningKey;
    use crate::tct::TctBuilder;

    fn build_tct(issued_at: Timestamp, ttl_secs: i64) -> (VerifiedTct, Option<String>) {
        let issuer = AitpSigningKey::from_seed(&[1u8; 32]);
        let holder = AitpSigningKey::from_seed(&[2u8; 32]);
        let issued = TctBuilder::new(&issuer)
            .subject(holder.aid().clone())
            .audience(holder.aid().clone())
            .grants(["demo.echo"])
            .ttl_secs(ttl_secs)
            .subject_pubkey(holder.verifying_key())
            .issued_at(issued_at)
            .build()
            .unwrap();
        (
            VerifiedTct {
                token: issued.token,
                claims: issued.claims,
            },
            issued.voucher,
        )
    }

    #[test]
    fn fresh_tct_does_not_need_refresh() {
        let store = TctStore::default();
        let now = Timestamp(1_700_000_000);
        let (tct, voucher) = build_tct(now, 3600);
        let issuer = tct.claims.iss.clone();
        store.insert(tct, voucher);
        assert!(!store.needs_refresh(&issuer, now));
        assert!(store.get_voucher(&issuer).is_some());
    }

    #[test]
    fn near_expiry_needs_refresh() {
        let store = TctStore::default();
        let now = Timestamp(1_700_000_000);
        let (tct, voucher) = build_tct(now, 3600);
        let issuer = tct.claims.iss.clone();
        store.insert(tct, voucher);
        // 90% of TTL elapsed → only 10% remaining < 20% threshold.
        let later = Timestamp(now.0 + 3240);
        assert!(store.needs_refresh(&issuer, later));
    }

    #[test]
    fn expired_needs_refresh() {
        let store = TctStore::default();
        let now = Timestamp(1_700_000_000);
        let (tct, voucher) = build_tct(now, 3600);
        let issuer = tct.claims.iss.clone();
        store.insert(tct, voucher);
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
        let (tct, voucher) = build_tct(Timestamp(1_700_000_000), 3600);
        let issuer = tct.claims.iss.clone();
        store.insert(tct, voucher);
        assert!(store.get(&issuer).is_some());
        store.remove(&issuer);
        assert!(store.get(&issuer).is_none());
    }
}

#[cfg(test)]
mod facade_http_tests {
    //! GAP-4: the facade now validates handshake responses
    //! (status, Content-Type, size) and recognizes AITP error
    //! envelopes before deserializing, instead of feeding every body
    //! straight to `.json()`.
    use super::*;
    use reqwest::StatusCode;

    #[test]
    fn http_500_with_non_aitp_body_is_http_error() {
        let err = interpret_aitp_response::<serde_json::Value>(
            StatusCode::INTERNAL_SERVER_ERROR,
            "text/html",
            b"<html><body>500 Internal Server Error</body></html>",
            MAX_RESPONSE_BYTES,
        )
        .unwrap_err();
        match err {
            FacadeError::Http(msg) => assert!(msg.contains("HTTP 500"), "got {msg}"),
            other => panic!("expected Http, got {other:?}"),
        }
    }

    #[test]
    fn non_json_content_type_on_success_is_http_error() {
        let err = interpret_aitp_response::<serde_json::Value>(
            StatusCode::OK,
            "text/html; charset=utf-8",
            b"<html>not json</html>",
            MAX_RESPONSE_BYTES,
        )
        .unwrap_err();
        match err {
            FacadeError::Http(msg) => assert!(msg.contains("Content-Type"), "got {msg}"),
            other => panic!("expected Http, got {other:?}"),
        }
    }

    #[test]
    fn aitp_error_envelope_is_protocol_error() {
        let body = br#"{"error":{"code":"IDENTITY_FAILED","message":"pinned key not trusted"}}"#;
        let err = interpret_aitp_response::<serde_json::Value>(
            StatusCode::BAD_REQUEST,
            "application/json",
            body,
            MAX_RESPONSE_BYTES,
        )
        .unwrap_err();
        match err {
            FacadeError::Protocol { code, message } => {
                assert_eq!(code, "IDENTITY_FAILED");
                assert_eq!(message, "pinned key not trusted");
            }
            other => panic!("expected Protocol, got {other:?}"),
        }
    }

    #[test]
    fn oversized_body_is_http_error() {
        let big = vec![b'x'; 64];
        let err = interpret_aitp_response::<serde_json::Value>(
            StatusCode::OK,
            "application/json",
            &big,
            16, // tiny cap to force the overflow path
        )
        .unwrap_err();
        match err {
            FacadeError::Http(msg) => assert!(msg.contains("exceeds"), "got {msg}"),
            other => panic!("expected Http, got {other:?}"),
        }
    }

    #[test]
    fn valid_json_success_deserializes() {
        let v: serde_json::Value = interpret_aitp_response(
            StatusCode::OK,
            "application/json",
            br#"{"ok":true}"#,
            MAX_RESPONSE_BYTES,
        )
        .unwrap();
        assert_eq!(v, serde_json::json!({"ok": true}));
    }

    /// RFC-AITP-0001 §5.4 check order on a response envelope: an
    /// `aitp/0.2` response (strict cutover) is refused on its version
    /// before its unknown sibling member is looked at.
    #[test]
    fn previous_revision_response_envelope_is_unknown_version() {
        let key = crate::crypto::AitpSigningKey::from_seed(&[7u8; 32]);
        let env = sign_envelope_with(
            &key,
            MessageType::MutualHelloAck,
            serde_json::json!({}),
            uuid::Uuid::new_v4(),
            Timestamp(1_711_900_000),
        )
        .unwrap();
        let mut wire = serde_json::to_value(&env).unwrap();
        let ok = interpret_aitp_envelope_response(
            StatusCode::OK,
            "application/json",
            wire.to_string().as_bytes(),
            MAX_RESPONSE_BYTES,
        );
        assert!(ok.is_ok(), "{ok:?}");
        wire["version"] = "aitp/0.2".into();
        wire["trace_id"] = "rogue".into();
        match interpret_aitp_envelope_response(
            StatusCode::OK,
            "application/json",
            wire.to_string().as_bytes(),
            MAX_RESPONSE_BYTES,
        ) {
            Err(FacadeError::Http(m)) => assert!(m.contains("unknown protocol version"), "{m}"),
            other => panic!("expected unknown version, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod initiator_config_knobs {
    //! R6.1: `InitiatorConfig` transport knobs — HTTP timeout + SSRF
    //! guard — default sensibly and are overridable.
    use super::*;
    use crate::crypto::AitpSigningKey;

    fn key_and_manifest() -> (AitpSigningKey, Manifest) {
        let key = AitpSigningKey::from_seed(&[0x33; 32]);
        let manifest = crate::manifest::ManifestBuilder::new(&key)
            .display_name("t")
            .handshake_endpoint("https://t.example.com/handshake".parse().unwrap())
            .identity_hint(crate::manifest::IdentityHint {
                kind: crate::manifest::IdentityHintKind::PinnedKey,
                subject: "t".into(),
                issuer: None,
                public_key: Some(key.aid().identifier().to_string()),
            })
            .offer("demo.echo")
            .published_at(Timestamp(1_700_000_000))
            .build()
            .unwrap();
        (key, manifest)
    }

    #[test]
    fn defaults_are_10s_and_warn_private() {
        let (key, manifest) = key_and_manifest();
        let cfg = InitiatorConfig::new(
            &key,
            &manifest,
            "https://peer.example.com".parse().unwrap(),
            TrustMode::PinnedKeys(&crate::handshake::NoPinnedKeys),
            IdentityMode::PinnedKey {
                subject: "t".into(),
            },
            vec!["demo.echo".into()],
        );
        assert_eq!(cfg.http_timeout, Duration::from_secs(10));
        assert_eq!(
            cfg.host_guard.mode(),
            crate::transport::GuardMode::WarnPrivate
        );
    }

    #[test]
    fn with_setters_override_defaults() {
        let (key, manifest) = key_and_manifest();
        let cfg = InitiatorConfig::new(
            &key,
            &manifest,
            "https://peer.example.com".parse().unwrap(),
            TrustMode::PinnedKeys(&crate::handshake::NoPinnedKeys),
            IdentityMode::PinnedKey {
                subject: "t".into(),
            },
            vec!["demo.echo".into()],
        )
        .with_http_timeout(Duration::from_secs(3))
        .with_host_guard(HostGuard::strict());
        assert_eq!(cfg.http_timeout, Duration::from_secs(3));
        assert_eq!(
            cfg.host_guard.mode(),
            crate::transport::GuardMode::DenyPrivate
        );
    }
}

#[cfg(test)]
mod identity_mode_tests {
    //! GAP-5: the facade presents the identity type selected by
    //! `InitiatorConfig::identity_mode` instead of always presenting
    //! pinned-key.
    use super::*;

    #[test]
    fn pinned_key_mode_presents_pinned_key_type() {
        let m = IdentityMode::PinnedKey {
            subject: "alice".into(),
        };
        assert_eq!(m.presented_type(), "pinned_key");
        match m.into_presented_identity() {
            PresentedIdentity::PinnedKey { subject } => assert_eq!(subject, "alice"),
            _ => panic!("expected a PinnedKey PresentedIdentity"),
        }
    }

    #[test]
    fn oidc_mint_callback_mode_presents_oidc_and_forwards_nonce() {
        use std::sync::{Arc, Mutex};

        let issuer: url::Url = "https://idp.example.com/".parse().unwrap();
        // Record the nonce the callback observes so we can assert the
        // facade forwards the handshake nonce verbatim.
        let seen = Arc::new(Mutex::new(None::<String>));
        let seen_in_cb = Arc::clone(&seen);
        let m = IdentityMode::Oidc {
            issuer: issuer.clone(),
            subject: "alice@example.com".into(),
            mint: Box::new(move |nonce: &str| {
                *seen_in_cb.lock().unwrap() = Some(nonce.to_string());
                Ok(format!("header.{nonce}.sig"))
            }),
        };
        assert_eq!(m.presented_type(), "oidc");
        match m.into_presented_identity() {
            PresentedIdentity::OidcMinter {
                issuer: got_issuer,
                subject,
                mint_jwt,
            } => {
                assert_eq!(got_issuer, issuer);
                assert_eq!(subject, "alice@example.com");
                // The state machine would call this with the real
                // pop_nonce; emulate that and confirm passthrough.
                let jwt = mint_jwt("nonce-xyz").expect("mint should succeed");
                assert_eq!(jwt, "header.nonce-xyz.sig");
                assert_eq!(seen.lock().unwrap().as_deref(), Some("nonce-xyz"));
            }
            _ => panic!("expected an OidcMinter PresentedIdentity"),
        }
    }
}
