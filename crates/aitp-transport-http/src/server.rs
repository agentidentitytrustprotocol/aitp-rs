//! HTTP server primitives: Manifest server, handshake server.

use crate::common::{sign_envelope, sign_envelope_with, verify_envelope_signature};
use aitp_core::{AitpEnvelope, MessageType};
use aitp_crypto::{AitpSigningKey, AitpVerifyingKey};
use aitp_handshake::{
    JwksResolver, MutualCommitPayload, MutualHelloPayload, PeerConfig, PresentedIdentity, Responder,
};
use aitp_manifest::{Manifest, ManifestEnvelope};
use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Default period after which an in-progress handshake session is
/// garbage-collected if it has not progressed. A healthy four-message
/// handshake on a local network completes in tens of milliseconds; one
/// minute leaves room for slow clients without indefinitely retaining
/// half-finished state.
pub const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(60);

/// Server that exposes `/.well-known/aitp-manifest` returning
/// `{"manifest": <inner>}`.
pub struct ManifestServer {
    manifest: Arc<Manifest>,
}

impl ManifestServer {
    /// Wrap a [`Manifest`] for serving.
    pub fn new(manifest: Manifest) -> Self {
        Self {
            manifest: Arc::new(manifest),
        }
    }

    /// The axum router (mount under whatever prefix you want; usually `/`).
    pub fn router(self) -> Router {
        let manifest = self.manifest;
        Router::new().route(
            "/.well-known/aitp-manifest",
            get(move || {
                let manifest = manifest.clone();
                async move {
                    let env = ManifestEnvelope {
                        manifest: (*manifest).clone(),
                    };
                    Json(env)
                }
            }),
        )
    }
}

/// Server that drives the responder side of the handshake.
///
/// Mounts:
/// - `POST /aitp/handshake/hello` accepts MUTUAL_HELLO, replies with
///   MUTUAL_HELLO_ACK
/// - `POST /aitp/handshake/commit` accepts MUTUAL_COMMIT, replies with
///   MUTUAL_COMMIT_ACK
///
/// Sessions are correlated by the `X-Aitp-Session-Id` HTTP header; clients
/// receive a session id in the same header on the HELLO_ACK response.
pub struct HandshakeServer<R: JwksResolver + Send + Sync + 'static> {
    state: Arc<HandshakeState<R>>,
}

struct HandshakeState<R: JwksResolver + Send + Sync> {
    signing_key: AitpSigningKey,
    manifest: Manifest,
    trust_anchors: Vec<url::Url>,
    jwks_resolver: R,
    /// Capabilities this responder requests from the peer. Per
    /// RFC-AITP-0004 §4.1 the issuing peer's TCT grants are
    /// `peer_requested ∩ self_offered`; if the responder requests
    /// nothing, the initiator's grant intersection is empty and the
    /// handshake aborts with `POLICY_VIOLATION`.
    requested_grants: Vec<String>,
    sessions: Mutex<HashMap<Uuid, SessionEntry>>,
    session_ttl: Duration,
}

struct SessionEntry {
    responder: Responder,
    created_at: Instant,
}

impl<R: JwksResolver + Send + Sync + 'static> HandshakeServer<R> {
    /// Construct a server. The `signing_key` is used both for the
    /// envelope signature on outbound replies and for the responder
    /// state machine. `requested_grants` are the capabilities this
    /// responder asks of the initiator (RFC-AITP-0004 §4.1).
    ///
    /// In-progress handshake sessions expire after [`DEFAULT_SESSION_TTL`].
    /// Use [`Self::with_session_ttl`] to override.
    pub fn new(
        signing_key: AitpSigningKey,
        manifest: Manifest,
        trust_anchors: Vec<url::Url>,
        jwks_resolver: R,
        requested_grants: Vec<String>,
    ) -> Self {
        Self::with_session_ttl(
            signing_key,
            manifest,
            trust_anchors,
            jwks_resolver,
            requested_grants,
            DEFAULT_SESSION_TTL,
        )
    }

    /// Same as [`Self::new`] with an explicit session TTL. Tests use
    /// short TTLs to exercise the expiry path; production callers
    /// should prefer [`Self::new`].
    pub fn with_session_ttl(
        signing_key: AitpSigningKey,
        manifest: Manifest,
        trust_anchors: Vec<url::Url>,
        jwks_resolver: R,
        requested_grants: Vec<String>,
        session_ttl: Duration,
    ) -> Self {
        Self {
            state: Arc::new(HandshakeState {
                signing_key,
                manifest,
                trust_anchors,
                jwks_resolver,
                requested_grants,
                sessions: Mutex::new(HashMap::new()),
                session_ttl,
            }),
        }
    }

    /// The axum router for this handshake server.
    pub fn router(self) -> Router {
        Router::new()
            .route("/aitp/handshake/hello", post(handle_hello::<R>))
            .route("/aitp/handshake/commit", post(handle_commit::<R>))
            .with_state(self.state)
    }
}

const SESSION_HEADER: &str = "x-aitp-session-id";

async fn handle_hello<R: JwksResolver + Send + Sync + 'static>(
    State(state): State<Arc<HandshakeState<R>>>,
    Json(envelope): Json<AitpEnvelope>,
) -> Result<Response, ResponseError> {
    if envelope.message_type != MessageType::MutualHello {
        return Err(ResponseError::bad_request("expected mutual_hello"));
    }
    let payload: MutualHelloPayload = serde_json::from_value(envelope.payload.clone())
        .map_err(|e| ResponseError::bad_request(&format!("malformed payload: {e}")))?;
    // Verify envelope signature using the *peer's* claimed key. Bootstrap
    // verification will check that the AID's public key actually matches
    // what the manifest claims.
    let peer_pk = AitpVerifyingKey::from_aid(&envelope.sender.agent_id)
        .map_err(|_| ResponseError::bad_request("sender AID malformed"))?;
    verify_envelope_signature(&envelope, &peer_pk)
        .map_err(|_| ResponseError::bad_request("envelope signature invalid"))?;

    let cfg = PeerConfig {
        signing_key: &state.signing_key,
        manifest: &state.manifest,
        trust_anchors: &state.trust_anchors,
        jwks_resolver: &state.jwks_resolver,
        now: aitp_core::Timestamp::now(),
    };
    // Server uses pinned-key identity by default (the demo). Production
    // deployments wanting OIDC should construct PresentedIdentity::Oidc
    // outside and use a custom server.
    let pubkey_b64 = aitp_core::base64url::encode(&state.signing_key.verifying_key().to_bytes());
    let _ = pubkey_b64; // captured by PresentedIdentity below
    let ack_mid = Uuid::new_v4();
    let ack_ts = aitp_core::Timestamp::now();
    let (responder, ack_payload) = Responder::on_hello(
        &envelope,
        &payload,
        PresentedIdentity::PinnedKey {
            subject: state
                .manifest
                .display_name
                .clone()
                .unwrap_or_else(|| "responder".into()),
        },
        &ack_mid,
        ack_ts,
        &cfg,
        state.requested_grants.clone(),
    )
    .map_err(|e| ResponseError::bad_request(&format!("handshake failed: {e}")))?;

    let session_id = Uuid::new_v4();
    {
        let mut sessions = state.sessions.lock().unwrap();
        sweep_expired(&mut sessions, state.session_ttl);
        sessions.insert(
            session_id,
            SessionEntry {
                responder,
                created_at: Instant::now(),
            },
        );
    }

    // Use the *same* (ack_mid, ack_ts) that built the identity proof inside
    // `ack_payload`. The pinned-key proof is bound to those values; if we
    // re-generated them here the receiving peer would fail identity
    // verification.
    let ack_envelope = sign_envelope_with(
        &state.signing_key,
        MessageType::MutualHelloAck,
        serde_json::to_value(&ack_payload).unwrap(),
        ack_mid,
        ack_ts,
    )
    .map_err(|e| ResponseError::server_error(&e))?;
    let mut response = Json(ack_envelope).into_response();
    response
        .headers_mut()
        .insert(SESSION_HEADER, session_id.to_string().parse().unwrap());
    Ok(response)
}

async fn handle_commit<R: JwksResolver + Send + Sync + 'static>(
    State(state): State<Arc<HandshakeState<R>>>,
    headers: HeaderMap,
    Json(envelope): Json<AitpEnvelope>,
) -> Result<Response, ResponseError> {
    if envelope.message_type != MessageType::MutualCommit {
        return Err(ResponseError::bad_request("expected mutual_commit"));
    }
    let session_id = headers
        .get(SESSION_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| ResponseError::bad_request("missing or malformed session header"))?;
    let mut entry = {
        let mut sessions = state.sessions.lock().unwrap();
        let expired_present = sessions
            .get(&session_id)
            .is_some_and(|e| Instant::now().duration_since(e.created_at) > state.session_ttl);
        sweep_expired(&mut sessions, state.session_ttl);
        if expired_present {
            return Err(ResponseError::bad_request("session expired"));
        }
        sessions
            .remove(&session_id)
            .ok_or_else(|| ResponseError::bad_request("unknown session"))?
    };
    let payload: MutualCommitPayload = serde_json::from_value(envelope.payload.clone())
        .map_err(|e| ResponseError::bad_request(&format!("malformed payload: {e}")))?;

    let peer_pk = AitpVerifyingKey::from_aid(&envelope.sender.agent_id)
        .map_err(|_| ResponseError::bad_request("sender AID malformed"))?;
    verify_envelope_signature(&envelope, &peer_pk)
        .map_err(|_| ResponseError::bad_request("envelope signature invalid"))?;

    let cfg = PeerConfig {
        signing_key: &state.signing_key,
        manifest: &state.manifest,
        trust_anchors: &state.trust_anchors,
        jwks_resolver: &state.jwks_resolver,
        now: aitp_core::Timestamp::now(),
    };
    let (ack_payload, _our_held_tct) = entry
        .responder
        .on_commit(&envelope, &payload, &cfg)
        .map_err(|e| ResponseError::bad_request(&format!("commit failed: {e}")))?;
    let ack_envelope = sign_envelope(
        &state.signing_key,
        MessageType::MutualCommitAck,
        serde_json::to_value(&ack_payload).unwrap(),
    )
    .map_err(|e| ResponseError::server_error(&e))?;
    Ok(Json(ack_envelope).into_response())
}

#[derive(Debug)]
struct ResponseError {
    status: StatusCode,
    body: String,
}

impl ResponseError {
    fn bad_request(msg: &str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            body: msg.to_string(),
        }
    }
    fn server_error(msg: &str) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            body: msg.to_string(),
        }
    }
}

impl IntoResponse for ResponseError {
    fn into_response(self) -> Response {
        Response::builder()
            .status(self.status)
            .body(Body::from(self.body))
            .unwrap()
    }
}

fn sweep_expired(sessions: &mut HashMap<Uuid, SessionEntry>, ttl: Duration) {
    let now = Instant::now();
    sessions.retain(|_, e| now.duration_since(e.created_at) <= ttl);
}
