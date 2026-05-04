//! Initiator and Responder state machines (RFC-AITP-0004).
//!
//! These are pure: they receive parsed payloads and parsed envelopes from
//! the caller, do every cryptographic check, and return the next payload
//! to send (or the final TCT). The caller wraps payloads in
//! [`AitpEnvelope`]s, applies replay-protection state, and drives I/O.

use crate::error::HandshakeError;
use crate::identity::{IdentityDescriptor, IdentityKind};
use crate::identity_oidc::{verify_oidc, JwksResolver, OidcVerifyContext};
use crate::identity_pinned::{sign_pinned_key_proof, verify_pinned_key, PinnedKeyVerifyContext};
use crate::payloads::{
    MutualCommitAckPayload, MutualCommitPayload, MutualHelloAckPayload, MutualHelloPayload,
};
use aitp_core::{base64url, Aid, AitpEnvelope, Timestamp};
use aitp_crypto::{AitpSigningKey, AitpVerifyingKey, Signature};
use aitp_manifest::{verify_manifest, Manifest, VerifyManifestContext};
use aitp_tct::{verify_tct, Tct, TctBuilder, TctEnvelope, TctVerifyContext};
use rand::RngCore;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Opaque session identifier — handle for an in-progress handshake.
pub type SessionId = Uuid;

/// Configuration shared by Initiator and Responder.
pub struct PeerConfig<'a> {
    /// Our long-term signing key.
    pub signing_key: &'a AitpSigningKey,
    /// Our published Manifest (must equal `payload.manifest` we send).
    pub manifest: &'a Manifest,
    /// Accepted OIDC issuers (when peers present OIDC identities).
    pub trust_anchors: &'a [url::Url],
    /// JWKS resolver. May be a no-op for pinned-key-only deployments.
    pub jwks_resolver: &'a dyn JwksResolver,
    /// Current time (Unix seconds).
    pub now: Timestamp,
}

/// What identity this peer will present.
pub enum PresentedIdentity {
    /// Self-sign a pinned-key proof over `message_id|timestamp` of the
    /// envelope being sent.
    PinnedKey {
        /// Subject identifier (free-form; bound to the AID's pubkey).
        subject: String,
    },
    /// Use a JWT supplied by the caller (already minted by the IdP).
    Oidc {
        /// OIDC issuer URI.
        issuer: url::Url,
        /// Subject identifier at the issuer.
        subject: String,
        /// Compact-serialized JWT to embed.
        proof_jwt: String,
    },
}

impl PresentedIdentity {
    fn build_descriptor(
        &self,
        envelope_message_id: &Uuid,
        envelope_timestamp: Timestamp,
        signing_key: &AitpSigningKey,
    ) -> IdentityDescriptor {
        match self {
            Self::PinnedKey { subject } => IdentityDescriptor {
                kind: IdentityKind::PinnedKey,
                issuer: None,
                subject: subject.clone(),
                proof: sign_pinned_key_proof(signing_key, envelope_message_id, envelope_timestamp),
                public_key: Some(base64url::encode(&signing_key.verifying_key().to_bytes())),
            },
            Self::Oidc {
                issuer,
                subject,
                proof_jwt,
            } => IdentityDescriptor {
                kind: IdentityKind::Oidc,
                issuer: Some(issuer.clone()),
                subject: subject.clone(),
                proof: proof_jwt.clone(),
                public_key: None,
            },
        }
    }
}

/// Generate a fresh 22-char base64url-unpadded nonce (128 random bits).
fn fresh_nonce() -> Result<String, HandshakeError> {
    let mut buf = [0u8; 16];
    rand::rngs::OsRng
        .try_fill_bytes(&mut buf)
        .map_err(|e| HandshakeError::Rng(e.to_string()))?;
    Ok(base64url::encode(&buf))
}

/// Bootstrap-verify a peer's Manifest + identity proof
/// (RFC-AITP-0004 §5.1 steps 3–6).
///
/// Returns the peer's verifying key on success.
pub fn bootstrap_verify_peer(
    envelope: &AitpEnvelope,
    payload_manifest: &Manifest,
    payload_identity: &IdentityDescriptor,
    payload_pop_nonce: &str,
    cfg: &PeerConfig<'_>,
) -> Result<AitpVerifyingKey, HandshakeError> {
    if payload_manifest.aid != envelope.sender.agent_id {
        return Err(HandshakeError::InvalidEnvelope(
            "manifest.aid does not match sender.agent_id".into(),
        ));
    }
    verify_manifest(payload_manifest, &VerifyManifestContext { now: cfg.now })?;
    if payload_identity.subject != payload_manifest.identity_hint.subject {
        return Err(HandshakeError::Identity(
            "identity.subject != manifest.identity_hint.subject".into(),
        ));
    }
    match payload_identity.kind {
        IdentityKind::Oidc => {
            let issuer = payload_identity
                .issuer
                .as_ref()
                .ok_or_else(|| HandshakeError::Identity("oidc missing issuer".into()))?;
            if Some(issuer) != payload_manifest.identity_hint.issuer.as_ref() {
                return Err(HandshakeError::Identity("issuer hint mismatch".into()));
            }
            let ctx = OidcVerifyContext {
                expected_audience: &cfg.manifest.aid,
                expected_nonce: payload_pop_nonce,
                trust_anchors: cfg.trust_anchors,
                jwks_resolver: cfg.jwks_resolver,
                subject_aid: &payload_manifest.aid,
                iat_tolerance_secs: 300,
                now_unix_secs: cfg.now.0,
            };
            verify_oidc(payload_identity, &ctx)?;
        }
        IdentityKind::PinnedKey => {
            verify_pinned_key(
                payload_identity,
                &PinnedKeyVerifyContext {
                    sender_aid: &payload_manifest.aid,
                    message_id: &envelope.message_id,
                    timestamp: envelope.timestamp,
                },
            )?;
        }
    }
    AitpVerifyingKey::from_aid(&payload_manifest.aid).map_err(Into::into)
}

/// Round-2 PoP: `sign(my_key, sha256(peer_nonce.as_bytes()))`.
fn sign_pop(my_key: &AitpSigningKey, peer_nonce: &str) -> String {
    let digest = Sha256::digest(peer_nonce.as_bytes());
    my_key.sign(&digest).into_string()
}

/// Round-2 PoP verify.
fn verify_pop(
    peer_pubkey: &AitpVerifyingKey,
    my_nonce: &str,
    pop_signature: &str,
) -> Result<(), HandshakeError> {
    let digest = Sha256::digest(my_nonce.as_bytes());
    let sig = Signature::parse(pop_signature).map_err(|_| HandshakeError::PopVerificationFailed)?;
    peer_pubkey
        .verify(&digest, &sig)
        .map_err(|_| HandshakeError::PopVerificationFailed)
}

/// Build a TCT for the peer.
///
/// Grants are the intersection of `peer_requested ∩ self.offered`. Empty
/// intersection ⇒ `PolicyViolation` (RFC-AITP-0004 §4.1).
fn issue_tct_for_peer(
    cfg: &PeerConfig<'_>,
    peer_aid: &Aid,
    peer_pubkey: &AitpVerifyingKey,
    peer_requested: &[String],
) -> Result<Tct, HandshakeError> {
    let grants: Vec<String> = peer_requested
        .iter()
        .filter(|g| cfg.manifest.offered_capabilities.contains(g))
        .cloned()
        .collect();
    if grants.is_empty() {
        return Err(HandshakeError::PolicyViolation);
    }
    TctBuilder::new(cfg.signing_key)
        .subject(peer_aid.clone())
        .audience(peer_aid.clone())
        .grants(grants)
        .ttl_secs(aitp_tct::DEFAULT_TCT_TTL_SECS)
        .subject_pubkey(peer_pubkey.clone())
        .issued_at(cfg.now)
        .build()
        .map_err(HandshakeError::Tct)
}

/// Verify a peer-issued TCT and that it satisfies our
/// `required_peer_capabilities`.
fn verify_received_tct(
    tct: &Tct,
    cfg: &PeerConfig<'_>,
    issuer_pubkey: &AitpVerifyingKey,
) -> Result<(), HandshakeError> {
    let ctx = TctVerifyContext {
        expected_audience: &cfg.manifest.aid,
        issuer_pubkey,
        now: cfg.now,
        revocation_check: None,
    };
    verify_tct(tct, &ctx)?;
    for required in &cfg.manifest.required_peer_capabilities {
        if !tct.grants.contains(required) {
            return Err(HandshakeError::InsufficientGrants);
        }
    }
    Ok(())
}

// ── Initiator ────────────────────────────────────────────────────────────

/// Initiator-side handshake driver.
pub struct Initiator {
    state: InitiatorState,
}

#[allow(dead_code, clippy::large_enum_variant)] // size diff between Done/Failed and Awaiting* is acceptable.
enum InitiatorState {
    AwaitingHelloAck {
        session_id: SessionId,
        my_pop_nonce: String,
    },
    AwaitingCommitAck {
        session_id: SessionId,
        my_pop_nonce: String,
        peer_aid: Aid,
        peer_pubkey: AitpVerifyingKey,
    },
    Done,
    Failed,
}

impl Initiator {
    /// Begin a new handshake. Returns the session and the
    /// `MutualHelloPayload` to wrap in an envelope and POST.
    pub fn start(
        cfg: &PeerConfig<'_>,
        identity: PresentedIdentity,
        envelope_message_id: &Uuid,
        envelope_timestamp: Timestamp,
        requested_grants: Vec<String>,
    ) -> Result<(Self, MutualHelloPayload), HandshakeError> {
        let session_id = Uuid::new_v4();
        let pop_nonce = fresh_nonce()?;
        let descriptor =
            identity.build_descriptor(envelope_message_id, envelope_timestamp, cfg.signing_key);
        let payload = MutualHelloPayload {
            identity: descriptor,
            manifest: cfg.manifest.clone(),
            requested_grants,
            pop_nonce: pop_nonce.clone(),
        };
        Ok((
            Self {
                state: InitiatorState::AwaitingHelloAck {
                    session_id,
                    my_pop_nonce: pop_nonce,
                },
            },
            payload,
        ))
    }

    /// Process MUTUAL_HELLO_ACK; produce MUTUAL_COMMIT.
    pub fn on_hello_ack(
        &mut self,
        envelope: &AitpEnvelope,
        ack: &MutualHelloAckPayload,
        cfg: &PeerConfig<'_>,
    ) -> Result<MutualCommitPayload, HandshakeError> {
        let (session_id, my_pop_nonce) = match &self.state {
            InitiatorState::AwaitingHelloAck {
                session_id,
                my_pop_nonce,
            } => (*session_id, my_pop_nonce.clone()),
            _ => return Err(HandshakeError::State("on_hello_ack out of order")),
        };
        if ack.pop_nonce_echo != my_pop_nonce {
            self.state = InitiatorState::Failed;
            return Err(HandshakeError::NonceMismatch);
        }
        let peer_pubkey = match bootstrap_verify_peer(
            envelope,
            &ack.manifest,
            &ack.identity,
            &ack.pop_nonce,
            cfg,
        ) {
            Ok(p) => p,
            Err(e) => {
                self.state = InitiatorState::Failed;
                return Err(e);
            }
        };
        let tct = issue_tct_for_peer(cfg, &ack.manifest.aid, &peer_pubkey, &ack.requested_grants)?;
        let pop_signature = sign_pop(cfg.signing_key, &ack.pop_nonce);
        let commit = MutualCommitPayload {
            tct_for_peer: TctEnvelope { tct },
            pop_signature,
            pop_nonce_echo: ack.pop_nonce.clone(),
        };
        self.state = InitiatorState::AwaitingCommitAck {
            session_id,
            my_pop_nonce,
            peer_aid: ack.manifest.aid.clone(),
            peer_pubkey,
        };
        Ok(commit)
    }

    /// Process MUTUAL_COMMIT_ACK; return the peer-issued TCT we now hold.
    pub fn on_commit_ack(
        &mut self,
        envelope: &AitpEnvelope,
        ack: &MutualCommitAckPayload,
        cfg: &PeerConfig<'_>,
    ) -> Result<Tct, HandshakeError> {
        let (peer_aid, peer_pubkey, my_pop_nonce) = match &self.state {
            InitiatorState::AwaitingCommitAck {
                peer_aid,
                peer_pubkey,
                my_pop_nonce,
                ..
            } => (peer_aid.clone(), peer_pubkey.clone(), my_pop_nonce.clone()),
            _ => return Err(HandshakeError::State("on_commit_ack out of order")),
        };
        if envelope.sender.agent_id != peer_aid {
            self.state = InitiatorState::Failed;
            return Err(HandshakeError::InvalidEnvelope(
                "commit_ack sender mismatch".into(),
            ));
        }
        if ack.pop_nonce_echo != my_pop_nonce {
            self.state = InitiatorState::Failed;
            return Err(HandshakeError::NonceMismatch);
        }
        verify_pop(&peer_pubkey, &my_pop_nonce, &ack.pop_signature)?;
        verify_received_tct(&ack.tct_for_peer.tct, cfg, &peer_pubkey)?;
        let tct = ack.tct_for_peer.tct.clone();
        self.state = InitiatorState::Done;
        Ok(tct)
    }
}

// ── Responder ────────────────────────────────────────────────────────────

/// Responder-side handshake driver.
pub struct Responder {
    state: ResponderState,
}

#[allow(dead_code, clippy::large_enum_variant)] // size diff between Done/Failed and AwaitingCommit is acceptable.
enum ResponderState {
    AwaitingCommit {
        session_id: SessionId,
        my_pop_nonce: String,
        peer_pop_nonce: String,
        peer_aid: Aid,
        peer_pubkey: AitpVerifyingKey,
        peer_requested_grants: Vec<String>,
    },
    Done,
    Failed,
}

impl Responder {
    /// Process MUTUAL_HELLO; return (responder, MUTUAL_HELLO_ACK payload).
    pub fn on_hello(
        envelope: &AitpEnvelope,
        hello: &MutualHelloPayload,
        my_identity: PresentedIdentity,
        ack_envelope_message_id: &Uuid,
        ack_envelope_timestamp: Timestamp,
        cfg: &PeerConfig<'_>,
        my_requested_grants: Vec<String>,
    ) -> Result<(Self, MutualHelloAckPayload), HandshakeError> {
        let peer_pubkey = bootstrap_verify_peer(
            envelope,
            &hello.manifest,
            &hello.identity,
            &hello.pop_nonce,
            cfg,
        )?;
        let my_pop_nonce = fresh_nonce()?;
        let descriptor = my_identity.build_descriptor(
            ack_envelope_message_id,
            ack_envelope_timestamp,
            cfg.signing_key,
        );
        let ack = MutualHelloAckPayload {
            identity: descriptor,
            manifest: cfg.manifest.clone(),
            requested_grants: my_requested_grants,
            pop_nonce: my_pop_nonce.clone(),
            pop_nonce_echo: hello.pop_nonce.clone(),
        };
        Ok((
            Self {
                state: ResponderState::AwaitingCommit {
                    session_id: Uuid::new_v4(),
                    my_pop_nonce,
                    peer_pop_nonce: hello.pop_nonce.clone(),
                    peer_aid: hello.manifest.aid.clone(),
                    peer_pubkey,
                    peer_requested_grants: hello.requested_grants.clone(),
                },
            },
            ack,
        ))
    }

    /// Process MUTUAL_COMMIT; return (MUTUAL_COMMIT_ACK payload, the
    /// peer-issued TCT we now hold).
    pub fn on_commit(
        &mut self,
        envelope: &AitpEnvelope,
        commit: &MutualCommitPayload,
        cfg: &PeerConfig<'_>,
    ) -> Result<(MutualCommitAckPayload, Tct), HandshakeError> {
        let (peer_aid, peer_pubkey, my_pop_nonce, peer_pop_nonce, peer_requested_grants) =
            match &self.state {
                ResponderState::AwaitingCommit {
                    peer_aid,
                    peer_pubkey,
                    my_pop_nonce,
                    peer_pop_nonce,
                    peer_requested_grants,
                    ..
                } => (
                    peer_aid.clone(),
                    peer_pubkey.clone(),
                    my_pop_nonce.clone(),
                    peer_pop_nonce.clone(),
                    peer_requested_grants.clone(),
                ),
                _ => return Err(HandshakeError::State("on_commit out of order")),
            };
        if envelope.sender.agent_id != peer_aid {
            self.state = ResponderState::Failed;
            return Err(HandshakeError::InvalidEnvelope(
                "commit sender mismatch".into(),
            ));
        }
        if commit.pop_nonce_echo != my_pop_nonce {
            self.state = ResponderState::Failed;
            return Err(HandshakeError::NonceMismatch);
        }
        verify_pop(&peer_pubkey, &my_pop_nonce, &commit.pop_signature)?;
        verify_received_tct(&commit.tct_for_peer.tct, cfg, &peer_pubkey)?;
        let received_tct = commit.tct_for_peer.tct.clone();

        // Issue our TCT for the initiator.
        let our_tct = issue_tct_for_peer(cfg, &peer_aid, &peer_pubkey, &peer_requested_grants)?;
        let ack = MutualCommitAckPayload {
            tct_for_peer: TctEnvelope { tct: our_tct },
            pop_signature: sign_pop(cfg.signing_key, &peer_pop_nonce),
            pop_nonce_echo: peer_pop_nonce,
        };
        self.state = ResponderState::Done;
        Ok((ack, received_tct))
    }
}
