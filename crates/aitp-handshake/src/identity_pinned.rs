//! Pinned-key identity verification (RFC-AITP-0002 §3).
//!
//! The pinned-key proof input is exactly:
//!
//! ```text
//! proof_input =
//!     b"aitp-pinned-key-v1\0"
//!     || sender_aid_bytes       || b"\0"
//!     || receiver_aid_bytes     || b"\0"
//!     || message_id_bytes       || b"\0"
//!     || timestamp_ascii_bytes  || b"\0"
//!     || pop_nonce_decoded_bytes
//! proof = sign_jcs(agent_priv, d = sha256(proof_input))   // RFC-AITP-0001 §5.4.6
//! ```
//!
//! Where:
//! - `sender_aid_bytes` = UTF-8 bytes of the full `aid:pubkey:...` string
//! - `receiver_aid_bytes` = UTF-8 bytes of the verifying peer's own AID
//! - `message_id_bytes` = UTF-8 bytes of the UUID in canonical lowercase form
//! - `timestamp_ascii_bytes` = envelope timestamp encoded as its base-10
//!   ASCII-decimal string (e.g. `1711900000` → UTF-8 bytes `"1711900000"`),
//!   matching how `message_id_bytes` is already string-encoded above. Per
//!   the RFC-AITP-0002 §3.1 erratum (spec issue #17), and made
//!   machine-checkable by the `kat-pinned-key-proof-001` KAT vector, this
//!   is NOT an 8-byte big-endian binary integer — an earlier revision of
//!   this module encoded it that way, which was a bug: it never verified
//!   against the reference `aitp-verifier-py` implementation, which has
//!   always used the ASCII-decimal form.
//! - `pop_nonce_decoded_bytes` = raw bytes from base64url-decoding the
//!   `pop_nonce` (NOT the ASCII string)
//! - `\0` = single null byte separator between every field
//!
//! Binding all five fields prevents a captured proof from being replayed
//! against a different sender, receiver, message, timestamp, or
//! handshake nonce.

use crate::error::HandshakeError;
use crate::identity::{IdentityDescriptor, IdentityKind};
use aitp_core::{base64url, Aid, AidAlgorithm, Timestamp};
use aitp_crypto::{AitpVerifyingKey, Signature};
use uuid::Uuid;

/// Domain-separation prefix for the pinned-key proof input. Prevents
/// a signature minted under one AITP version from being replayed
/// against a future version with a different proof-input layout.
pub const PINNED_KEY_PROOF_DOMAIN: &[u8] = b"aitp-pinned-key-v1\0";

/// Decoded length of a `pop_nonce` (RFC-AITP-0002 §3.4, proposal #72
/// Item 5): exactly 16 bytes. Any other length is `IDENTITY_FAILED`,
/// rejected before signature verification.
pub const POP_NONCE_LEN: usize = 16;

/// Build the canonical pinned-key proof input bytes.
///
/// See module-level docs for the exact byte layout. This is the
/// pre-hash input — both signer and verifier MUST produce identical
/// bytes here for the signature check to succeed.
pub fn pinned_key_proof_input(
    sender_aid: &Aid,
    receiver_aid: &Aid,
    message_id: &Uuid,
    timestamp: Timestamp,
    pop_nonce: &str,
) -> Result<Vec<u8>, HandshakeError> {
    let pop_nonce_bytes = base64url::decode_strict(pop_nonce)
        .map_err(|_| HandshakeError::Identity("pop_nonce is not valid base64url".into()))?;
    if pop_nonce_bytes.len() != POP_NONCE_LEN {
        return Err(HandshakeError::Identity(format!(
            "pop_nonce must decode to exactly {POP_NONCE_LEN} bytes, got {}",
            pop_nonce_bytes.len()
        )));
    }
    let ts_ascii = timestamp.0.to_string();
    let mut input = Vec::with_capacity(
        PINNED_KEY_PROOF_DOMAIN.len()
            + sender_aid.as_str().len()
            + 1
            + receiver_aid.as_str().len()
            + 1
            + 36 // UUID canonical form
            + 1
            + ts_ascii.len()
            + 1
            + pop_nonce_bytes.len(),
    );
    input.extend_from_slice(PINNED_KEY_PROOF_DOMAIN);
    input.extend_from_slice(sender_aid.as_str().as_bytes());
    input.push(0);
    input.extend_from_slice(receiver_aid.as_str().as_bytes());
    input.push(0);
    input.extend_from_slice(message_id.to_string().as_bytes());
    input.push(0);
    input.extend_from_slice(ts_ascii.as_bytes());
    input.push(0);
    input.extend_from_slice(&pop_nonce_bytes);
    Ok(input)
}

/// Local trust store for pinned keys (RFC-AITP-0002 §3.2 step 3).
///
/// Entries are keyed by `(algorithm, key bytes)`, never by raw bytes
/// alone: [`AitpVerifyingKey`] carries both, and its `Eq`/`Hash` compare
/// the pair. An Ed25519 key and a P-256 key can therefore never alias,
/// whatever their encodings.
///
/// A store is REQUIRED for every pinned-key verification. There is no
/// possession-only mode (proposal agentidentitytrustprotocol#72,
/// resolved 2026-10-16). Tests use an in-memory
/// [`StaticPinnedKeyStore`]. A deployment that accepts no pinned-key
/// peers at all (OIDC-only) passes [`NoPinnedKeys`].
///
/// `is_trusted` runs on the handshake's hot path and is synchronous.
/// A store backed by a database or a control plane should serve it from
/// a local snapshot that it refreshes out of band.
pub trait PinnedKeyStore: Send + Sync {
    /// Whether `key` (algorithm and bytes) is locally trusted to make
    /// pinned-key claims.
    fn is_trusted(&self, key: &AitpVerifyingKey) -> bool;
}

impl<T: PinnedKeyStore + ?Sized> PinnedKeyStore for &T {
    fn is_trusted(&self, key: &AitpVerifyingKey) -> bool {
        (**self).is_trusted(key)
    }
}

impl<T: PinnedKeyStore + ?Sized> PinnedKeyStore for std::sync::Arc<T> {
    fn is_trusted(&self, key: &AitpVerifyingKey) -> bool {
        (**self).is_trusted(key)
    }
}

impl<T: PinnedKeyStore + ?Sized> PinnedKeyStore for Box<T> {
    fn is_trusted(&self, key: &AitpVerifyingKey) -> bool {
        (**self).is_trusted(key)
    }
}

/// A [`PinnedKeyStore`] that trusts nothing: every pinned-key identity
/// is rejected with `IDENTITY_FAILED`. Use it for OIDC-only deployments.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoPinnedKeys;

impl PinnedKeyStore for NoPinnedKeys {
    fn is_trusted(&self, _key: &AitpVerifyingKey) -> bool {
        false
    }
}

/// In-memory [`PinnedKeyStore`] over a fixed set of Ed25519 and P-256
/// keys.
#[derive(Debug, Clone, Default)]
pub struct StaticPinnedKeyStore {
    trusted: std::collections::HashSet<AitpVerifyingKey>,
}

impl StaticPinnedKeyStore {
    /// A store holding exactly `keys`.
    pub fn new(keys: impl IntoIterator<Item = AitpVerifyingKey>) -> Self {
        Self {
            trusted: keys.into_iter().collect(),
        }
    }

    /// A store holding the keys of `aids`. Fails on the first AID whose
    /// key does not decode (for example an invalid P-256 point).
    pub fn from_aids<'a>(aids: impl IntoIterator<Item = &'a Aid>) -> Result<Self, HandshakeError> {
        let trusted = aids
            .into_iter()
            .map(AitpVerifyingKey::from_aid)
            .collect::<Result<_, _>>()?;
        Ok(Self { trusted })
    }

    /// Add `key`. Returns `false` if it was already present.
    pub fn insert(&mut self, key: AitpVerifyingKey) -> bool {
        self.trusted.insert(key)
    }

    /// Remove `key`. Returns `false` if it was absent.
    pub fn remove(&mut self, key: &AitpVerifyingKey) -> bool {
        self.trusted.remove(key)
    }

    /// Number of trusted keys.
    pub fn len(&self) -> usize {
        self.trusted.len()
    }

    /// Whether the store trusts no key.
    pub fn is_empty(&self) -> bool {
        self.trusted.is_empty()
    }
}

impl FromIterator<AitpVerifyingKey> for StaticPinnedKeyStore {
    fn from_iter<I: IntoIterator<Item = AitpVerifyingKey>>(iter: I) -> Self {
        Self::new(iter)
    }
}

impl PinnedKeyStore for StaticPinnedKeyStore {
    fn is_trusted(&self, key: &AitpVerifyingKey) -> bool {
        self.trusted.contains(key)
    }
}

/// One `pinned_keys` entry of a trust-anchors document
/// (`aitp-trust-anchors.schema.json`).
///
/// `algorithm` is optional. When present it MUST match the key length:
/// 43 base64url characters for Ed25519, 44 for P-256 (proposal
/// agentidentitytrustprotocol#72, resolved 2026-10-16). When absent the
/// length decides. Either way the key is then decoded and, for P-256,
/// checked to be a point on the curve, so a store never holds a key that
/// cannot verify.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct PinnedKeyEntry {
    /// Operator label for the agent. Not authenticated by the proof.
    pub subject: String,
    /// base64url-unpadded public key: 32 raw bytes (Ed25519) or the
    /// 33-byte SEC1-compressed point (P-256).
    pub public_key: String,
    /// `"ed25519"` or `"p256"`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "pinned_algorithm"
    )]
    pub algorithm: Option<AidAlgorithm>,
    /// Capabilities this key may be granted, if the operator restricts
    /// them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_capabilities: Option<Vec<String>>,
}

/// Why a [`PinnedKeyEntry`] does not yield a key.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PinnedKeyEntryError {
    /// `public_key` is neither 43 nor 44 characters.
    #[error("pinned public_key has length {0}; expected 43 (ed25519) or 44 (p256)")]
    Length(usize),
    /// `algorithm` disagrees with the key length.
    #[error("pinned public_key has length {len}, which does not match algorithm `{algorithm}`")]
    AlgorithmMismatch {
        /// The declared algorithm.
        algorithm: &'static str,
        /// The key's length in characters.
        len: usize,
    },
    /// `public_key` is not base64url-unpadded.
    #[error("pinned public_key is not base64url: {0}")]
    Encoding(String),
    /// The bytes are not a valid key (for P-256, not a curve point).
    #[error(transparent)]
    Key(#[from] aitp_crypto::CryptoError),
}

impl PinnedKeyEntry {
    /// An entry for `key`, with `algorithm` set.
    pub fn new(subject: impl Into<String>, key: &AitpVerifyingKey) -> Self {
        Self {
            subject: subject.into(),
            public_key: base64url::encode(&key.to_compressed()),
            algorithm: Some(key.algorithm()),
            allowed_capabilities: None,
        }
    }

    /// The algorithm, declared or inferred from the key length.
    pub fn resolved_algorithm(&self) -> Result<AidAlgorithm, PinnedKeyEntryError> {
        let len = self.public_key.len();
        let by_len = match len {
            43 => AidAlgorithm::Ed25519,
            44 => AidAlgorithm::P256,
            _ => return Err(PinnedKeyEntryError::Length(len)),
        };
        match self.algorithm {
            Some(a) if a != by_len => Err(PinnedKeyEntryError::AlgorithmMismatch {
                algorithm: a.as_str(),
                len,
            }),
            _ => Ok(by_len),
        }
    }

    /// Decode the key.
    pub fn verifying_key(&self) -> Result<AitpVerifyingKey, PinnedKeyEntryError> {
        let algorithm = self.resolved_algorithm()?;
        let bytes = base64url::decode_strict(&self.public_key)
            .map_err(|e| PinnedKeyEntryError::Encoding(e.to_string()))?;
        let key = AitpVerifyingKey::from_compressed(&bytes)?;
        debug_assert_eq!(key.algorithm(), algorithm);
        Ok(key)
    }
}

mod pinned_algorithm {
    use aitp_core::AidAlgorithm;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(a: &Option<AidAlgorithm>, s: S) -> Result<S::Ok, S::Error> {
        match a {
            Some(a) => s.serialize_str(a.as_str()),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<AidAlgorithm>, D::Error> {
        match String::deserialize(d)?.as_str() {
            "ed25519" => Ok(Some(AidAlgorithm::Ed25519)),
            "p256" => Ok(Some(AidAlgorithm::P256)),
            other => Err(serde::de::Error::unknown_variant(
                other,
                &["ed25519", "p256"],
            )),
        }
    }
}

impl StaticPinnedKeyStore {
    /// A store holding the keys of a trust-anchors `pinned_keys` array.
    /// Fails on the first entry that does not decode, so a typo in
    /// operator config is an error at load time, not a silent
    /// `IDENTITY_FAILED` later.
    pub fn from_entries<'a>(
        entries: impl IntoIterator<Item = &'a PinnedKeyEntry>,
    ) -> Result<Self, PinnedKeyEntryError> {
        entries
            .into_iter()
            .map(PinnedKeyEntry::verifying_key)
            .collect::<Result<_, _>>()
            .map(|trusted| Self { trusted })
    }
}

/// Inputs for verifying a pinned-key identity proof.
pub struct PinnedKeyVerifyContext<'a> {
    /// The sender's AID (per `envelope.sender.agent_id`).
    pub sender_aid: &'a Aid,
    /// The verifying peer's own AID — required by RFC-AITP-0002 §3.1
    /// to bind the proof to *this* receiver and defend against
    /// cross-peer replay.
    pub receiver_aid: &'a Aid,
    /// The envelope's `message_id`.
    pub message_id: &'a Uuid,
    /// The envelope's `timestamp`.
    pub timestamp: Timestamp,
    /// The handshake's `pop_nonce` (the base64url string from the
    /// surrounding HELLO/HELLO_ACK payload). MUST decode to exactly 16
    /// bytes.
    pub pop_nonce: &'a str,
    /// What the descriptor's `subject` must be. Default
    /// [`SubjectBinding::Unchecked`].
    pub subject: SubjectBinding,
}

/// How [`verify_pinned_key`] treats the descriptor's `subject`.
///
/// `subject` is not covered by `proof` (proposal
/// agentidentitytrustprotocol#72 Item 6a). RFC-AITP-0002 lets it be a
/// free-form label (`"internal-worker-1"`), so the default leaves it
/// unchecked. Deployments that put the agent's AID in `subject` opt into
/// [`SubjectBinding::SenderAid`] so a mismatched label cannot reach logs
/// or policy as if it named the sender.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum SubjectBinding {
    /// Accept any `subject`. Callers MUST NOT treat it as authenticated.
    #[default]
    Unchecked,
    /// `subject` MUST byte-equal the sender AID string.
    SenderAid,
}

/// The outcome of a successful [`verify_pinned_key`]: the sender's key,
/// established from the sender AID and the trust store, never from
/// descriptor fields alone. Callers bind the peer to this value and do
/// not re-derive it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerifiedPinnedKey {
    /// The key's algorithm.
    pub algorithm: AidAlgorithm,
    /// The trusted key the proof verified under.
    pub key: AitpVerifyingKey,
    /// The sender AID the key was bound to.
    pub aid: Aid,
}

/// Verify a pinned-key identity proof (RFC-AITP-0002 §3.2, as revised by
/// proposal agentidentitytrustprotocol#72 Item 2).
///
/// 1. `descriptor.type` MUST be `pinned_key`. No other type is run
///    through this path, whatever fields it carries. `issuer` MUST be
///    absent. `subject` is checked per `ctx.subject`
///    ([`SubjectBinding`]); by default it is an unauthenticated label.
/// 2. `descriptor.public_key` MUST decode to the AID-identifier form for
///    the sender AID's algorithm: 32 raw bytes for Ed25519, or a 33-byte
///    SEC1 compressed point for P-256 (uncompressed points, SPKI and
///    the identity are rejected), byte-equal to the key in
///    `ctx.sender_aid`.
/// 3. `(algorithm, key)` MUST be in `store`.
/// 4. `proof_input` is rebuilt per [`pinned_key_proof_input`]; the
///    `pop_nonce` MUST decode to exactly 16 bytes.
/// 5. `descriptor.proof` is verified over `d = sha256(proof_input)` per
///    RFC-AITP-0001 §5.4.3/§5.4.6/§5.4.7. Its algorithm tag MUST match
///    the key: an untagged proof is Ed25519, so a P-256 sender MUST tag.
///
/// Steps 1–4 complete before any signature verification. Every failure
/// is [`HandshakeError::Identity`] (`IDENTITY_FAILED`).
pub fn verify_pinned_key(
    descriptor: &IdentityDescriptor,
    ctx: &PinnedKeyVerifyContext<'_>,
    store: &dyn PinnedKeyStore,
) -> Result<VerifiedPinnedKey, HandshakeError> {
    let key = resolve_pinned_key(descriptor, ctx, store)?;
    check_pinned_key_proof(descriptor, ctx, &key)?;
    Ok(key)
}

/// §3.2 steps 1–3: descriptor shape, key equality and the trust-store
/// lookup. No signature work. Split from [`check_pinned_key_proof`] so
/// pinned-key admission can verify the envelope signature in between
/// (RFC-AITP-0002 §3.4 check order, steps 6–8).
pub(crate) fn resolve_pinned_key(
    descriptor: &IdentityDescriptor,
    ctx: &PinnedKeyVerifyContext<'_>,
    store: &dyn PinnedKeyStore,
) -> Result<VerifiedPinnedKey, HandshakeError> {
    // Step 1: type dispatch.
    if descriptor.kind != IdentityKind::PinnedKey {
        return Err(HandshakeError::Identity(
            "pinned-key verification requires identity.type = pinned_key".into(),
        ));
    }

    // Step 1b: descriptor shape. `issuer` has no meaning for a pinned
    // key and nothing authenticates it in a standalone presentation, so
    // a descriptor carrying one is rejected rather than half-trusted.
    if descriptor.issuer.is_some() {
        return Err(HandshakeError::Identity(
            "pinned_key descriptor must not carry issuer".into(),
        ));
    }
    if ctx.subject == SubjectBinding::SenderAid && descriptor.subject != ctx.sender_aid.as_str() {
        return Err(HandshakeError::Identity(
            "pinned_key subject does not equal the sender AID".into(),
        ));
    }

    // Step 2: public_key byte-equals the sender AID key, same algorithm.
    let algorithm = ctx.sender_aid.algorithm();
    let public_key = descriptor
        .public_key
        .as_ref()
        .ok_or_else(|| HandshakeError::Identity("pinned_key missing public_key".into()))?;
    let pk_bytes = base64url::decode_strict(public_key)
        .map_err(|_| HandshakeError::Identity("public_key malformed base64url".into()))?;
    let expected_len = match algorithm {
        AidAlgorithm::Ed25519 => 32,
        AidAlgorithm::P256 => 33,
        other => {
            return Err(HandshakeError::Identity(format!(
                "pinned_key does not support sender algorithm {}",
                other.as_str()
            )))
        }
    };
    if pk_bytes.len() != expected_len {
        return Err(HandshakeError::Identity(format!(
            "public_key must decode to {expected_len} bytes for a {} sender",
            algorithm.as_str()
        )));
    }
    if algorithm == AidAlgorithm::P256 && !matches!(pk_bytes[0], 0x02 | 0x03) {
        return Err(HandshakeError::Identity(
            "public_key must be a SEC1 compressed P-256 point".into(),
        ));
    }
    if pk_bytes != ctx.sender_aid.pubkey_compressed_bytes() {
        return Err(HandshakeError::Identity(
            "public_key does not match sender AID".into(),
        ));
    }
    let key = AitpVerifyingKey::from_compressed(&pk_bytes)
        .map_err(|_| HandshakeError::Identity("public_key is not a valid point".into()))?;

    // Step 3: trust store, keyed by (algorithm, key).
    if !store.is_trusted(&key) {
        return Err(HandshakeError::Identity(
            "pinned_key not in local trust store".into(),
        ));
    }

    Ok(VerifiedPinnedKey {
        algorithm,
        key,
        aid: ctx.sender_aid.clone(),
    })
}

/// §3.2 steps 4–5: the proof over the tuple, under the key
/// [`resolve_pinned_key`] returned.
pub(crate) fn check_pinned_key_proof(
    descriptor: &IdentityDescriptor,
    ctx: &PinnedKeyVerifyContext<'_>,
    key: &VerifiedPinnedKey,
) -> Result<(), HandshakeError> {
    // Step 4: proof input (enforces the 16-byte nonce).
    let input = pinned_key_proof_input(
        ctx.sender_aid,
        ctx.receiver_aid,
        ctx.message_id,
        ctx.timestamp,
        ctx.pop_nonce,
    )?;

    // Step 5: strict verify; `verify_jcs` refuses a tag that does not
    // match the key's algorithm.
    let sig = Signature::parse(&descriptor.proof)
        .map_err(|_| HandshakeError::Identity("proof malformed".into()))?;
    key.key
        .verify_jcs(&aitp_crypto::Digest32::sha256(&input), &sig)
        .map_err(|_| HandshakeError::Identity("pinned_key signature invalid".into()))
}

/// Sign a pinned-key identity proof — helper for the issuing side.
///
/// All five fields MUST match what the verifying peer will reconstruct
/// from the surrounding envelope (sender AID, receiver AID, message_id,
/// timestamp, pop_nonce). A captured signature is bound to that exact
/// tuple and cannot be replayed.
///
/// Accepts any [`aitp_crypto::AitpSigner`] (in-process key, KMS, HSM); a
/// backend failure returns `HandshakeError::Crypto(CryptoError::Signer(_))`.
pub fn sign_pinned_key_proof(
    signing_key: &dyn aitp_crypto::AitpSigner,
    sender_aid: &Aid,
    receiver_aid: &Aid,
    message_id: &Uuid,
    timestamp: Timestamp,
    pop_nonce: &str,
) -> Result<String, HandshakeError> {
    let input = pinned_key_proof_input(sender_aid, receiver_aid, message_id, timestamp, pop_nonce)?;
    let digest = aitp_crypto::Digest32::sha256(&input);
    Ok(aitp_crypto::sign_jcs(signing_key, &digest)
        .map_err(aitp_crypto::CryptoError::Signer)?
        .into_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_key_entry_algorithm_must_match_length() {
        let ed = AitpSigningKey::from_ed25519_seed(&[1; 32]).verifying_key();
        let p = AitpSigningKey::from_p256_seed(&[2; 32])
            .unwrap()
            .verifying_key();
        for k in [&ed, &p] {
            let e = PinnedKeyEntry::new("a", k);
            assert_eq!(&e.verifying_key().unwrap(), k);
            // Absent algorithm: inferred from the length.
            let bare = PinnedKeyEntry {
                algorithm: None,
                ..e.clone()
            };
            assert_eq!(&bare.verifying_key().unwrap(), k);
        }
        // Declared algorithm disagreeing with the length.
        let mut wrong = PinnedKeyEntry::new("a", &ed);
        wrong.algorithm = Some(AidAlgorithm::P256);
        assert!(matches!(
            wrong.verifying_key(),
            Err(PinnedKeyEntryError::AlgorithmMismatch { len: 43, .. })
        ));
        let mut wrong = PinnedKeyEntry::new("a", &p);
        wrong.algorithm = Some(AidAlgorithm::Ed25519);
        assert!(wrong.verifying_key().is_err());
    }

    #[test]
    fn pinned_key_entry_wire_form() {
        let p = AitpSigningKey::from_p256_seed(&[2; 32])
            .unwrap()
            .verifying_key();
        let e = PinnedKeyEntry::new("svc", &p);
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["algorithm"], "p256");
        let back: PinnedKeyEntry = serde_json::from_value(v.clone()).unwrap();
        assert_eq!(back, e);
        let store = StaticPinnedKeyStore::from_entries([&back]).unwrap();
        assert!(store.is_trusted(&p));
        // Unknown algorithm and unknown members are rejected.
        let mut bad = v.clone();
        bad["algorithm"] = "rsa".into();
        assert!(serde_json::from_value::<PinnedKeyEntry>(bad).is_err());
        let mut bad = v;
        bad["note"] = "x".into();
        assert!(serde_json::from_value::<PinnedKeyEntry>(bad).is_err());
        // A 44-char key that is not a point (x >= p) fails at load time.
        let mut not_a_point = [0xff; 33];
        not_a_point[0] = 0x02;
        let off_curve = PinnedKeyEntry {
            subject: "x".into(),
            public_key: base64url::encode(&not_a_point),
            algorithm: None,
            allowed_capabilities: None,
        };
        assert!(StaticPinnedKeyStore::from_entries([&off_curve]).is_err());
    }

    use aitp_crypto::AitpSigningKey;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Trusts exactly the keys of the given signers.
    fn store_of(keys: &[&AitpSigningKey]) -> StaticPinnedKeyStore {
        keys.iter().map(|k| k.verifying_key()).collect()
    }

    fn fixed_nonce() -> &'static str {
        // 16 bytes → 22 char base64url (matches the on-wire format).
        "AAECAwQFBgcICQoLDA0ODw"
    }

    fn descriptor_for(
        signer: &AitpSigningKey,
        sender: &Aid,
        receiver: &Aid,
        mid: &Uuid,
        ts: Timestamp,
        nonce: &str,
    ) -> IdentityDescriptor {
        let proof = sign_pinned_key_proof(signer, sender, receiver, mid, ts, nonce).unwrap();
        IdentityDescriptor {
            kind: IdentityKind::PinnedKey,
            issuer: None,
            subject: "agent-x".into(),
            proof,
            public_key: Some(base64url::encode(&signer.verifying_key().to_compressed())),
            extensions: None,
        }
    }

    #[test]
    fn round_trip_full_context() {
        let key = AitpSigningKey::from_seed(&[3u8; 32]);
        let receiver = AitpSigningKey::from_seed(&[4u8; 32]);
        let mid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let ts = Timestamp(1_700_000_000);
        let nonce = fixed_nonce();
        let desc = descriptor_for(&key, key.aid(), receiver.aid(), &mid, ts, nonce);
        verify_pinned_key(
            &desc,
            &PinnedKeyVerifyContext {
                sender_aid: key.aid(),
                receiver_aid: receiver.aid(),
                message_id: &mid,
                timestamp: ts,
                pop_nonce: nonce,
                subject: Default::default(),
            },
            &store_of(&[&key]),
        )
        .expect("proof verifies under the same five-tuple");
    }

    #[test]
    fn changing_receiver_aid_rejects() {
        let key = AitpSigningKey::from_seed(&[3u8; 32]);
        let receiver = AitpSigningKey::from_seed(&[4u8; 32]);
        let other_receiver = AitpSigningKey::from_seed(&[5u8; 32]);
        let mid = Uuid::nil();
        let ts = Timestamp(1);
        let desc = descriptor_for(&key, key.aid(), receiver.aid(), &mid, ts, fixed_nonce());
        let err = verify_pinned_key(
            &desc,
            &PinnedKeyVerifyContext {
                sender_aid: key.aid(),
                receiver_aid: other_receiver.aid(),
                message_id: &mid,
                timestamp: ts,
                pop_nonce: fixed_nonce(),
                subject: Default::default(),
            },
            &store_of(&[&key]),
        )
        .unwrap_err();
        assert!(matches!(err, HandshakeError::Identity(_)));
    }

    #[test]
    fn changing_sender_aid_rejects() {
        let key = AitpSigningKey::from_seed(&[3u8; 32]);
        let other = AitpSigningKey::from_seed(&[6u8; 32]);
        let receiver = AitpSigningKey::from_seed(&[4u8; 32]);
        let mid = Uuid::nil();
        let ts = Timestamp(1);
        // Sign claiming to be `key`, but the verifier reconstructs with `other` as sender.
        let desc = descriptor_for(&key, key.aid(), receiver.aid(), &mid, ts, fixed_nonce());
        let err = verify_pinned_key(
            &desc,
            &PinnedKeyVerifyContext {
                sender_aid: other.aid(),
                receiver_aid: receiver.aid(),
                message_id: &mid,
                timestamp: ts,
                pop_nonce: fixed_nonce(),
                subject: Default::default(),
            },
            &store_of(&[&key]),
        )
        .unwrap_err();
        assert!(matches!(err, HandshakeError::Identity(_)));
    }

    #[test]
    fn changing_message_id_rejects() {
        let key = AitpSigningKey::from_seed(&[3u8; 32]);
        let receiver = AitpSigningKey::from_seed(&[4u8; 32]);
        let mid_a = Uuid::nil();
        let mid_b = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let ts = Timestamp(1);
        let desc = descriptor_for(&key, key.aid(), receiver.aid(), &mid_a, ts, fixed_nonce());
        let err = verify_pinned_key(
            &desc,
            &PinnedKeyVerifyContext {
                sender_aid: key.aid(),
                receiver_aid: receiver.aid(),
                message_id: &mid_b,
                timestamp: ts,
                pop_nonce: fixed_nonce(),
                subject: Default::default(),
            },
            &store_of(&[&key]),
        )
        .unwrap_err();
        assert!(matches!(err, HandshakeError::Identity(_)));
    }

    #[test]
    fn changing_timestamp_rejects() {
        let key = AitpSigningKey::from_seed(&[3u8; 32]);
        let receiver = AitpSigningKey::from_seed(&[4u8; 32]);
        let mid = Uuid::nil();
        let ts_a = Timestamp(1);
        let ts_b = Timestamp(2);
        let desc = descriptor_for(&key, key.aid(), receiver.aid(), &mid, ts_a, fixed_nonce());
        let err = verify_pinned_key(
            &desc,
            &PinnedKeyVerifyContext {
                sender_aid: key.aid(),
                receiver_aid: receiver.aid(),
                message_id: &mid,
                timestamp: ts_b,
                pop_nonce: fixed_nonce(),
                subject: Default::default(),
            },
            &store_of(&[&key]),
        )
        .unwrap_err();
        assert!(matches!(err, HandshakeError::Identity(_)));
    }

    #[test]
    fn changing_pop_nonce_rejects() {
        let key = AitpSigningKey::from_seed(&[3u8; 32]);
        let receiver = AitpSigningKey::from_seed(&[4u8; 32]);
        let mid = Uuid::nil();
        let ts = Timestamp(1);
        let nonce_a = "AAECAwQFBgcICQoLDA0ODw";
        let nonce_b = "DwAAAAAAAAAAAAAAAAAAAA";
        let desc = descriptor_for(&key, key.aid(), receiver.aid(), &mid, ts, nonce_a);
        let err = verify_pinned_key(
            &desc,
            &PinnedKeyVerifyContext {
                sender_aid: key.aid(),
                receiver_aid: receiver.aid(),
                message_id: &mid,
                timestamp: ts,
                pop_nonce: nonce_b,
                subject: Default::default(),
            },
            &store_of(&[&key]),
        )
        .unwrap_err();
        assert!(matches!(err, HandshakeError::Identity(_)));
    }

    #[test]
    fn malformed_pop_nonce_returns_error_not_panic() {
        let key = AitpSigningKey::from_seed(&[3u8; 32]);
        let receiver = AitpSigningKey::from_seed(&[4u8; 32]);
        let result = sign_pinned_key_proof(
            &key,
            key.aid(),
            receiver.aid(),
            &Uuid::nil(),
            Timestamp(1),
            "not!valid!base64url!",
        );
        assert!(matches!(result, Err(HandshakeError::Identity(_))));
    }

    #[test]
    fn legacy_two_field_proof_fails_under_new_verifier() {
        // Manually mint a signature using the old `message_id|timestamp`
        // layout — the v0.1 verifier MUST reject it.
        let key = AitpSigningKey::from_seed(&[3u8; 32]);
        let receiver = AitpSigningKey::from_seed(&[4u8; 32]);
        let mid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let ts = Timestamp(1_700_000_000);
        let legacy_input = format!("{}|{}", mid, ts.0);
        let legacy_digest = aitp_crypto::Digest32::sha256(legacy_input.as_bytes());
        let legacy_proof = key.sign_jcs(&legacy_digest).into_string();
        let desc = IdentityDescriptor {
            kind: IdentityKind::PinnedKey,
            issuer: None,
            subject: "agent-x".into(),
            proof: legacy_proof,
            public_key: Some(base64url::encode(&key.verifying_key().to_compressed())),
            extensions: None,
        };
        let err = verify_pinned_key(
            &desc,
            &PinnedKeyVerifyContext {
                sender_aid: key.aid(),
                receiver_aid: receiver.aid(),
                message_id: &mid,
                timestamp: ts,
                pop_nonce: fixed_nonce(),
                subject: Default::default(),
            },
            &store_of(&[&key]),
        )
        .unwrap_err();
        assert!(matches!(err, HandshakeError::Identity(_)));
    }

    /// A store that records how often it is consulted and a verifying
    /// key wrapper is impossible to intercept, so ordering is shown by
    /// pairing it with a proof that would fail: a store refusal must win.
    struct CountingStore {
        inner: StaticPinnedKeyStore,
        calls: AtomicUsize,
    }

    impl PinnedKeyStore for CountingStore {
        fn is_trusted(&self, key: &AitpVerifyingKey) -> bool {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.inner.is_trusted(key)
        }
    }

    fn ctx<'a>(sender: &'a Aid, receiver: &'a Aid, mid: &'a Uuid) -> PinnedKeyVerifyContext<'a> {
        PinnedKeyVerifyContext {
            sender_aid: sender,
            receiver_aid: receiver,
            message_id: mid,
            timestamp: Timestamp(1_711_900_000),
            pop_nonce: fixed_nonce(),
            subject: Default::default(),
        }
    }

    fn identity_msg(err: HandshakeError) -> String {
        match err {
            HandshakeError::Identity(s) => s,
            other => panic!("expected IDENTITY_FAILED, got {other:?}"),
        }
    }

    #[test]
    fn issuer_on_pinned_key_is_rejected_before_signature_work() {
        let key = AitpSigningKey::from_seed(&[3u8; 32]);
        let receiver = AitpSigningKey::from_seed(&[4u8; 32]);
        let mid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let c = ctx(key.aid(), receiver.aid(), &mid);
        let mut desc = descriptor_for(
            &key,
            key.aid(),
            receiver.aid(),
            &mid,
            c.timestamp,
            c.pop_nonce,
        );
        desc.issuer = Some(aitp_core::RawUrl::new("https://idp.example"));
        let store = CountingStore {
            inner: store_of(&[&key]),
            calls: AtomicUsize::new(0),
        };
        let msg = identity_msg(verify_pinned_key(&desc, &c, &store).unwrap_err());
        assert!(msg.contains("issuer"), "{msg}");
        assert_eq!(
            store.calls.load(Ordering::SeqCst),
            0,
            "rejected before the store"
        );
    }

    #[test]
    fn subject_binding_sender_aid_requires_subject_to_equal_the_sender_aid() {
        let key = AitpSigningKey::from_seed(&[3u8; 32]);
        let receiver = AitpSigningKey::from_seed(&[4u8; 32]);
        let mid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let mut c = ctx(key.aid(), receiver.aid(), &mid);
        let mut desc = descriptor_for(
            &key,
            key.aid(),
            receiver.aid(),
            &mid,
            c.timestamp,
            c.pop_nonce,
        );
        let store = store_of(&[&key]);

        // Default: `subject` is an unauthenticated label (RFC-AITP-0002 §1).
        assert_eq!(c.subject, SubjectBinding::Unchecked);
        verify_pinned_key(&desc, &c, &store).expect("free-form subject accepted by default");

        c.subject = SubjectBinding::SenderAid;
        let msg = identity_msg(verify_pinned_key(&desc, &c, &store).unwrap_err());
        assert!(msg.contains("subject"), "{msg}");

        desc.subject = key.aid().as_str().to_owned();
        verify_pinned_key(&desc, &c, &store).expect("subject equals the sender AID");
    }

    #[test]
    fn p256_pinned_key_round_trip_returns_verified_key() {
        let key = AitpSigningKey::from_p256_seed(&[0x05; 32]).unwrap();
        let receiver = AitpSigningKey::from_seed(&[4u8; 32]);
        let mid = Uuid::nil();
        let c = ctx(key.aid(), receiver.aid(), &mid);
        let desc = descriptor_for(
            &key,
            key.aid(),
            receiver.aid(),
            &mid,
            c.timestamp,
            c.pop_nonce,
        );
        assert!(
            desc.proof.starts_with("p256."),
            "P-256 proof MUST be tagged"
        );
        assert_eq!(desc.public_key.as_ref().unwrap().len(), 44);
        let v = verify_pinned_key(&desc, &c, &store_of(&[&key])).expect("P-256 pinned key");
        assert_eq!(v.algorithm, AidAlgorithm::P256);
        assert_eq!(v.key, key.verifying_key());
        assert_eq!(&v.aid, key.aid());
    }

    #[test]
    fn p256_untagged_proof_rejected_as_algorithm_mismatch() {
        // id-011: an untagged proof reads as Ed25519; a P-256 key refuses it.
        let key = AitpSigningKey::from_p256_seed(&[0x05; 32]).unwrap();
        let receiver = AitpSigningKey::from_seed(&[4u8; 32]);
        let mid = Uuid::nil();
        let c = ctx(key.aid(), receiver.aid(), &mid);
        let mut desc = descriptor_for(
            &key,
            key.aid(),
            receiver.aid(),
            &mid,
            c.timestamp,
            c.pop_nonce,
        );
        desc.proof = desc.proof["p256.".len()..].to_string();
        let msg = identity_msg(verify_pinned_key(&desc, &c, &store_of(&[&key])).unwrap_err());
        assert!(msg.contains("signature invalid"), "{msg}");
    }

    #[test]
    fn p256_uncompressed_public_key_rejected() {
        // id-012: the 65-byte SEC1 uncompressed form is not permitted.
        use p256::elliptic_curve::sec1::ToSec1Point as _;
        let key = AitpSigningKey::from_p256_seed(&[0x05; 32]).unwrap();
        let receiver = AitpSigningKey::from_seed(&[4u8; 32]);
        let mid = Uuid::nil();
        let c = ctx(key.aid(), receiver.aid(), &mid);
        let mut desc = descriptor_for(
            &key,
            key.aid(),
            receiver.aid(),
            &mid,
            c.timestamp,
            c.pop_nonce,
        );
        let sk = p256::ecdsa::SigningKey::from_slice(&[0x05; 32]).unwrap();
        let uncompressed = sk.verifying_key().as_affine().to_sec1_point(false);
        assert_eq!(uncompressed.as_bytes().len(), 65);
        desc.public_key = Some(base64url::encode(uncompressed.as_bytes()));
        identity_msg(verify_pinned_key(&desc, &c, &store_of(&[&key])).unwrap_err());
    }

    #[test]
    fn p256_public_key_must_be_compressed_prefix() {
        let key = AitpSigningKey::from_p256_seed(&[0x05; 32]).unwrap();
        let receiver = AitpSigningKey::from_seed(&[4u8; 32]);
        let mid = Uuid::nil();
        let c = ctx(key.aid(), receiver.aid(), &mid);
        let mut desc = descriptor_for(
            &key,
            key.aid(),
            receiver.aid(),
            &mid,
            c.timestamp,
            c.pop_nonce,
        );
        let mut pk = key.verifying_key().to_compressed();
        pk[0] = 0x04;
        desc.public_key = Some(base64url::encode(&pk));
        let msg = identity_msg(verify_pinned_key(&desc, &c, &store_of(&[&key])).unwrap_err());
        assert!(msg.contains("compressed"), "{msg}");
    }

    #[test]
    fn ed25519_key_and_p256_key_never_alias_in_the_store() {
        let ed = AitpSigningKey::from_seed(&[3u8; 32]);
        let p = AitpSigningKey::from_p256_seed(&[0x05; 32]).unwrap();
        let store = store_of(&[&ed]);
        assert!(store.is_trusted(&ed.verifying_key()));
        assert!(!store.is_trusted(&p.verifying_key()));
        assert!(!NoPinnedKeys.is_trusted(&ed.verifying_key()));
    }

    #[test]
    fn store_is_consulted_before_the_proof() {
        // An untrusted key with a garbage proof must fail at the store,
        // so the error names the store, not the signature.
        let key = AitpSigningKey::from_seed(&[3u8; 32]);
        let receiver = AitpSigningKey::from_seed(&[4u8; 32]);
        let mid = Uuid::nil();
        let c = ctx(key.aid(), receiver.aid(), &mid);
        let mut desc = descriptor_for(
            &key,
            key.aid(),
            receiver.aid(),
            &mid,
            c.timestamp,
            c.pop_nonce,
        );
        desc.proof = "!not-a-signature!".into();
        let store = CountingStore {
            inner: StaticPinnedKeyStore::default(),
            calls: AtomicUsize::new(0),
        };
        let msg = identity_msg(verify_pinned_key(&desc, &c, &store).unwrap_err());
        assert!(msg.contains("trust store"), "{msg}");
        assert_eq!(store.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn non_pinned_type_rejected_without_consulting_store() {
        // id-011b: an `oidc`-typed descriptor carrying a valid pinned
        // proof and public_key is not run through the pinned path.
        let key = AitpSigningKey::from_seed(&[3u8; 32]);
        let receiver = AitpSigningKey::from_seed(&[4u8; 32]);
        let mid = Uuid::nil();
        let c = ctx(key.aid(), receiver.aid(), &mid);
        let mut desc = descriptor_for(
            &key,
            key.aid(),
            receiver.aid(),
            &mid,
            c.timestamp,
            c.pop_nonce,
        );
        verify_pinned_key(&desc, &c, &store_of(&[&key])).expect("valid as pinned_key");
        desc.kind = IdentityKind::Oidc;
        let store = CountingStore {
            inner: store_of(&[&key]),
            calls: AtomicUsize::new(0),
        };
        let msg = identity_msg(verify_pinned_key(&desc, &c, &store).unwrap_err());
        assert!(msg.contains("pinned_key"), "{msg}");
        assert_eq!(store.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn pop_nonce_must_be_exactly_16_bytes() {
        // id-014: 15 and 17 bytes are rejected on both sides.
        let key = AitpSigningKey::from_seed(&[3u8; 32]);
        let receiver = AitpSigningKey::from_seed(&[4u8; 32]);
        let mid = Uuid::nil();
        let good = ctx(key.aid(), receiver.aid(), &mid);
        let desc = descriptor_for(
            &key,
            key.aid(),
            receiver.aid(),
            &mid,
            good.timestamp,
            good.pop_nonce,
        );
        for len in [0usize, 15, 17, 32] {
            let nonce = base64url::encode(&vec![7u8; len]);
            assert!(
                sign_pinned_key_proof(
                    &key,
                    key.aid(),
                    receiver.aid(),
                    &mid,
                    good.timestamp,
                    &nonce
                )
                .is_err(),
                "signing with a {len}-byte nonce must fail"
            );
            let c = PinnedKeyVerifyContext {
                pop_nonce: &nonce,
                subject: Default::default(),
                ..ctx(key.aid(), receiver.aid(), &mid)
            };
            let msg = identity_msg(verify_pinned_key(&desc, &c, &store_of(&[&key])).unwrap_err());
            assert!(msg.contains("16 bytes"), "{len}: {msg}");
        }
    }

    #[test]
    fn kat_pinned_key_proof_002_p256_verifies() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/schemas/known-answer/jcs-sha256.json"
        );
        let doc: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let v = doc["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["id"] == "kat-pinned-key-proof-002-p256")
            .unwrap();
        let sender = Aid::parse(v["sender_aid"].as_str().unwrap()).unwrap();
        let receiver = Aid::parse(v["receiver_aid"].as_str().unwrap()).unwrap();
        let mid = Uuid::parse_str(v["message_id"].as_str().unwrap()).unwrap();
        let c = PinnedKeyVerifyContext {
            sender_aid: &sender,
            receiver_aid: &receiver,
            message_id: &mid,
            timestamp: Timestamp(v["timestamp"].as_i64().unwrap()),
            pop_nonce: v["pop_nonce"].as_str().unwrap(),
            subject: Default::default(),
        };
        let mut desc = IdentityDescriptor {
            kind: IdentityKind::PinnedKey,
            issuer: None,
            subject: "kat".into(),
            proof: v["signature"].as_str().unwrap().into(),
            public_key: Some(sender.identifier().to_string()),
            extensions: None,
        };
        let store = StaticPinnedKeyStore::from_aids([&sender]).unwrap();
        let got = verify_pinned_key(&desc, &c, &store).expect("KAT proof verifies");
        assert_eq!(got.algorithm, AidAlgorithm::P256);
        desc.proof = v["double_hash_signature_MUST_NOT_verify"]
            .as_str()
            .unwrap()
            .into();
        identity_msg(verify_pinned_key(&desc, &c, &store).unwrap_err());
    }
}
