//! Pluggable signing backends: in-process keys, cloud KMS, HSMs.

use crate::core::{Aid, AidAlgorithm, BoxError, BoxFuture};
use crate::crypto::keys::raw_signature_len;
use crate::crypto::{AitpSigningKey, AitpVerifyingKey, Digest32, RawSignature, Signature};
use std::future::Future;
use std::time::Duration;

/// What the library asks a backend to sign.
///
/// The variant is chosen by the library from the signer AID's algorithm.
/// A backend that receives a variant it does not implement returns
/// [`SignerError::UnsupportedAlgorithm`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignRequest<'a> {
    /// Ed25519: sign these bytes as the PureEdDSA message (RFC 8032).
    /// For [`sign_jcs`] this is the 32-byte digest `d`. For [`sign_raw`]
    /// it is the full signing input, e.g. a compact-JWS
    /// `b64(header).b64(payload)`. AWS KMS: `MessageType = RAW`,
    /// `ED25519_SHA_512`.
    Ed25519Message(&'a [u8]),
    /// P-256: sign this 32-byte value as the ECDSA message hash `e`. It
    /// is **already hashed**: the backend MUST NOT hash it again. AWS
    /// KMS: `MessageType = DIGEST`, `ECDSA_SHA_256`. PKCS#11:
    /// `CKM_ECDSA` (not `CKM_ECDSA_SHA256`).
    P256Digest(&'a Digest32),
}

impl SignRequest<'_> {
    /// The algorithm this request is for.
    pub fn algorithm(&self) -> AidAlgorithm {
        match self {
            SignRequest::Ed25519Message(_) => AidAlgorithm::Ed25519,
            SignRequest::P256Digest(_) => AidAlgorithm::P256,
        }
    }

    /// The bytes to sign.
    pub fn bytes(&self) -> &[u8] {
        match self {
            SignRequest::Ed25519Message(m) => m,
            SignRequest::P256Digest(d) => d.as_bytes(),
        }
    }

    /// Length of [`Self::bytes`], compared with
    /// [`AitpSigner::max_message_len`].
    pub fn len(&self) -> usize {
        self.bytes().len()
    }

    /// Whether [`Self::bytes`] is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A signature as a backend produced it, before the library normalises
/// and verifies it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BackendSignature {
    /// The algorithm's raw encoding: Ed25519 `R || S`, or P-256 JOSE
    /// `R || S` (either S), 64 bytes each. A length other than the
    /// algorithm's is [`SignerError::MalformedSignature`].
    Raw(Vec<u8>),
    /// P-256 ASN.1 DER `ECDSA-Sig-Value`, as AWS KMS, GCP Cloud KMS and
    /// most HSMs return it. Not valid for Ed25519.
    Der(Vec<u8>),
}

/// Why a signing operation failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SignerError {
    /// The backend failed in a way that may succeed on retry:
    /// throttling, a timeout, a 5xx, a dropped connection.
    #[error("transient signer failure: {message}")]
    Transient {
        /// Human-readable detail. Must not contain key material.
        message: String,
        /// The backend's hint for when to retry, if it gave one.
        retry_after: Option<Duration>,
        /// The underlying SDK error.
        #[source]
        source: Option<BoxError>,
    },
    /// The backend failed in a way a retry will not fix: access denied,
    /// key disabled or scheduled for deletion, wrong key type.
    #[error("permanent signer failure: {message}")]
    Permanent {
        /// Human-readable detail. Must not contain key material.
        message: String,
        /// The underlying SDK error.
        #[source]
        source: Option<BoxError>,
    },
    /// The request exceeds [`AitpSigner::max_message_len`]. Raised by
    /// the library before the backend is called.
    #[error("message of {len} bytes exceeds the signer's {max}-byte limit")]
    MessageTooLarge {
        /// Length of the request.
        len: usize,
        /// The signer's limit.
        max: usize,
    },
    /// The signer cannot sign for this algorithm.
    #[error("unsupported signing algorithm: {0}")]
    UnsupportedAlgorithm(String),
    /// The backend returned bytes that are not a signature in the
    /// expected encoding (bad DER, wrong length, out-of-range scalar,
    /// DER for Ed25519).
    #[error("backend returned a malformed signature: {0}")]
    MalformedSignature(String),
    /// Verify-before-emit failed: the backend's signature does not verify
    /// under the key encoded in the signer's AID. Usually a backend
    /// configured with a different key than the AID it claims.
    #[error("backend signature does not verify under the signer AID (verify-before-emit)")]
    VerificationFailed,
    /// The backend's public key is not the key encoded in the signer's
    /// AID. Raised by [`check_public_key`].
    #[error("backend public key {reported} does not match the signer AID {expected}")]
    KeyMismatch {
        /// The AID the signer claims.
        expected: Aid,
        /// The AID of the key the backend reported.
        reported: Aid,
    },
}

impl SignerError {
    /// A transient failure with no retry hint.
    pub fn transient(message: impl Into<String>) -> Self {
        SignerError::Transient {
            message: message.into(),
            retry_after: None,
            source: None,
        }
    }

    /// A transient failure the backend asked to retry after `after`.
    pub fn transient_retry_after(message: impl Into<String>, after: Duration) -> Self {
        SignerError::Transient {
            message: message.into(),
            retry_after: Some(after),
            source: None,
        }
    }

    /// A permanent failure.
    pub fn permanent(message: impl Into<String>) -> Self {
        SignerError::Permanent {
            message: message.into(),
            source: None,
        }
    }

    /// Attach the underlying error to a `Transient` or `Permanent`
    /// failure. Other variants are returned unchanged.
    pub fn with_source(mut self, err: impl Into<BoxError>) -> Self {
        match &mut self {
            SignerError::Transient { source, .. } | SignerError::Permanent { source, .. } => {
                *source = Some(err.into());
            }
            _ => {}
        }
        self
    }

    /// Whether a retry may succeed.
    pub fn is_transient(&self) -> bool {
        matches!(self, SignerError::Transient { .. })
    }

    /// The backend's retry hint, for a transient failure.
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            SignerError::Transient { retry_after, .. } => *retry_after,
            _ => None,
        }
    }
}

/// A blocking signing backend. Implement this for a KMS or HSM client;
/// [`AitpSigningKey`] implements it for in-process keys.
///
/// Callers do not call [`Self::sign`] directly: they go through
/// [`sign_jcs`], [`sign_raw`] or the artifact builders, which apply the
/// framing, size check, normalisation and verify-before-emit described
/// below.
///
/// [`AitpSigningKey`] keeps the key in process memory. Production
/// deployments often cannot: the key lives in AWS KMS, GCP Cloud KMS,
/// Azure Key Vault, a PKCS#11 HSM or a remote signing service. This
/// trait and [`AsyncAitpSigner`] are the seam between the protocol and
/// those backends, and
/// keeps every protocol-critical step on the library side of it.
///
/// # The split
///
/// A backend implements [`AitpSigner`] (blocking) or [`AsyncAitpSigner`]
/// (async). It only has to do one thing: sign the bytes in a
/// [`SignRequest`] with the key behind [`AitpSigner::aid`], and return
/// what the backend produced ([`BackendSignature`]). The library does the
/// rest, so a backend cannot get it wrong:
///
/// - **Framing.** [`sign_jcs`] and [`sign_raw`] decide what is signed.
///   Ed25519 receives the message ([`SignRequest::Ed25519Message`]);
///   P-256 receives the 32-byte digest it signs as the ECDSA hash `e`
///   ([`SignRequest::P256Digest`], RFC-AITP-0001 §5.4.6). The backend
///   never hashes, so the 0.13.x double hash cannot come back through a
///   KMS that defaults to "hash the message for me".
/// - **Size limits.** A request longer than
///   [`AitpSigner::max_message_len`] is refused with
///   [`SignerError::MessageTooLarge`] *before* the backend is called
///   (AWS KMS `RAW` signing accepts at most 4096 bytes).
/// - **Encoding.** DER (`ECDSA-Sig-Value`) is decoded to JOSE `R || S`.
/// - **Low-S.** P-256 output is normalised to low-S (§5.4.7), whatever
///   the backend returned.
/// - **Verify before emit.** The normalised signature is verified,
///   strictly, against the key encoded in the signer's AID. A backend
///   that signed with a different key, truncated, or corrupted the
///   signature produces [`SignerError::VerificationFailed`], never a
///   token that fails at the peer.
/// - **Key binding at startup.** [`check_public_key`] compares the
///   backend's own public key ([`AitpSigner::public_key`]) with the AID,
///   so a misconfigured key ARN fails at boot, not at first use.
///
/// Randomized ECDSA nonces (AWS KMS) are accepted: §5.4.7 constrains the
/// encoding, not the nonce. Ed25519 is deterministic by definition
/// (RFC 8032), and the strict verifier is the only check it needs.
///
/// # Errors a caller can act on
///
/// [`SignerError::is_transient`] separates "retry, maybe after
/// [`SignerError::retry_after`]" (throttling, timeouts, a KMS 5xx) from
/// permanent failures (access denied, key disabled, wrong key). The
/// library never retries on its own; the caller owns the retry budget.
///
/// # No SDK dependency
///
/// This crate depends on no cloud SDK. A backend is a few lines in the
/// application, on top of the SDK it already uses. See
/// `docs/key-management.md` for AWS KMS, GCP and PKCS#11 sketches.
pub trait AitpSigner: Send + Sync {
    /// The AID this signer signs for. Fixed for the signer's lifetime.
    fn aid(&self) -> &Aid;

    /// The longest [`SignRequest::bytes`] the backend accepts, if it has
    /// a limit (AWS KMS `RAW`: 4096). Longer requests are refused before
    /// [`Self::sign`] is called.
    fn max_message_len(&self) -> Option<usize> {
        None
    }

    /// The backend's own view of its public key (AWS KMS `GetPublicKey`).
    /// [`check_public_key`] compares it with [`Self::aid`].
    fn public_key(&self) -> Result<AitpVerifyingKey, SignerError>;

    /// Sign `request` with the backend key.
    fn sign(&self, request: SignRequest<'_>) -> Result<BackendSignature, SignerError>;

    /// In-process fast path for [`AitpSigningKey`] and the wrappers this
    /// crate implements: the library signs with the key directly and
    /// skips the backend round trip and verify-before-emit. Its argument
    /// cannot be named outside this crate, so a backend cannot override
    /// it and always takes the backend path.
    #[doc(hidden)]
    fn as_signing_key(&self, _: sealed::Local) -> Option<&AitpSigningKey> {
        None
    }
}

mod sealed {
    /// The argument of `as_signing_key`: only this crate can construct
    /// it, so only this crate's impls supply the in-process key.
    #[derive(Debug)]
    pub struct Local(pub(super) ());
}

/// An async signing backend, for clients whose SDK is async (every
/// cloud KMS SDK). [`AitpSigningKey`] implements it too.
///
/// The futures are `Send`, so the signer works on multi-threaded
/// runtimes. Use [`DynAsyncAitpSigner`] for a type-erased
/// `Arc<dyn DynAsyncAitpSigner>`; every `AsyncAitpSigner` implements it.
pub trait AsyncAitpSigner: Send + Sync {
    /// See [`AitpSigner::aid`].
    fn aid(&self) -> &Aid;

    /// See [`AitpSigner::max_message_len`].
    fn max_message_len(&self) -> Option<usize> {
        None
    }

    /// See [`AitpSigner::public_key`].
    fn public_key(&self) -> impl Future<Output = Result<AitpVerifyingKey, SignerError>> + Send;

    /// See [`AitpSigner::sign`].
    fn sign(
        &self,
        request: SignRequest<'_>,
    ) -> impl Future<Output = Result<BackendSignature, SignerError>> + Send;

    #[doc(hidden)]
    fn as_signing_key(&self, _: sealed::Local) -> Option<&AitpSigningKey> {
        None
    }
}

/// Object-safe form of [`AsyncAitpSigner`], for
/// `Arc<dyn DynAsyncAitpSigner>`. Implemented for every
/// [`AsyncAitpSigner`]; implement that trait, not this one.
pub trait DynAsyncAitpSigner: Send + Sync {
    /// See [`AitpSigner::aid`].
    fn aid(&self) -> &Aid;
    /// See [`AitpSigner::max_message_len`].
    fn max_message_len(&self) -> Option<usize>;
    /// See [`AitpSigner::public_key`].
    fn public_key(&self) -> BoxFuture<'_, Result<AitpVerifyingKey, SignerError>>;
    /// See [`AitpSigner::sign`].
    fn sign<'a>(
        &'a self,
        request: SignRequest<'a>,
    ) -> BoxFuture<'a, Result<BackendSignature, SignerError>>;
    #[doc(hidden)]
    fn as_signing_key(&self, _: sealed::Local) -> Option<&AitpSigningKey>;
}

impl<T: AsyncAitpSigner> DynAsyncAitpSigner for T {
    fn aid(&self) -> &Aid {
        AsyncAitpSigner::aid(self)
    }
    fn max_message_len(&self) -> Option<usize> {
        AsyncAitpSigner::max_message_len(self)
    }
    fn public_key(&self) -> BoxFuture<'_, Result<AitpVerifyingKey, SignerError>> {
        Box::pin(AsyncAitpSigner::public_key(self))
    }
    fn sign<'a>(
        &'a self,
        request: SignRequest<'a>,
    ) -> BoxFuture<'a, Result<BackendSignature, SignerError>> {
        Box::pin(AsyncAitpSigner::sign(self, request))
    }
    fn as_signing_key(&self, _: sealed::Local) -> Option<&AitpSigningKey> {
        AsyncAitpSigner::as_signing_key(self, sealed::Local(()))
    }
}

/// Use a blocking [`AitpSigner`] where an async one is expected. The
/// blocking call runs inline on the polling task, so wrap only signers
/// that do not block for long (in-process keys, a local HSM).
#[derive(Debug, Clone)]
pub struct BlockingSigner<S>(pub S);

impl<S: AitpSigner> AsyncAitpSigner for BlockingSigner<S> {
    fn aid(&self) -> &Aid {
        self.0.aid()
    }
    fn max_message_len(&self) -> Option<usize> {
        self.0.max_message_len()
    }
    fn public_key(&self) -> impl Future<Output = Result<AitpVerifyingKey, SignerError>> + Send {
        std::future::ready(self.0.public_key())
    }
    fn sign(
        &self,
        request: SignRequest<'_>,
    ) -> impl Future<Output = Result<BackendSignature, SignerError>> + Send {
        std::future::ready(self.0.sign(request))
    }
    fn as_signing_key(&self, _: sealed::Local) -> Option<&AitpSigningKey> {
        self.0.as_signing_key(sealed::Local(()))
    }
}

impl AitpSigner for AitpSigningKey {
    fn aid(&self) -> &Aid {
        AitpSigningKey::aid(self)
    }
    fn public_key(&self) -> Result<AitpVerifyingKey, SignerError> {
        Ok(self.verifying_key())
    }
    fn sign(&self, request: SignRequest<'_>) -> Result<BackendSignature, SignerError> {
        match (self.algorithm(), request) {
            (AidAlgorithm::Ed25519, SignRequest::Ed25519Message(m)) => {
                Ok(BackendSignature::Raw(self.sign_raw(m).into_vec()))
            }
            (AidAlgorithm::P256, SignRequest::P256Digest(d)) => {
                let wire = self.sign_jcs(d);
                Ok(BackendSignature::Raw(decode_wire_raw(&wire).into_vec()))
            }
            (alg, req) => Err(SignerError::UnsupportedAlgorithm(format!(
                "{alg:?} key cannot serve a {:?} request",
                req.algorithm()
            ))),
        }
    }
    fn as_signing_key(&self, _: sealed::Local) -> Option<&AitpSigningKey> {
        Some(self)
    }
}

impl AsyncAitpSigner for AitpSigningKey {
    fn aid(&self) -> &Aid {
        AitpSigningKey::aid(self)
    }
    fn public_key(&self) -> impl Future<Output = Result<AitpVerifyingKey, SignerError>> + Send {
        std::future::ready(Ok(self.verifying_key()))
    }
    fn sign(
        &self,
        request: SignRequest<'_>,
    ) -> impl Future<Output = Result<BackendSignature, SignerError>> + Send {
        std::future::ready(AitpSigner::sign(self, request))
    }
    fn as_signing_key(&self, _: sealed::Local) -> Option<&AitpSigningKey> {
        Some(self)
    }
}

impl<S: AitpSigner + ?Sized> AitpSigner for &S {
    fn aid(&self) -> &Aid {
        (**self).aid()
    }
    fn max_message_len(&self) -> Option<usize> {
        (**self).max_message_len()
    }
    fn public_key(&self) -> Result<AitpVerifyingKey, SignerError> {
        (**self).public_key()
    }
    fn sign(&self, request: SignRequest<'_>) -> Result<BackendSignature, SignerError> {
        (**self).sign(request)
    }
    fn as_signing_key(&self, _: sealed::Local) -> Option<&AitpSigningKey> {
        (**self).as_signing_key(sealed::Local(()))
    }
}

impl<S: AitpSigner + ?Sized> AitpSigner for std::sync::Arc<S> {
    fn aid(&self) -> &Aid {
        (**self).aid()
    }
    fn max_message_len(&self) -> Option<usize> {
        (**self).max_message_len()
    }
    fn public_key(&self) -> Result<AitpVerifyingKey, SignerError> {
        (**self).public_key()
    }
    fn sign(&self, request: SignRequest<'_>) -> Result<BackendSignature, SignerError> {
        (**self).sign(request)
    }
    fn as_signing_key(&self, _: sealed::Local) -> Option<&AitpSigningKey> {
        (**self).as_signing_key(sealed::Local(()))
    }
}

impl<S: AitpSigner + ?Sized> AitpSigner for Box<S> {
    fn aid(&self) -> &Aid {
        (**self).aid()
    }
    fn max_message_len(&self) -> Option<usize> {
        (**self).max_message_len()
    }
    fn public_key(&self) -> Result<AitpVerifyingKey, SignerError> {
        (**self).public_key()
    }
    fn sign(&self, request: SignRequest<'_>) -> Result<BackendSignature, SignerError> {
        (**self).sign(request)
    }
    fn as_signing_key(&self, _: sealed::Local) -> Option<&AitpSigningKey> {
        (**self).as_signing_key(sealed::Local(()))
    }
}

/// Decode the raw bytes of a wire signature this crate just produced.
fn decode_wire_raw(sig: &Signature) -> RawSignature {
    use base64ct::{Base64UrlUnpadded, Encoding};
    let raw = Base64UrlUnpadded::decode_vec(sig.payload()).expect("own signature is base64url");
    RawSignature::from_bytes(&raw)
}

/// What the library signs and how the result is checked.
enum Target<'a> {
    /// The AITP digest `d` (§5.4.6).
    Jcs(&'a Digest32),
    /// A raw message (EdDSA / ES256 over the message).
    Raw(&'a [u8]),
}

/// The in-process key, if the signer offers one bound to its own AID.
fn local_key<'a>(key: Option<&'a AitpSigningKey>, aid: &Aid) -> Option<&'a AitpSigningKey> {
    key.filter(|k| k.aid() == aid)
}

/// The algorithm of `aid`, if this build can sign for it.
fn signing_algorithm(aid: &Aid) -> Result<AidAlgorithm, SignerError> {
    match aid.algorithm() {
        a @ (AidAlgorithm::Ed25519 | AidAlgorithm::P256) => Ok(a),
    }
}

/// The 32 bytes a P-256 backend signs for `target`.
fn p256_digest(target: &Target<'_>) -> Digest32 {
    match target {
        Target::Jcs(d) => **d,
        Target::Raw(m) => Digest32::sha256(m),
    }
}

/// Build the request for `target`. `digest` is the P-256 hash, computed
/// by the caller so it outlives an `.await`.
fn request<'a>(
    alg: AidAlgorithm,
    target: &Target<'a>,
    digest: &'a Digest32,
    max: Option<usize>,
) -> Result<SignRequest<'a>, SignerError> {
    let req = match (alg, target) {
        (AidAlgorithm::Ed25519, Target::Jcs(d)) => SignRequest::Ed25519Message(d.as_bytes()),
        (AidAlgorithm::Ed25519, Target::Raw(m)) => SignRequest::Ed25519Message(m),
        _ => SignRequest::P256Digest(digest),
    };
    if let Some(max) = max {
        if req.len() > max {
            return Err(SignerError::MessageTooLarge {
                len: req.len(),
                max,
            });
        }
    }
    Ok(req)
}

/// Normalise the backend output and verify it before it leaves the
/// library.
fn finalize(
    aid: &Aid,
    alg: AidAlgorithm,
    target: &Target<'_>,
    sig: BackendSignature,
) -> Result<RawSignature, SignerError> {
    let raw = match alg {
        AidAlgorithm::P256 => {
            RawSignature::from_bytes(&crate::crypto::keys::p256_backend_to_low_s(&sig)?)
        }
        _ => match sig {
            BackendSignature::Raw(raw) if raw.len() == raw_signature_len(alg) => {
                RawSignature::from_bytes(&raw)
            }
            BackendSignature::Raw(raw) => {
                return Err(SignerError::MalformedSignature(format!(
                    "{alg:?} signature is {} bytes, expected {}",
                    raw.len(),
                    raw_signature_len(alg)
                )))
            }
            BackendSignature::Der(_) => {
                return Err(SignerError::MalformedSignature(
                    "DER is not an Ed25519 signature encoding".into(),
                ))
            }
        },
    };
    let vk = AitpVerifyingKey::from_aid(aid)
        .map_err(|e| SignerError::permanent(format!("signer AID does not encode a key: {e}")))?;
    let verified = match target {
        Target::Jcs(d) => vk.verify_jcs(d, &Signature::from_raw(alg, raw.as_bytes())),
        Target::Raw(m) => vk.verify_raw(m, raw.as_bytes()),
    };
    verified.map_err(|_| SignerError::VerificationFailed)?;
    Ok(raw)
}

fn sign_target(signer: &dyn AitpSigner, target: Target<'_>) -> Result<RawSignature, SignerError> {
    let aid = signer.aid();
    let alg = signing_algorithm(aid)?;
    if let Some(key) = local_key(signer.as_signing_key(sealed::Local(())), aid) {
        return Ok(sign_local(key, &target));
    }
    let digest = p256_digest(&target);
    let req = request(alg, &target, &digest, signer.max_message_len())?;
    let sig = signer.sign(req)?;
    finalize(aid, alg, &target, sig)
}

async fn sign_target_async(
    signer: &dyn DynAsyncAitpSigner,
    target: Target<'_>,
) -> Result<RawSignature, SignerError> {
    let aid = signer.aid();
    let alg = signing_algorithm(aid)?;
    if let Some(key) = local_key(signer.as_signing_key(sealed::Local(())), aid) {
        return Ok(sign_local(key, &target));
    }
    let digest = p256_digest(&target);
    let req = request(alg, &target, &digest, signer.max_message_len())?;
    let sig = signer.sign(req).await?;
    finalize(aid, alg, &target, sig)
}

fn sign_local(key: &AitpSigningKey, target: &Target<'_>) -> RawSignature {
    match target {
        Target::Jcs(d) => decode_wire_raw(&key.sign_jcs(d)),
        Target::Raw(m) => key.sign_raw(m),
    }
}

/// Sign the AITP digest `d` (RFC-AITP-0001 §5.4.6) with any backend and
/// return the wire-form signature, exactly as
/// [`AitpSigningKey::sign_jcs`] would for the same key (byte-identical
/// for Ed25519 and for deterministic P-256 backends).
pub fn sign_jcs(signer: &dyn AitpSigner, d: &Digest32) -> Result<Signature, SignerError> {
    let alg = signing_algorithm(signer.aid())?;
    sign_target(signer, Target::Jcs(d)).map(|raw| Signature::from_raw(alg, raw.as_bytes()))
}

/// Sign raw `message` bytes with any backend: PureEdDSA for Ed25519,
/// ES256 (one SHA-256, low-S, `R || S`) for P-256, returned as a
/// [`RawSignature`] of the algorithm's length. The public raw-sign
/// entry point for compact JWS and application framings; see
/// [`AitpSigningKey::sign_raw`] for the domain-separation duty.
///
/// For Ed25519 the whole message goes to the backend, so
/// [`AitpSigner::max_message_len`] applies to it. For P-256 the library
/// hashes and the backend only sees 32 bytes.
pub fn sign_raw(signer: &dyn AitpSigner, message: &[u8]) -> Result<RawSignature, SignerError> {
    sign_target(signer, Target::Raw(message))
}

/// Async [`sign_jcs`].
pub async fn sign_jcs_async(
    signer: &dyn DynAsyncAitpSigner,
    d: &Digest32,
) -> Result<Signature, SignerError> {
    let alg = signing_algorithm(signer.aid())?;
    sign_target_async(signer, Target::Jcs(d))
        .await
        .map(|raw| Signature::from_raw(alg, raw.as_bytes()))
}

/// Async [`sign_raw`].
pub async fn sign_raw_async(
    signer: &dyn DynAsyncAitpSigner,
    message: &[u8],
) -> Result<RawSignature, SignerError> {
    sign_target_async(signer, Target::Raw(message)).await
}

fn compare_keys(aid: &Aid, reported: AitpVerifyingKey) -> Result<(), SignerError> {
    let expected = AitpVerifyingKey::from_aid(aid)
        .map_err(|e| SignerError::permanent(format!("signer AID does not encode a key: {e}")))?;
    if expected == reported {
        Ok(())
    } else {
        Err(SignerError::KeyMismatch {
            expected: aid.clone(),
            reported: reported.to_aid(),
        })
    }
}

/// Startup check: the backend's public key is the key encoded in the
/// signer's AID. Call once when the signer is configured, so a wrong key
/// ID fails at boot with [`SignerError::KeyMismatch`].
pub fn check_public_key(signer: &dyn AitpSigner) -> Result<(), SignerError> {
    signing_algorithm(signer.aid())?;
    compare_keys(signer.aid(), signer.public_key()?)
}

/// Async [`check_public_key`].
pub async fn check_public_key_async(signer: &dyn DynAsyncAitpSigner) -> Result<(), SignerError> {
    signing_algorithm(signer.aid())?;
    compare_keys(signer.aid(), signer.public_key().await?)
}
