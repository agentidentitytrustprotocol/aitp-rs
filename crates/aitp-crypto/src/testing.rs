//! Test doubles for [`crate::signer`]. Enabled by the `test-util`
//! feature; never compiled into a release build of a dependent unless it
//! asks for it.

use crate::signer::{AitpSigner, AsyncAitpSigner, BackendSignature, SignRequest, SignerError};
use crate::{AitpSigningKey, AitpVerifyingKey};
use aitp_core::{Aid, AidAlgorithm};
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// How [`MockKmsSigner`] shapes the signature it returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MockOutput {
    /// 64-byte `R || S` exactly as the in-process key produces it.
    Raw,
    /// P-256 as ASN.1 DER, like AWS KMS / GCP Cloud KMS.
    Der,
    /// P-256 DER with `S` replaced by `n - S` (high-S, still valid
    /// ECDSA). The library must normalise it.
    DerHighS,
    /// P-256 raw `R || S` with high-S.
    RawHighS,
    /// P-256 DER over a random nonce instead of RFC 6979, like AWS KMS.
    /// Two calls over the same digest return different signatures.
    RandomizedDer,
    /// Bytes that are not DER.
    MalformedDer,
    /// Ed25519 with `S + L` (non-canonical). Strict verify must refuse.
    Ed25519NonCanonicalS,
}

/// A deterministic stand-in for a cloud KMS key.
///
/// It holds a real [`AitpSigningKey`] but offers no in-process fast path,
/// so every signature goes through the library's full backend pipeline
/// (size check, DER decoding, low-S, verify-before-emit). Knobs:
/// output shape ([`MockOutput`]), the advertised size limit, a different
/// key to sign with or to report, and a number of transient failures to
/// return first. [`Self::calls`] counts backend invocations, so a test
/// can prove a request was refused before the backend saw it.
pub struct MockKmsSigner {
    key: AitpSigningKey,
    claimed_aid: Aid,
    signing_key: Option<AitpSigningKey>,
    reported_key: Option<AitpVerifyingKey>,
    output: MockOutput,
    max_message_len: Option<usize>,
    transient_failures: AtomicUsize,
    retry_after: Option<Duration>,
    calls: AtomicUsize,
}

/// AWS KMS `Sign` limit for `MessageType = RAW`.
pub const AWS_KMS_RAW_MAX: usize = 4096;

impl MockKmsSigner {
    /// A backend for `key`, returning [`MockOutput::Der`] for P-256 and
    /// [`MockOutput::Raw`] for Ed25519, with the AWS KMS 4096-byte limit.
    pub fn new(key: AitpSigningKey) -> Self {
        let output = match key.algorithm() {
            AidAlgorithm::P256 => MockOutput::Der,
            _ => MockOutput::Raw,
        };
        Self {
            claimed_aid: key.aid().clone(),
            key,
            signing_key: None,
            reported_key: None,
            output,
            max_message_len: Some(AWS_KMS_RAW_MAX),
            transient_failures: AtomicUsize::new(0),
            retry_after: None,
            calls: AtomicUsize::new(0),
        }
    }

    /// Set the output shape.
    pub fn output(mut self, output: MockOutput) -> Self {
        self.output = output;
        self
    }

    /// Set the advertised size limit.
    pub fn max_message_len(mut self, max: Option<usize>) -> Self {
        self.max_message_len = max;
        self
    }

    /// Sign with `other` while still claiming the original AID: a KMS
    /// key ARN pointing at the wrong key.
    pub fn sign_with(mut self, other: AitpSigningKey) -> Self {
        self.signing_key = Some(other);
        self
    }

    /// Report `vk` from `public_key()` instead of the real key.
    pub fn report_public_key(mut self, vk: AitpVerifyingKey) -> Self {
        self.reported_key = Some(vk);
        self
    }

    /// Fail the first `n` sign calls with a transient error carrying
    /// `retry_after`.
    pub fn fail_transient(mut self, n: usize, retry_after: Option<Duration>) -> Self {
        self.transient_failures = AtomicUsize::new(n);
        self.retry_after = retry_after;
        self
    }

    /// How many times the backend's `sign` was invoked.
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn do_sign(&self, request: SignRequest<'_>) -> Result<BackendSignature, SignerError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self
            .transient_failures
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            return Err(SignerError::Transient {
                message: "ThrottlingException".into(),
                retry_after: self.retry_after,
                source: None,
            });
        }
        if let Some(max) = self.max_message_len {
            assert!(
                request.len() <= max,
                "library must refuse oversize requests before the backend"
            );
        }
        let key = self.signing_key.as_ref().unwrap_or(&self.key);
        if key.algorithm() != request.algorithm() {
            return Err(SignerError::UnsupportedAlgorithm(format!(
                "{:?}",
                request.algorithm()
            )));
        }
        match request {
            SignRequest::Ed25519Message(m) => {
                let mut raw = key.sign_raw(m);
                if self.output == MockOutput::Ed25519NonCanonicalS {
                    add_l(&mut raw[32..]);
                }
                Ok(BackendSignature::Raw(raw))
            }
            SignRequest::P256Digest(d) => {
                let raw = if self.output == MockOutput::RandomizedDer {
                    crate::keys::p256_sign_prehash_randomized(key, d).expect("P-256 key")
                } else {
                    let BackendSignature::Raw(raw) = AitpSigner::sign(key, request)? else {
                        unreachable!("in-process keys return raw signatures")
                    };
                    raw
                };
                Ok(match self.output {
                    MockOutput::Raw | MockOutput::Ed25519NonCanonicalS => {
                        BackendSignature::Raw(raw)
                    }
                    MockOutput::RawHighS => BackendSignature::Raw(high_s(raw)),
                    MockOutput::Der | MockOutput::RandomizedDer => {
                        BackendSignature::Der(der_encode(&raw))
                    }
                    MockOutput::DerHighS => BackendSignature::Der(der_encode(&high_s(raw))),
                    MockOutput::MalformedDer => BackendSignature::Der(vec![0x30, 0x03, 0x02]),
                })
            }
        }
    }

    fn do_public_key(&self) -> AitpVerifyingKey {
        self.reported_key.clone().unwrap_or_else(|| {
            self.signing_key
                .as_ref()
                .unwrap_or(&self.key)
                .verifying_key()
        })
    }
}

impl AitpSigner for MockKmsSigner {
    fn aid(&self) -> &Aid {
        &self.claimed_aid
    }
    fn max_message_len(&self) -> Option<usize> {
        self.max_message_len
    }
    fn public_key(&self) -> Result<AitpVerifyingKey, SignerError> {
        Ok(self.do_public_key())
    }
    fn sign(&self, request: SignRequest<'_>) -> Result<BackendSignature, SignerError> {
        self.do_sign(request)
    }
}

impl AsyncAitpSigner for MockKmsSigner {
    fn aid(&self) -> &Aid {
        &self.claimed_aid
    }
    fn max_message_len(&self) -> Option<usize> {
        self.max_message_len
    }
    fn public_key(&self) -> impl Future<Output = Result<AitpVerifyingKey, SignerError>> + Send {
        let vk = self.do_public_key();
        async move {
            yield_once().await;
            Ok(vk)
        }
    }
    // Spelled as `impl Future + Send` to mirror the trait signature exactly.
    #[allow(clippy::manual_async_fn)]
    fn sign(
        &self,
        request: SignRequest<'_>,
    ) -> impl Future<Output = Result<BackendSignature, SignerError>> + Send {
        async move {
            // A real SDK call suspends at least once.
            yield_once().await;
            self.do_sign(request)
        }
    }
}

/// Suspend once, so async tests exercise a real `Pending` poll.
async fn yield_once() {
    let mut yielded = false;
    std::future::poll_fn(|cx| {
        if yielded {
            std::task::Poll::Ready(())
        } else {
            yielded = true;
            cx.waker().wake_by_ref();
            std::task::Poll::Pending
        }
    })
    .await
}

/// P-256 group order `n`, big-endian.
const P256_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

/// Ed25519 group order `L`, little-endian.
const ED25519_L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// `(r, n - s)`: the high-S twin of a low-S signature.
fn high_s(mut raw: [u8; 64]) -> [u8; 64] {
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let v = P256_N[i] as i16 - raw[32 + i] as i16 - borrow;
        borrow = (v < 0) as i16;
        raw[32 + i] = v.rem_euclid(256) as u8;
    }
    raw
}

/// `s += L` (little-endian); stays below 2^256 for any canonical `s`.
fn add_l(s: &mut [u8]) {
    let mut carry = 0u16;
    for (b, l) in s.iter_mut().zip(ED25519_L) {
        let v = *b as u16 + l as u16 + carry;
        *b = v as u8;
        carry = v >> 8;
    }
}

/// Minimal DER `ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }`.
fn der_encode(raw: &[u8; 64]) -> Vec<u8> {
    fn int(out: &mut Vec<u8>, be: &[u8]) {
        let start = be.iter().position(|&b| b != 0).unwrap_or(be.len() - 1);
        let v = &be[start..];
        let pad = v[0] & 0x80 != 0;
        out.push(0x02);
        out.push((v.len() + pad as usize) as u8);
        if pad {
            out.push(0);
        }
        out.extend_from_slice(v);
    }
    let mut body = Vec::with_capacity(72);
    int(&mut body, &raw[..32]);
    int(&mut body, &raw[32..]);
    let mut out = vec![0x30, body.len() as u8];
    out.extend(body);
    out
}
