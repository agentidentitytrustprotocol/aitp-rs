//! Shared client/server helpers.
//!
//! Envelope signing/verification is implemented in the `aitp::envelope`
//! crate (no HTTP, no async) so language bindings and other sync
//! consumers can reuse it without a transport stack. The thin wrappers
//! below delegate to it while keeping the `crate::transport::common`
//! API surface stable for existing callers.

use crate::core::{AitpEnvelope, MessageType, Timestamp};
use crate::crypto::{AitpSigner, DynAsyncAitpSigner};
use uuid::Uuid;

/// Sign and wrap a payload as an [`AitpEnvelope`] with caller-provided
/// `message_id` and `timestamp`.
///
/// **Use this** whenever the payload contains a pinned-key identity proof
/// (the proof is signed over `<message_id>|<timestamp>` and the receiver
/// reconstructs the same string from `envelope.message_id` /
/// `envelope.timestamp`). Caller MUST pass the same `(mid, ts)` it used
/// to build the identity proof inside `payload`.
///
/// Accepts any [`AitpSigner`] (in-process key, KMS, HSM); a backend
/// failure is returned as `Err("signing backend failed: ...")`.
pub fn sign_envelope_with(
    signing_key: &dyn AitpSigner,
    message_type: MessageType,
    payload: serde_json::Value,
    message_id: Uuid,
    timestamp: Timestamp,
) -> Result<AitpEnvelope, String> {
    crate::envelope::sign_envelope_with(signing_key, message_type, payload, message_id, timestamp)
}

/// Convenience: sign with a freshly generated `message_id` and
/// `timestamp`. **Do not use** for envelopes whose payload carries a
/// pinned-key identity proof — see [`sign_envelope_with`].
///
/// Accepts any [`AitpSigner`] (in-process key, KMS, HSM); a backend
/// failure is returned as `Err("signing backend failed: ...")`.
pub fn sign_envelope(
    signing_key: &dyn AitpSigner,
    message_type: MessageType,
    payload: serde_json::Value,
) -> Result<AitpEnvelope, String> {
    crate::envelope::sign_envelope(signing_key, message_type, payload)
}

/// As [`sign_envelope_with`], signed by an async backend (KMS, HSM).
/// Delegates to [`crate::envelope::sign_envelope_with_async`]; the future
/// is `Send`.
pub async fn sign_envelope_with_async(
    signing_key: &dyn DynAsyncAitpSigner,
    message_type: MessageType,
    payload: serde_json::Value,
    message_id: Uuid,
    timestamp: Timestamp,
) -> Result<AitpEnvelope, String> {
    crate::envelope::sign_envelope_with_async(
        signing_key,
        message_type,
        payload,
        message_id,
        timestamp,
    )
    .await
}

/// As [`sign_envelope`], signed by an async backend (KMS, HSM).
/// Delegates to [`crate::envelope::sign_envelope_async`]; the future is
/// `Send`. **Do not use** for envelopes whose payload carries a
/// pinned-key identity proof — see [`sign_envelope_with_async`].
pub async fn sign_envelope_async(
    signing_key: &dyn DynAsyncAitpSigner,
    message_type: MessageType,
    payload: serde_json::Value,
) -> Result<AitpEnvelope, String> {
    crate::envelope::sign_envelope_async(signing_key, message_type, payload).await
}

/// Verify an envelope's outer signature given the sender's verifying key.
pub fn verify_envelope_signature(
    envelope: &AitpEnvelope,
    sender_pubkey: &crate::crypto::AitpVerifyingKey,
) -> Result<(), crate::crypto::CryptoError> {
    crate::envelope::verify_envelope_signature(envelope, sender_pubkey)
}

/// Minimum accepted RSA modulus size, in bits, for third-party
/// (OIDC) verification keys. 2048 bits is the floor NIST
/// SP 800-131A and every mainstream IdP have required for years;
/// anything smaller is a weak-key acceptance bug.
pub const MIN_RSA_MODULUS_BITS: usize = 2048;

/// Whether a base64url-encoded RSA modulus (`n`) meets
/// [`MIN_RSA_MODULUS_BITS`].
///
/// The JWK `n` parameter is the big-endian modulus with no leading zero
/// octets (RFC 7518 §6.3.1), so its decoded byte length maps directly to
/// the key size. We strip any leading zero bytes defensively before
/// measuring, and count bits from the most-significant set bit so a
/// modulus that is one bit short of 2048 is still rejected. Returns
/// `false` if `n` is not valid base64url.
pub fn rsa_modulus_bits_ok(n_b64: &str) -> bool {
    let Ok(bytes) = crate::core::base64url::decode_strict(n_b64) else {
        return false;
    };
    let first_set = bytes.iter().position(|&b| b != 0);
    let Some(first) = first_set else {
        return false; // all-zero / empty modulus
    };
    let significant = &bytes[first..];
    // Bits = 8 * (full bytes after the top one) + bit-width of the top byte.
    let top = significant[0];
    let top_bits = 8 - top.leading_zeros() as usize;
    let bits = top_bits + (significant.len() - 1) * 8;
    bits >= MIN_RSA_MODULUS_BITS
}

#[cfg(test)]
mod rsa_floor_tests {
    use super::rsa_modulus_bits_ok;
    use crate::core::base64url::encode;

    fn n_of_bytes(len: usize, top: u8) -> String {
        let mut v = vec![0xffu8; len];
        v[0] = top;
        encode(&v)
    }

    #[test]
    fn accepts_2048_and_larger() {
        assert!(rsa_modulus_bits_ok(&n_of_bytes(256, 0x80))); // exactly 2048
        assert!(rsa_modulus_bits_ok(&n_of_bytes(384, 0x80))); // 3072
        assert!(rsa_modulus_bits_ok(&n_of_bytes(512, 0x01))); // 4096-ish, low top byte
    }

    #[test]
    fn rejects_below_2048() {
        assert!(!rsa_modulus_bits_ok(&n_of_bytes(128, 0x80))); // 1024
        assert!(!rsa_modulus_bits_ok(&n_of_bytes(255, 0xff))); // 2040 — one byte short
                                                               // 256 bytes but top byte 0x01 => 2041 bits, still short of 2048.
        assert!(!rsa_modulus_bits_ok(&n_of_bytes(256, 0x01)));
    }

    #[test]
    fn ignores_leading_zero_padding() {
        // 0x00 || 256 significant bytes (top 0x80) = 2048-bit modulus.
        let mut v = vec![0u8, 0x80];
        v.extend(std::iter::repeat_n(0xffu8, 255));
        assert!(rsa_modulus_bits_ok(&encode(&v)));
    }

    #[test]
    fn rejects_garbage_and_empty() {
        assert!(!rsa_modulus_bits_ok("!!!not-base64!!!"));
        assert!(!rsa_modulus_bits_ok(""));
        assert!(!rsa_modulus_bits_ok(&encode(&[0u8; 300])));
    }
}
