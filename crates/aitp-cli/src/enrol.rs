//! Wire format of the interop peer's key registration (`aitp enroll` /
//! `aitp serve --interop`), shared by client and server.
//!
//! Enrolment is a registration step, not an AITP identity verification
//! mode: RFC-AITP-0002 §3.2 leaves how `pinned_keys` gets populated to
//! operator policy. Like uploading an SSH key, the caller proves it
//! holds the private key for an AID by signing a single-use challenge;
//! the operator's policy then writes the key into the peer's pinned-key
//! store. Handshakes afterwards verify against that store as usual.
//! None of this is RFC-AITP-0002 §3.4 pinned admission, and the error
//! codes are this endpoint's own (lowercase, unlike AITP's registry).
//!
//! ```text
//! POST /enroll/challenge  {}                         -> {nonce, peer_aid, expires_at}
//! POST /enroll            {aid, nonce, signature}    -> {aid, expires_at, capabilities}
//! ```
//!
//! `signature` is the AID key's JCS-style signature (`sign_jcs`) over
//! `SHA-256("aitp-interop-enrol-v1" 0x00 aid 0x00 peer_aid 0x00 nonce)`,
//! with `nonce` the 16 raw challenge bytes. Binding the peer's AID stops
//! a signature made for one peer being replayed at another.

use aitp::core::{base64url, Aid};
use aitp::crypto::{AitpSigningKey, AitpVerifyingKey, Digest32, Signature};
use serde::{Deserialize, Serialize};

/// Challenge route.
pub(crate) const CHALLENGE_PATH: &str = "/enroll/challenge";
/// Enrolment route.
pub(crate) const ENROLL_PATH: &str = "/enroll";
/// Domain separator for the signed digest.
const DOMAIN: &[u8] = b"aitp-interop-enrol-v1";
/// Raw challenge length (as RFC-AITP-0002 §3.1's `pop_nonce`).
pub(crate) const NONCE_LEN: usize = 16;

/// `POST /enroll/challenge` response.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Challenge {
    /// 16 random bytes, base64url without padding.
    pub nonce: String,
    /// The peer's AID, which the signature binds.
    pub peer_aid: Aid,
    /// Last second (Unix) at which the nonce is accepted.
    pub expires_at: i64,
}

/// `POST /enroll` request.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnrollRequest {
    /// The AID to enrol; its key verifies `signature`.
    pub aid: String,
    /// The challenge nonce, as received.
    pub nonce: String,
    /// Signature over [`signing_digest`].
    pub signature: String,
}

/// `POST /enroll` success response.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Enrolled {
    /// The enrolled AID.
    pub aid: Aid,
    /// When the enrolment lapses (Unix seconds).
    pub expires_at: i64,
    /// What a handshake from this AID may be granted.
    pub capabilities: Vec<String>,
}

/// Error body for every non-2xx enrolment response.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ErrorBody {
    /// One of `bad_request`, `bad_signature`, `bad_nonce`,
    /// `rate_limited`, `enrol_busy`.
    pub error: String,
    /// Human-readable detail.
    pub message: String,
}

/// A request that parsed and decoded, ready for the nonce and signature
/// checks.
#[cfg_attr(not(feature = "serve"), allow(dead_code))]
pub(crate) struct ParsedEnroll {
    pub aid: Aid,
    pub key: AitpVerifyingKey,
    pub nonce: [u8; NONCE_LEN],
    pub signature: Signature,
}

/// Parse and decode a `POST /enroll` body. Never panics on any input
/// (fuzzed by `fuzz_targets/interop_enroll.rs`).
#[cfg_attr(not(feature = "serve"), allow(dead_code))]
pub(crate) fn parse_enroll(body: &[u8]) -> Result<ParsedEnroll, String> {
    let req: EnrollRequest =
        serde_json::from_slice(body).map_err(|e| format!("invalid body: {e}"))?;
    let aid = Aid::parse(&req.aid).map_err(|e| format!("aid: {e}"))?;
    let key = AitpVerifyingKey::from_aid(&aid).map_err(|e| format!("aid: {e}"))?;
    let nonce = base64url::decode_strict_exact::<NONCE_LEN>(&req.nonce)
        .map_err(|_| "nonce: not 16 base64url-encoded bytes")?;
    let signature = Signature::parse(&req.signature).map_err(|e| format!("signature: {e}"))?;
    Ok(ParsedEnroll {
        aid,
        key,
        nonce,
        signature,
    })
}

/// The digest an enrolment signature covers.
pub(crate) fn signing_digest(aid: &Aid, peer_aid: &Aid, nonce: &[u8; NONCE_LEN]) -> Digest32 {
    let mut input = Vec::with_capacity(DOMAIN.len() + 160);
    input.extend_from_slice(DOMAIN);
    input.push(0);
    input.extend_from_slice(aid.as_str().as_bytes());
    input.push(0);
    input.extend_from_slice(peer_aid.as_str().as_bytes());
    input.push(0);
    input.extend_from_slice(nonce);
    Digest32::sha256(&input)
}

/// Sign an enrolment for `key` against `challenge`.
#[cfg_attr(not(feature = "http-client"), allow(dead_code))]
pub(crate) fn sign_enroll(
    key: &AitpSigningKey,
    challenge: &Challenge,
) -> Result<EnrollRequest, String> {
    let nonce = base64url::decode_strict_exact::<NONCE_LEN>(&challenge.nonce)
        .map_err(|_| "peer sent a malformed challenge nonce")?;
    let digest = signing_digest(key.aid(), &challenge.peer_aid, &nonce);
    Ok(EnrollRequest {
        aid: key.aid().to_string(),
        nonce: challenge.nonce.clone(),
        signature: key.sign_jcs(&digest).into_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn challenge(peer: &AitpSigningKey) -> Challenge {
        Challenge {
            nonce: base64url::encode(&[7u8; NONCE_LEN]),
            peer_aid: peer.aid().clone(),
            expires_at: 0,
        }
    }

    #[test]
    fn signed_request_parses_and_verifies() {
        let peer = AitpSigningKey::from_seed(&[1; 32]);
        for key in [
            AitpSigningKey::from_seed(&[2; 32]),
            AitpSigningKey::from_p256_seed(&[3; 32]).unwrap(),
        ] {
            let req = sign_enroll(&key, &challenge(&peer)).unwrap();
            let parsed = parse_enroll(&serde_json::to_vec(&req).unwrap()).unwrap();
            let digest = signing_digest(&parsed.aid, peer.aid(), &parsed.nonce);
            parsed.key.verify_jcs(&digest, &parsed.signature).unwrap();
        }
    }

    #[test]
    fn signature_is_bound_to_the_peer() {
        let peer = AitpSigningKey::from_seed(&[1; 32]);
        let other = AitpSigningKey::from_seed(&[9; 32]);
        let key = AitpSigningKey::from_seed(&[2; 32]);
        let req = sign_enroll(&key, &challenge(&peer)).unwrap();
        let parsed = parse_enroll(&serde_json::to_vec(&req).unwrap()).unwrap();
        let digest = signing_digest(&parsed.aid, other.aid(), &parsed.nonce);
        assert!(parsed.key.verify_jcs(&digest, &parsed.signature).is_err());
    }

    #[test]
    fn malformed_bodies_are_rejected() {
        for body in [
            &b""[..],
            b"{}",
            b"[]",
            br#"{"aid":"x","nonce":"AAAAAAAAAAAAAAAAAAAAAA","signature":"x"}"#,
            br#"{"aid":"aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik","nonce":"short","signature":"x"}"#,
            br#"{"aid":"aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik","nonce":"AAAAAAAAAAAAAAAAAAAAAA","signature":"x","extra":1}"#,
        ] {
            assert!(parse_enroll(body).is_err(), "{}", String::from_utf8_lossy(body));
        }
    }
}
