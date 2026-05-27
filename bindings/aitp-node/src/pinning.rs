//! SHA-256 SPKI certificate pinning — Node SDK.
//!
//! Gated by `experimental-pinning`. Thin (no rustls, no transport): just
//! the hash primitive plus a list-membership check. Wire into your own
//! HTTP client (undici, fetch) via its `checkServerIdentity` /
//! `tlsSocket.getPeerCertificate()` hook.

use napi::bindgen_prelude::*;
use napi_derive::napi;
use sha2::{Digest, Sha256};

/// Compute the SHA-256 SPKI hash for an X.509 DER certificate. Returns
/// a 32-byte Buffer. Throws if `certDer` is not a parseable certificate.
#[napi]
pub fn compute_spki_hash(cert_der: Buffer) -> Result<Buffer> {
    let bytes = compute_inner(&cert_der)?;
    Ok(Buffer::from(bytes.to_vec()))
}

fn compute_inner(cert_der: &[u8]) -> Result<[u8; 32]> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der)
        .map_err(|e| Error::from_reason(format!("invalid X.509 certificate (DER): {e}")))?;
    let mut hasher = Sha256::new();
    hasher.update(cert.tbs_certificate.subject_pki.raw);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

/// Holds a list of 32-byte SPKI pins. `isPinned(certDer)` returns true
/// iff the cert's SPKI hash is in the list.
#[napi]
pub struct SpkiPinVerifier {
    pins: Vec<[u8; 32]>,
}

#[napi]
impl SpkiPinVerifier {
    /// Construct from an array of 32-byte Buffers. Throws if any pin is
    /// not exactly 32 bytes.
    #[napi(constructor)]
    pub fn new(pins: Vec<Buffer>) -> Result<Self> {
        let mut out = Vec::with_capacity(pins.len());
        for (i, p) in pins.into_iter().enumerate() {
            let arr: [u8; 32] = p.as_ref().try_into().map_err(|_| {
                Error::from_reason(format!(
                    "pin at index {i} must be exactly 32 bytes (got {})",
                    p.len()
                ))
            })?;
            out.push(arr);
        }
        Ok(Self { pins: out })
    }

    /// Returns true iff the SPKI hash of `certDer` is in the pin list.
    #[napi]
    pub fn is_pinned(&self, cert_der: Buffer) -> Result<bool> {
        let h = compute_inner(&cert_der)?;
        Ok(self.pins.iter().any(|p| p == &h))
    }

    /// Number of pins currently held.
    #[napi(getter)]
    pub fn len(&self) -> u32 {
        self.pins.len() as u32
    }
}
