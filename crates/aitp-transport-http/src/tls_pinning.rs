//! SHA-256 SPKI certificate pinning for outbound HTTPS.
//!
//! Air-gapped deployments and high-security paths sometimes need the
//! outbound client to refuse any TLS peer whose end-entity certificate
//! does not present a known `SubjectPublicKeyInfo` hash. This is the
//! pinning model defined by [RFC 7469] (HPKP) — the public-key bytes
//! are stable across cert rotations as long as the operator re-uses
//! the same keypair, so the pin survives routine cert renewal.
//!
//! Use via [`crate::ClientConfig::with_spki_pin`].
//!
//! # Threat model
//!
//! When at least one pin is registered, [`SpkiPinVerifier`] **replaces
//! the WebPKI chain validator** but **still requires the server to
//! prove possession of the pinned key**. The verifier:
//!
//! - Accepts a presented end-entity cert iff its SPKI SHA-256 is in
//!   the pin list. There is no fallback to the OS root store.
//! - Delegates the TLS 1.2 / 1.3 handshake signature verification to
//!   the active rustls `CryptoProvider`. This is what proves the
//!   peer holds the cert's private key, not merely a copy of the
//!   public cert.
//!
//! Skipping signature verification is unsafe — a public certificate
//! can be captured by anyone, so without the handshake-sig check,
//! pinning would only verify that the attacker possesses the same
//! public bytes anyone could fetch.
//!
//! - This protects against rogue CAs and MITM via stolen
//!   intermediates: even a valid chain to a trusted root is rejected
//!   if the leaf's SPKI is not pinned.
//! - It does **not** check hostname or expiry; the operator is
//!   accepting that the pinned key is the authoritative identifier.
//!   Rotate pins out of band when keys rotate.
//!
//! # SPKI hash
//!
//! The SPKI is the DER-encoded `SubjectPublicKeyInfo` field exactly
//! as it appears in the certificate's TBS structure. The pin is
//! `SHA-256(SPKI_DER)`, 32 bytes. To compute one for a server you
//! control:
//!
//! ```bash
//! openssl x509 -in server.crt -pubkey -noout \
//!   | openssl pkey -pubin -outform DER \
//!   | openssl dgst -sha256 -binary \
//!   | xxd -p -c 64
//! ```
//!
//! [RFC 7469]: https://www.rfc-editor.org/rfc/rfc7469

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};
use sha2::{Digest, Sha256};

/// 32-byte SHA-256 hash of a `SubjectPublicKeyInfo` DER encoding.
pub type SpkiHash = [u8; 32];

/// Compute the SPKI hash for an X.509 certificate (DER bytes).
///
/// Returns `None` if `cert_der` is not a parseable certificate.
pub fn compute_spki_hash(cert_der: &[u8]) -> Option<SpkiHash> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der).ok()?;
    let spki = cert.tbs_certificate.subject_pki.raw;
    let mut hasher = Sha256::new();
    hasher.update(spki);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Some(out)
}

/// Server cert verifier that accepts a peer iff the SHA-256 of the
/// end-entity cert's `SubjectPublicKeyInfo` is present in the pin
/// list **and** the peer proves possession of the pinned key by
/// signing the handshake with the matching private key.
///
/// Construct via [`SpkiPinVerifier::new`] (uses the active rustls
/// `CryptoProvider`'s signature verification algorithms) or
/// [`SpkiPinVerifier::with_provider`] for explicit provider
/// selection. Wire into a [`rustls::ClientConfig`] via
/// `with_custom_certificate_verifier(Arc::new(verifier))`.
#[derive(Debug)]
pub struct SpkiPinVerifier {
    pins: Vec<SpkiHash>,
    /// Signature verification algorithms taken from the rustls
    /// `CryptoProvider`. Used by `verify_tls1{2,3}_signature` to
    /// validate the server's handshake signature.
    algorithms: WebPkiSupportedAlgorithms,
}

impl SpkiPinVerifier {
    /// Build a verifier from a non-empty pin list, using the active
    /// rustls `CryptoProvider` for signature verification.
    ///
    /// If no provider has been installed yet, falls back to
    /// `rustls::crypto::ring::default_provider()`. Either way the
    /// verifier owns a `WebPkiSupportedAlgorithms` snapshot — later
    /// changes to the global provider don't retroactively affect
    /// what this verifier accepts.
    ///
    /// # Panics
    ///
    /// - If `pins` is empty (a pin set that accepts everything is
    ///   almost certainly a misconfiguration).
    pub fn new(pins: Vec<SpkiHash>) -> Self {
        let provider = rustls::crypto::CryptoProvider::get_default()
            .cloned()
            .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()));
        Self::with_provider(pins, &provider)
    }

    /// Like [`Self::new`] but takes the `CryptoProvider` explicitly.
    /// Use when the application installs `aws-lc-rs` or another
    /// non-ring provider and wants the pinning verifier to use the
    /// same set of signature algorithms.
    ///
    /// # Panics
    ///
    /// Panics if `pins` is empty.
    pub fn with_provider(pins: Vec<SpkiHash>, provider: &rustls::crypto::CryptoProvider) -> Self {
        assert!(
            !pins.is_empty(),
            "SpkiPinVerifier requires at least one pin"
        );
        Self {
            pins,
            algorithms: provider.signature_verification_algorithms,
        }
    }

    /// Check whether a given DER cert is pinned.
    pub fn is_pinned(&self, cert_der: &[u8]) -> bool {
        match compute_spki_hash(cert_der) {
            Some(h) => self.pins.iter().any(|p| p == &h),
            None => false,
        }
    }
}

impl ServerCertVerifier for SpkiPinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        if self.is_pinned(end_entity.as_ref()) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(TlsError::General(
                "server certificate SPKI does not match any registered pin".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        // SPKI pinning replaces *chain* validation; the handshake
        // signature still has to verify against the cert's public
        // key, otherwise an attacker who has captured a copy of the
        // (public) cert could complete the handshake without
        // possessing the private key. Delegate to the rustls
        // CryptoProvider's signature verifier.
        verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// Build a `rustls::ClientConfig` whose only verifier is an
/// [`SpkiPinVerifier`].
///
/// reqwest's `use_preconfigured_tls` accepts this config and
/// installs it for outbound HTTPS. Uses the active rustls
/// `CryptoProvider`; falls back to `ring::default_provider()` if
/// none is installed yet (typical when the pinned client is
/// configured before any reqwest call has triggered provider
/// installation). The same provider is used for cipher selection
/// and for the verifier's handshake-signature check, so cipher /
/// signature-algorithm sets stay consistent.
pub fn build_pinning_client_config(pins: Vec<SpkiHash>) -> rustls::ClientConfig {
    let provider = rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()));
    let verifier = Arc::new(SpkiPinVerifier::with_provider(pins, &provider));
    rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("rustls default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth()
}

#[cfg(test)]
mod tests {
    use super::*;

    // A real self-signed Ed25519 cert generated offline with:
    //   openssl req -x509 -newkey ed25519 -nodes -days 1 \
    //     -subj "/CN=pin.test" -keyout /tmp/k.pem -out /tmp/c.pem
    //   openssl x509 -in /tmp/c.pem -outform DER | xxd -p -c 999
    // The cert's not_before is irrelevant here — we don't validate
    // expiry, only the SPKI hash.
    const FIXTURE_CERT_DER_HEX: &str = "3082013a3081eda003020102021464f77ab0daa054338dd276a9ae7956d8bd737740300506032b657030133111300f06035504030c0870696e2e74657374301e170d3236303530373032343032355a170d3236303530383032343032355a30133111300f06035504030c0870696e2e74657374302a300506032b6570032100f84a2a0061babc970403a760a22ff9e1d426910eb85b47a1147ee67a9218499fa3533051301d0603551d0e04160414c31886fa0adbb84e1012080bacdcd4252b0eb648301f0603551d23041830168014c31886fa0adbb84e1012080bacdcd4252b0eb648300f0603551d130101ff040530030101ff300506032b65700341002205344cca62d90cdd042110dd72faa29e8b2cfb97e4f61c8dd8744c073800c4ba51018595b24569a94952cd7e3201df236958fd1a3d0503b85134bcd710c30a";

    // Expected SPKI hash, computed independently with:
    //   openssl x509 -in /tmp/c.pem -pubkey -noout
    //     | openssl pkey -pubin -outform DER
    //     | openssl dgst -sha256 -binary
    //     | xxd -p -c 64
    const FIXTURE_SPKI_HASH_HEX: &str =
        "355aef3223b7c90587664d896722dede429ba20dc1934bf5fbe0000bceb83e17";

    fn fixture_cert_der() -> Vec<u8> {
        (0..FIXTURE_CERT_DER_HEX.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&FIXTURE_CERT_DER_HEX[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn malformed_der_returns_none() {
        assert!(compute_spki_hash(b"not a der cert").is_none());
    }

    #[test]
    fn compute_spki_hash_matches_openssl() {
        // Round-trip a real DER cert through compute_spki_hash and
        // compare against the SHA-256 OpenSSL produces over the
        // SPKI bytes. If x509-parser ever changes how
        // `tbs_certificate.subject_pki.raw` is exposed, this test
        // would catch it.
        let der = fixture_cert_der();
        let computed = compute_spki_hash(&der).expect("parse fixture cert");
        let expected: Vec<u8> = (0..FIXTURE_SPKI_HASH_HEX.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&FIXTURE_SPKI_HASH_HEX[i..i + 2], 16).unwrap())
            .collect();
        assert_eq!(computed.as_slice(), expected.as_slice());
    }

    #[test]
    fn pinned_cert_accepted_unpinned_rejected() {
        let der = fixture_cert_der();
        let correct_pin = compute_spki_hash(&der).unwrap();
        let wrong_pin = [0xAAu8; 32];

        let v_match = SpkiPinVerifier::new(vec![correct_pin]);
        assert!(v_match.is_pinned(&der));

        let v_other = SpkiPinVerifier::new(vec![wrong_pin]);
        assert!(!v_other.is_pinned(&der));
    }

    #[test]
    #[should_panic(expected = "SpkiPinVerifier requires at least one pin")]
    fn empty_pin_list_panics() {
        SpkiPinVerifier::new(Vec::new());
    }

    #[test]
    fn supported_verify_schemes_includes_modern() {
        let v = SpkiPinVerifier::new(vec![[0u8; 32]]);
        let schemes = v.supported_verify_schemes();
        assert!(schemes.contains(&SignatureScheme::ED25519));
        assert!(schemes.contains(&SignatureScheme::ECDSA_NISTP256_SHA256));
    }

    #[test]
    fn unpinned_der_is_rejected() {
        // A non-cert blob → compute_spki_hash returns None → not pinned.
        let v = SpkiPinVerifier::new(vec![[0u8; 32]]);
        assert!(!v.is_pinned(b"random"));
    }

    #[test]
    fn build_client_config_smoke() {
        // Exercise the constructor; we can't drive a TLS handshake
        // here without a CryptoProvider installed in the test
        // process, but constructing the config must not panic.
        let _cfg = build_pinning_client_config(vec![[0u8; 32]]);
    }
}
