//! HTTP client configuration: connection pool + TLS knobs.
//!
//! Single-shot config struct used by both [`crate::ManifestFetcher`] and
//! [`crate::JwksFetcher`] via `with_client_config`. The knobs map directly
//! to `reqwest::ClientBuilder` settings; the wrapper exists so callers
//! can configure once and pass to multiple fetchers without depending on
//! `reqwest` at the API surface.
//!
//! # Examples
//!
//! ```rust,ignore
//! use aitp_transport_http::{ClientConfig, ManifestFetcher};
//! use std::time::Duration;
//!
//! let cfg = ClientConfig::default()
//!     .with_pool_idle_timeout(Duration::from_secs(90))
//!     .with_pool_max_idle_per_host(8)
//!     .with_tcp_keepalive(Duration::from_secs(60))
//!     .with_extra_root_cert_pem(my_ca_pem);
//!
//! let fetcher = ManifestFetcher::new().with_client_config(cfg);
//! ```

use std::time::Duration;

/// Combined connection-pool and TLS configuration for outbound HTTP.
///
/// Default-constructed [`ClientConfig`] preserves rc.1 behavior:
/// reqwest's default pool, system root CAs, no certificate pinning.
/// Each `with_*` builder method opts into a non-default setting.
#[derive(Debug, Default, Clone)]
pub struct ClientConfig {
    pool_idle_timeout: Option<Duration>,
    pool_max_idle_per_host: Option<usize>,
    tcp_keepalive: Option<Duration>,
    extra_root_cert_pems: Vec<Vec<u8>>,
    use_only_extra_roots: bool,
    #[cfg(feature = "client-spki-pinning")]
    spki_pins: Vec<crate::tls_pinning::SpkiHash>,
}

impl ClientConfig {
    /// Idle connections in the pool are evicted after this duration.
    /// Default: reqwest's internal default (typically 90 s).
    pub fn with_pool_idle_timeout(mut self, d: Duration) -> Self {
        self.pool_idle_timeout = Some(d);
        self
    }

    /// Maximum idle connections per host kept in the pool. Set lower
    /// when many distinct hosts share the same client.
    pub fn with_pool_max_idle_per_host(mut self, n: usize) -> Self {
        self.pool_max_idle_per_host = Some(n);
        self
    }

    /// TCP keep-alive interval. Useful behind LBs that drop idle
    /// connections silently.
    pub fn with_tcp_keepalive(mut self, d: Duration) -> Self {
        self.tcp_keepalive = Some(d);
        self
    }

    /// Add an extra trust-root PEM. The blob may contain one or more
    /// `-----BEGIN CERTIFICATE-----` blocks. Multiple calls accumulate.
    /// By default these roots are added *alongside* the OS roots; call
    /// [`Self::trust_only_extra_roots`] to suppress the OS roots and
    /// trust ONLY the provided ones (pinned-CA deployments).
    pub fn with_extra_root_cert_pem(mut self, pem: impl Into<Vec<u8>>) -> Self {
        self.extra_root_cert_pems.push(pem.into());
        self
    }

    /// Disable the OS / built-in root certificate stores so only the
    /// roots added via [`Self::with_extra_root_cert_pem`] are trusted.
    /// Calling this without any extra roots will fail every TLS
    /// handshake — that's the point.
    pub fn trust_only_extra_roots(mut self) -> Self {
        self.use_only_extra_roots = true;
        self
    }

    /// Pin a server end-entity public key by SHA-256(SPKI). Once at
    /// least one pin is registered, the outbound HTTPS client
    /// **only** accepts servers whose end-entity certificate's
    /// `SubjectPublicKeyInfo` SHA-256 hash matches one of the pins.
    /// All other certificates — even with valid CA chains — are
    /// rejected.
    ///
    /// Multiple calls accumulate; rotating a key requires rolling
    /// the pin set forward (add the new pin, then remove the old).
    ///
    /// Requires the `client-spki-pinning` feature on
    /// `aitp-transport-http`. See
    /// [`crate::tls_pinning`] for the threat model and how to
    /// compute pins from an `openssl x509` command line.
    #[cfg(feature = "client-spki-pinning")]
    pub fn with_spki_pin(mut self, pin: crate::tls_pinning::SpkiHash) -> Self {
        self.spki_pins.push(pin);
        self
    }

    /// Apply this configuration to a fresh `reqwest::ClientBuilder`.
    /// Crate-internal — fetchers call this when constructing their
    /// underlying client.
    pub(crate) fn apply(self, mut b: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
        if let Some(d) = self.pool_idle_timeout {
            b = b.pool_idle_timeout(d);
        }
        if let Some(n) = self.pool_max_idle_per_host {
            b = b.pool_max_idle_per_host(n);
        }
        if let Some(d) = self.tcp_keepalive {
            b = b.tcp_keepalive(d);
        }
        if self.use_only_extra_roots {
            b = b.tls_built_in_root_certs(false);
        }
        for pem in self.extra_root_cert_pems {
            // reqwest::tls::Certificate::from_pem returns Result; we
            // log+skip a malformed PEM rather than panicking the
            // builder. This mirrors how operators usually want config
            // errors surfaced — at startup, with a tracing event, not
            // by aborting the process.
            match reqwest::tls::Certificate::from_pem(&pem) {
                Ok(cert) => {
                    b = b.add_root_certificate(cert);
                }
                Err(e) => {
                    tracing::warn!(error = %e, "skipping malformed root CA PEM");
                }
            }
        }
        #[cfg(feature = "client-spki-pinning")]
        if !self.spki_pins.is_empty() {
            // SPKI pinning fully replaces WebPKI verification. The
            // root-CA list configured above is irrelevant once a pin
            // is registered: only certs whose SPKI SHA-256 is in the
            // pin list are accepted.
            let tls = crate::tls_pinning::build_pinning_client_config(self.spki_pins);
            b = b.use_preconfigured_tls(tls);
        }
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_lossless() {
        // Default ClientConfig::apply should not break a default builder.
        let cfg = ClientConfig::default();
        let _b = cfg.apply(reqwest::Client::builder());
    }

    #[test]
    fn applies_pool_knobs() {
        let cfg = ClientConfig::default()
            .with_pool_idle_timeout(Duration::from_secs(30))
            .with_pool_max_idle_per_host(4)
            .with_tcp_keepalive(Duration::from_secs(45));
        let b = cfg.apply(reqwest::Client::builder());
        let client = b.build().unwrap();
        let _ = client; // smoke check
    }

    #[test]
    fn malformed_pem_does_not_panic() {
        let cfg = ClientConfig::default().with_extra_root_cert_pem(b"not a cert".to_vec());
        let b = cfg.apply(reqwest::Client::builder());
        let _ = b.build().unwrap();
    }
}
