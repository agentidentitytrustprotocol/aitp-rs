//! Outbound-fetch host guard: SSRF defense for peer-derived URLs.
//!
//! Several client fetch paths in this crate GET a URL whose host the
//! *peer* controls (`peer_origin` for `/.well-known/aitp-manifest`,
//! issuer hosts for `/.well-known/aitp-keys`). Without a guard, a
//! peer origin can steer those GETs at internal infrastructure — cloud
//! metadata services (`169.254.169.254`), RFC 1918 hosts, loopback
//! daemons — a server-side request forgery (SSRF) pattern.
//!
//! [`HostGuard`] classifies every address a URL's host resolves to and
//! applies a [`GuardMode`]:
//!
//! - Addresses no legitimate AITP peer can occupy — unspecified,
//!   broadcast, multicast, and link-local (which includes the cloud
//!   metadata range) — are **always rejected** (except under
//!   [`GuardMode::AllowAll`]).
//! - *Private* addresses (loopback, RFC 1918, CGNAT `100.64/10`, IPv6
//!   unique-local) are rejected by the default mode
//!   ([`GuardMode::DenyPrivate`]). Intranet agent-to-agent deployments
//!   opt in to [`GuardMode::WarnPrivate`] (allow with a warning) with
//!   `HostGuard::new(GuardMode::WarnPrivate)`.
//!
//! # Loopback
//!
//! [`HostGuard::allow_loopback_dangerous`] admits loopback addresses
//! (`127.0.0.0/8`, `::1`) and only those, whatever the mode; the other
//! private ranges still follow the mode. The fetchers' local-development
//! switch (`with_insecure_localhost_dangerous` on
//! [`ManifestFetcher`](crate::transport::ManifestFetcher),
//! [`RevocationFetcher`](crate::transport::RevocationFetcher) and
//! [`InitiatorConfig`](crate::facade::InitiatorConfig)) applies the same
//! loopback allowance to the guard it uses, so a demo on
//! `http://localhost` needs that one opt-in.
//!
//! The vetted addresses are returned so callers can **pin** them into
//! the HTTP client (`reqwest::ClientBuilder::resolve_to_addrs`),
//! closing the DNS-rebinding TOCTOU window between this check and the
//! actual connection: the connection can only go to an address that
//! passed classification.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tracing::warn;
use url::{Host, Url};

/// How the guard treats *private* (but not always-forbidden) addresses.
///
/// See the [module docs](self) for the address classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum GuardMode {
    /// Reject always-forbidden ranges; log a warning for private
    /// ranges but allow the fetch. For intranet deployments whose peers
    /// live on private addresses.
    WarnPrivate,
    /// Reject always-forbidden and private ranges. The default mode.
    DenyPrivate,
    /// No address checks at all. For air-gapped/test networks where
    /// the operator explicitly accepts fetches to any address.
    AllowAll,
}

/// SSRF guard for outbound fetches whose URL a peer controls.
#[derive(Debug, Clone)]
pub struct HostGuard {
    mode: GuardMode,
    allow_loopback: bool,
}

impl Default for HostGuard {
    /// [`GuardMode::DenyPrivate`], no loopback allowance — see the
    /// module docs.
    ///
    /// ```
    /// use aitp::transport::net_guard::{HostGuard, GuardMode};
    ///
    /// assert_eq!(HostGuard::default().mode(), GuardMode::DenyPrivate);
    /// ```
    fn default() -> Self {
        Self::new(GuardMode::DenyPrivate)
    }
}

/// Errors from [`HostGuard::resolve_checked`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HostGuardError {
    /// The URL has no host component.
    #[error("URL has no host component")]
    MissingHost,
    /// The host is, or resolves to, an address in a forbidden range.
    #[error("host `{host}` resolves to forbidden address {addr} ({class})")]
    ForbiddenAddress {
        /// Host component of the guarded URL.
        host: String,
        /// The offending resolved address.
        addr: IpAddr,
        /// Address class that triggered the rejection (e.g.
        /// `link-local`, `rfc1918`).
        class: &'static str,
    },
    /// DNS resolution failed (transient — callers may retry).
    #[error("DNS resolution failed for `{host}`: {message}")]
    Resolution {
        /// Host component of the guarded URL.
        host: String,
        /// Underlying resolver error text.
        message: String,
    },
    /// DNS resolution succeeded but returned no addresses.
    #[error("DNS returned no addresses for `{host}`")]
    NoAddresses {
        /// Host component of the guarded URL.
        host: String,
    },
}

impl HostGuardError {
    /// Whether the error is transient (worth retrying). Only DNS
    /// resolution failures are; classification rejections are not.
    pub fn is_transient(&self) -> bool {
        matches!(self, HostGuardError::Resolution { .. })
    }
}

/// Classification of a single address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddrClass {
    /// Globally routable (or at least not a known-internal range).
    Public,
    /// No legitimate AITP peer can live here; rejected in every mode
    /// except [`GuardMode::AllowAll`].
    Forbidden(&'static str),
    /// Legitimate on intranets; mode-dependent.
    Private(&'static str),
}

fn classify_v4(ip: Ipv4Addr) -> AddrClass {
    if ip.is_unspecified() {
        AddrClass::Forbidden("unspecified")
    } else if ip.is_broadcast() {
        AddrClass::Forbidden("broadcast")
    } else if ip.is_multicast() {
        AddrClass::Forbidden("multicast")
    } else if ip.is_link_local() {
        // 169.254.0.0/16 — includes cloud metadata services.
        AddrClass::Forbidden("link-local")
    } else if ip.is_loopback() {
        AddrClass::Private("loopback")
    } else if ip.is_private() {
        AddrClass::Private("rfc1918")
    } else if is_cgnat(ip) {
        AddrClass::Private("cgnat")
    } else {
        AddrClass::Public
    }
}

/// 100.64.0.0/10 (RFC 6598 shared address space / CGNAT).
/// `Ipv4Addr::is_shared` is not yet stable on our MSRV.
fn is_cgnat(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 100 && (o[1] & 0b1100_0000) == 0b0100_0000
}

fn classify_v6(ip: Ipv6Addr) -> AddrClass {
    // An IPv4-mapped address (`::ffff:a.b.c.d`) is the v4 address in
    // disguise — classify the embedded v4 so `::ffff:169.254.169.254`
    // cannot smuggle past the v6 branch.
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return classify_v4(mapped);
    }
    if ip.is_unspecified() {
        AddrClass::Forbidden("unspecified")
    } else if ip.is_multicast() {
        AddrClass::Forbidden("multicast")
    } else if (ip.segments()[0] & 0xffc0) == 0xfe80 {
        AddrClass::Forbidden("link-local")
    } else if ip.is_loopback() {
        AddrClass::Private("loopback")
    } else if (ip.segments()[0] & 0xfe00) == 0xfc00 {
        // fc00::/7 — unique local addresses.
        AddrClass::Private("unique-local")
    } else {
        AddrClass::Public
    }
}

fn classify(ip: IpAddr) -> AddrClass {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

impl HostGuard {
    /// Build a guard with an explicit mode and no loopback allowance.
    pub fn new(mode: GuardMode) -> Self {
        Self {
            mode,
            allow_loopback: false,
        }
    }

    /// Admit loopback addresses (`127.0.0.0/8`, `::1`) in every mode.
    /// The other private ranges still follow the mode. For local
    /// development and tests whose peers run on the same host.
    ///
    /// ```
    /// use aitp::transport::net_guard::{HostGuard, GuardMode};
    ///
    /// let guard = HostGuard::default().allow_loopback_dangerous();
    /// assert_eq!(guard.mode(), GuardMode::DenyPrivate);
    /// ```
    pub fn allow_loopback_dangerous(mut self) -> Self {
        self.allow_loopback = true;
        self
    }

    /// The configured mode.
    pub fn mode(&self) -> GuardMode {
        self.mode
    }

    /// Resolve `url`'s host and classify **every** returned address
    /// (one answer can mix public and internal records, so one
    /// rejected address rejects the whole set). On success, returns
    /// the full vetted address list — pin it into the HTTP client via
    /// `resolve_to_addrs` so the connection cannot be re-resolved to
    /// an unchecked address (DNS rebinding).
    pub async fn resolve_checked(&self, url: &Url) -> Result<Vec<SocketAddr>, HostGuardError> {
        self.resolve_checked_with(url, false).await
    }

    /// [`Self::resolve_checked`], also admitting loopback addresses when
    /// `allow_loopback` is set. The fetchers' insecure-localhost switch
    /// passes it here.
    pub(crate) async fn resolve_checked_with(
        &self,
        url: &Url,
        allow_loopback: bool,
    ) -> Result<Vec<SocketAddr>, HostGuardError> {
        let allow_loopback = allow_loopback || self.allow_loopback;
        let host = url.host().ok_or(HostGuardError::MissingHost)?;
        // `Url::port_or_known_default` knows http/https; AITP fetches
        // are always one of those, but fall back to 443 defensively.
        let port = url.port_or_known_default().unwrap_or(443);

        let addrs: Vec<SocketAddr> = match host {
            Host::Ipv4(ip) => vec![SocketAddr::new(IpAddr::V4(ip), port)],
            Host::Ipv6(ip) => vec![SocketAddr::new(IpAddr::V6(ip), port)],
            Host::Domain(domain) => tokio::net::lookup_host((domain, port))
                .await
                .map_err(|e| HostGuardError::Resolution {
                    host: domain.to_string(),
                    message: e.to_string(),
                })?
                .collect(),
        };
        if addrs.is_empty() {
            return Err(HostGuardError::NoAddresses {
                host: host.to_string(),
            });
        }
        if self.mode == GuardMode::AllowAll {
            return Ok(addrs);
        }
        for sa in &addrs {
            match classify(sa.ip()) {
                AddrClass::Public => {}
                AddrClass::Private("loopback") if allow_loopback => {}
                AddrClass::Forbidden(class) => {
                    return Err(HostGuardError::ForbiddenAddress {
                        host: host.to_string(),
                        addr: sa.ip(),
                        class,
                    });
                }
                AddrClass::Private(class) => match self.mode {
                    GuardMode::DenyPrivate => {
                        return Err(HostGuardError::ForbiddenAddress {
                            host: host.to_string(),
                            addr: sa.ip(),
                            class,
                        });
                    }
                    GuardMode::WarnPrivate => {
                        warn!(
                            host = %host,
                            addr = %sa.ip(),
                            class,
                            "outbound fetch to a private address allowed by \
                             GuardMode::WarnPrivate"
                        );
                    }
                    // Handled by the early return above.
                    GuardMode::AllowAll => {}
                },
            }
        }
        Ok(addrs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> AddrClass {
        classify(IpAddr::V4(s.parse().unwrap()))
    }
    fn v6(s: &str) -> AddrClass {
        classify(IpAddr::V6(s.parse().unwrap()))
    }

    #[test]
    fn forbidden_classes() {
        assert_eq!(v4("0.0.0.0"), AddrClass::Forbidden("unspecified"));
        assert_eq!(v4("255.255.255.255"), AddrClass::Forbidden("broadcast"));
        assert_eq!(v4("224.0.0.1"), AddrClass::Forbidden("multicast"));
        // The classic cloud-metadata SSRF target.
        assert_eq!(v4("169.254.169.254"), AddrClass::Forbidden("link-local"));
        assert_eq!(v6("::"), AddrClass::Forbidden("unspecified"));
        assert_eq!(v6("ff02::1"), AddrClass::Forbidden("multicast"));
        assert_eq!(v6("fe80::1"), AddrClass::Forbidden("link-local"));
    }

    #[test]
    fn private_classes() {
        assert_eq!(v4("127.0.0.1"), AddrClass::Private("loopback"));
        assert_eq!(v4("10.1.2.3"), AddrClass::Private("rfc1918"));
        assert_eq!(v4("172.16.0.1"), AddrClass::Private("rfc1918"));
        assert_eq!(v4("192.168.1.1"), AddrClass::Private("rfc1918"));
        assert_eq!(v4("100.64.0.1"), AddrClass::Private("cgnat"));
        assert_eq!(v4("100.127.255.255"), AddrClass::Private("cgnat"));
        assert_eq!(v6("::1"), AddrClass::Private("loopback"));
        assert_eq!(v6("fd12:3456::1"), AddrClass::Private("unique-local"));
    }

    #[test]
    fn public_classes() {
        assert_eq!(v4("93.184.216.34"), AddrClass::Public);
        assert_eq!(v4("100.128.0.1"), AddrClass::Public); // just past CGNAT
        assert_eq!(v4("172.32.0.1"), AddrClass::Public); // just past 172.16/12
        assert_eq!(v6("2606:2800:220:1::1"), AddrClass::Public);
    }

    #[test]
    fn v4_mapped_v6_cannot_smuggle() {
        assert_eq!(
            v6("::ffff:169.254.169.254"),
            AddrClass::Forbidden("link-local")
        );
        assert_eq!(v6("::ffff:10.0.0.1"), AddrClass::Private("rfc1918"));
    }

    fn warn() -> HostGuard {
        HostGuard::new(GuardMode::WarnPrivate)
    }

    #[test]
    fn default_is_deny_private() {
        let guard = HostGuard::default();
        assert_eq!(guard.mode(), GuardMode::DenyPrivate);
        assert!(!guard.allow_loopback);
    }

    #[tokio::test]
    async fn ip_literal_forbidden_is_rejected_in_all_checking_modes() {
        for guard in [
            HostGuard::default(),
            warn(),
            HostGuard::default().allow_loopback_dangerous(),
        ] {
            let url = Url::parse("https://169.254.169.254/").unwrap();
            let err = guard.resolve_checked(&url).await.unwrap_err();
            assert!(matches!(err, HostGuardError::ForbiddenAddress { .. }));
            assert!(!err.is_transient());
        }
    }

    #[tokio::test]
    async fn ip_literal_forbidden_is_allowed_under_allow_all() {
        let guard = HostGuard::new(GuardMode::AllowAll);
        let url = Url::parse("https://169.254.169.254/").unwrap();
        let addrs = guard.resolve_checked(&url).await.unwrap();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].port(), 443);
    }

    #[tokio::test]
    async fn private_literal_mode_dependent() {
        let url = Url::parse("http://10.0.0.7:8080/x").unwrap();
        // WarnPrivate: allowed (with a warning).
        let addrs = warn().resolve_checked(&url).await.unwrap();
        assert_eq!(addrs, vec!["10.0.0.7:8080".parse().unwrap()]);
        // DenyPrivate (the default): rejected.
        let err = HostGuard::default()
            .resolve_checked(&url)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            HostGuardError::ForbiddenAddress {
                class: "rfc1918",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn localhost_domain_resolves_to_loopback_and_follows_mode() {
        let url = Url::parse("https://localhost:9443/").unwrap();
        // WarnPrivate allows...
        let addrs = warn().resolve_checked(&url).await.unwrap();
        assert!(!addrs.is_empty());
        assert!(addrs.iter().all(|a| a.port() == 9443));
        // ...DenyPrivate rejects.
        let err = HostGuard::default()
            .resolve_checked(&url)
            .await
            .unwrap_err();
        assert!(matches!(err, HostGuardError::ForbiddenAddress { .. }));
    }

    #[tokio::test]
    async fn loopback_allowance_admits_loopback_only() {
        let guard = HostGuard::default().allow_loopback_dangerous();
        for url in [
            "https://127.0.0.1:9443/",
            "https://[::1]:9443/",
            "https://localhost:9443/",
        ] {
            let url = Url::parse(url).unwrap();
            let addrs = guard.resolve_checked(&url).await.unwrap();
            assert!(addrs.iter().all(|a| a.ip().is_loopback()));
        }
        for (url, class) in [
            ("https://10.0.0.7/", "rfc1918"),
            ("https://192.168.1.1/", "rfc1918"),
            ("https://100.64.0.1/", "cgnat"),
            ("https://[fd12:3456::1]/", "unique-local"),
            ("https://169.254.169.254/", "link-local"),
        ] {
            let url = Url::parse(url).unwrap();
            let err = guard.resolve_checked(&url).await.unwrap_err();
            assert!(
                matches!(err, HostGuardError::ForbiddenAddress { class: c, .. } if c == class),
                "{url}: {err:?}"
            );
        }
        // The crate-internal per-call allowance behaves the same.
        let url = Url::parse("https://127.0.0.1/").unwrap();
        HostGuard::default()
            .resolve_checked_with(&url, true)
            .await
            .unwrap();
        HostGuard::default()
            .resolve_checked_with(&url, false)
            .await
            .unwrap_err();
    }
}
