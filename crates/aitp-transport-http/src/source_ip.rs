//! The RFC-AITP-0009 §3.1 trusted-proxy rule for finding the client
//! address behind a reverse proxy. Needs only `http` 1.x (feature
//! `source-ip`), so a service on another HTTP stack can key its own rate
//! limits the same way `HandshakeServer` does without pulling in axum.

use std::net::{IpAddr, SocketAddr};

/// An address or CIDR range of a reverse proxy whose `X-Forwarded-For`
/// and `X-Real-IP` headers [`resolve_source_ip`] (and so `HandshakeServer`) believes
/// (RFC-AITP-0009 §3.1). Parse from `"10.0.0.0/8"`, `"fd00::/8"` or a
/// bare address such as `"127.0.0.1"`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrustedProxy {
    network: IpAddr,
    prefix: u8,
}

/// A [`TrustedProxy`] string that is not an address or CIDR range.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid trusted proxy `{0}`: expected an IP address or CIDR range")]
pub struct TrustedProxyParseError(String);

impl TrustedProxy {
    /// Whether `ip` is inside this range. An IPv4-mapped IPv6 address
    /// is compared as IPv4.
    pub fn contains(&self, ip: IpAddr) -> bool {
        use IpAddr;
        match (self.network, ip.to_canonical()) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                prefix_eq(&net.octets(), &ip.octets(), self.prefix)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                prefix_eq(&net.octets(), &ip.octets(), self.prefix)
            }
            _ => false,
        }
    }
}

fn prefix_eq(a: &[u8], b: &[u8], prefix: u8) -> bool {
    let full = usize::from(prefix / 8);
    let rem = prefix % 8;
    if a[..full] != b[..full] {
        return false;
    }
    rem == 0 || {
        let mask = 0xFFu8 << (8 - rem);
        a[full] & mask == b[full] & mask
    }
}

impl std::str::FromStr for TrustedProxy {
    type Err = TrustedProxyParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || TrustedProxyParseError(s.to_string());
        let (addr, prefix) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let network: IpAddr = addr.parse().map_err(|_| err())?;
        let network = network.to_canonical();
        let max = if network.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            None => max,
            Some(p) => match p.parse::<u8>() {
                Ok(p) if p <= max => p,
                _ => return Err(err()),
            },
        };
        Ok(Self { network, prefix })
    }
}

/// The client address behind `peer` per RFC-AITP-0009 §3.1, for keying
/// rate limits. Usable from any HTTP stack that has the socket peer and
/// an [`http::HeaderMap`].
///
/// Forwarding headers are read only when `peer` is inside
/// `trusted_proxies`. The client is then the rightmost
/// `X-Forwarded-For` hop (all header lines, in order) that is not
/// itself a trusted proxy, else `X-Real-IP`, else `peer`. Anything a
/// client prepends to `X-Forwarded-For` is therefore ignored.
///
/// A hop is an IP address, optionally with a port (`1.2.3.4:5678`,
/// as Azure Application Gateway writes) or in brackets (`[2001:db8::1]`,
/// `[2001:db8::1]:443`); the port is dropped. Any other hop, including
/// RFC 7239 obfuscated identifiers, stops the walk and the last trusted
/// hop is used, which throttles harder rather than softer.
pub fn resolve_source_ip(
    peer: IpAddr,
    headers: &http::HeaderMap,
    trusted_proxies: &[TrustedProxy],
) -> IpAddr {
    let trusted = |ip: IpAddr| trusted_proxies.iter().any(|p| p.contains(ip));
    if !trusted(peer) {
        return peer;
    }
    let xff: Vec<&str> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .filter(|h| !h.is_empty())
        .collect();
    if !xff.is_empty() {
        let mut source = peer;
        for hop in xff.iter().rev() {
            match parse_hop(hop) {
                Some(ip) => {
                    source = ip;
                    if !trusted(ip) {
                        break;
                    }
                }
                None => break,
            }
        }
        return source;
    }
    headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| parse_hop(v.trim()))
        .unwrap_or(peer)
}

/// One forwarding-header hop: `ip`, `ip:port`, `[ipv6]` or `[ipv6]:port`.
fn parse_hop(hop: &str) -> Option<IpAddr> {
    if let Ok(ip) = hop.parse::<IpAddr>() {
        return Some(ip);
    }
    if let Ok(sa) = hop.parse::<SocketAddr>() {
        return Some(sa.ip());
    }
    hop.strip_prefix('[')?
        .strip_suffix(']')?
        .parse::<std::net::Ipv6Addr>()
        .ok()
        .map(IpAddr::V6)
}
