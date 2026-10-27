//! aitp-rs#205 A-2: the RFC-AITP-0009 §3.1 trusted-proxy source rule,
//! callable without the axum server: feature `source-ip` needs only
//! `http` 1.x.
#![cfg(feature = "source-ip")]

use aitp::transport::{resolve_source_ip, TrustedProxy};
use http::{HeaderMap, HeaderValue};
use std::net::IpAddr;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
    let mut h = HeaderMap::new();
    for (k, v) in pairs {
        h.append(*k, HeaderValue::from_str(v).unwrap());
    }
    h
}

fn proxies() -> Vec<TrustedProxy> {
    vec!["10.0.0.0/8".parse().unwrap(), "fd00::/8".parse().unwrap()]
}

#[test]
fn untrusted_peer_headers_ignored() {
    let h = headers(&[("x-forwarded-for", "1.1.1.1"), ("x-real-ip", "2.2.2.2")]);
    assert_eq!(
        resolve_source_ip(ip("203.0.113.9"), &h, &proxies()),
        ip("203.0.113.9")
    );
    // No trusted proxies configured: the peer, always.
    assert_eq!(resolve_source_ip(ip("10.0.0.1"), &h, &[]), ip("10.0.0.1"));
}

#[test]
fn rightmost_untrusted_hop_wins_over_client_prefix() {
    // The client prepended a spoofed hop; the proxy appended the real one.
    let h = headers(&[("x-forwarded-for", "6.6.6.6, 198.51.100.4, 10.1.1.1")]);
    assert_eq!(
        resolve_source_ip(ip("10.0.0.2"), &h, &proxies()),
        ip("198.51.100.4")
    );
    // Split across several header lines.
    let h = headers(&[
        ("x-forwarded-for", "6.6.6.6"),
        ("x-forwarded-for", "198.51.100.4"),
    ]);
    assert_eq!(
        resolve_source_ip(ip("10.0.0.2"), &h, &proxies()),
        ip("198.51.100.4")
    );
}

#[test]
fn unparsable_hop_stops_at_last_trusted() {
    let h = headers(&[("x-forwarded-for", "198.51.100.4, garbage, 10.1.1.1")]);
    assert_eq!(
        resolve_source_ip(ip("10.0.0.2"), &h, &proxies()),
        ip("10.1.1.1")
    );
}

#[test]
fn x_real_ip_then_peer() {
    let h = headers(&[("x-real-ip", " 198.51.100.7 ")]);
    assert_eq!(
        resolve_source_ip(ip("fd00::1"), &h, &proxies()),
        ip("198.51.100.7")
    );
    let h = headers(&[("x-real-ip", "nope")]);
    assert_eq!(
        resolve_source_ip(ip("fd00::1"), &h, &proxies()),
        ip("fd00::1")
    );
    assert_eq!(
        resolve_source_ip(ip("fd00::1"), &HeaderMap::new(), &proxies()),
        ip("fd00::1")
    );
}

#[test]
fn ipv4_mapped_peer_matches_v4_range() {
    let h = headers(&[("x-forwarded-for", "198.51.100.4")]);
    assert_eq!(
        resolve_source_ip(ip("::ffff:10.0.0.2"), &h, &proxies()),
        ip("198.51.100.4")
    );
}

#[test]
fn hop_with_port_or_brackets_reads_the_address() {
    // Azure Application Gateway writes `ip:port`; others bracket IPv6.
    let h = headers(&[(
        "x-forwarded-for",
        "6.6.6.6, 198.51.100.4:51234, [fd00::9]:443, 10.1.1.1:80",
    )]);
    assert_eq!(
        resolve_source_ip(ip("10.0.0.2"), &h, &proxies()),
        ip("198.51.100.4")
    );
    let h = headers(&[("x-forwarded-for", "[2001:db8::7]")]);
    assert_eq!(
        resolve_source_ip(ip("10.0.0.2"), &h, &proxies()),
        ip("2001:db8::7")
    );
    let h = headers(&[("x-real-ip", "198.51.100.7:9000")]);
    assert_eq!(
        resolve_source_ip(ip("10.0.0.2"), &h, &proxies()),
        ip("198.51.100.7")
    );
}

#[test]
fn malformed_bracket_or_port_still_stops_the_walk() {
    for bad in [
        "[fd00::9",
        "198.51.100.4:",
        "198.51.100.4:99999",
        "fd00::9]:1",
        "1.2.3.4:5:6",
    ] {
        let h = headers(&[("x-forwarded-for", &format!("198.51.100.4, {bad}, 10.1.1.1"))]);
        assert_eq!(
            resolve_source_ip(ip("10.0.0.2"), &h, &proxies()),
            ip("10.1.1.1"),
            "{bad}"
        );
    }
}
