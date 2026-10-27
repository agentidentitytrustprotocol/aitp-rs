//! The `rfc-aitp-0005.renew_uri` Manifest extension (RFC-AITP-0013 §2).
//!
//! TCT renewal is opt-in. An issuer that offers it advertises the concrete
//! endpoint in its signed Manifest:
//!
//! ```json
//! "extensions": {
//!   "rfc-aitp-0005.renew_uri": "https://issuer.example/aitp/handshake/renew"
//! }
//! ```
//!
//! A holder renews only at that URL. When the key is absent the holder
//! MUST fall back to a full Mutual Handshake and MUST NOT probe a guessed
//! path (RFC-AITP-0013 §2).

/// Manifest extension key carrying the issuer's TCT renewal endpoint
/// (registered Provisional in the spec's `registries/extension-keys.md`).
pub const RENEW_URI_EXT: &str = "rfc-aitp-0005.renew_uri";

/// The renewal endpoint a Manifest advertises, if any.
///
/// Returns `None` when the extension is missing, not a string, not a URL,
/// or not HTTPS. Plain `http` is accepted only for `localhost` and
/// `127.0.0.1`, and only when `allow_insecure_localhost` is `true`: the
/// same opt-in local-development exemption as
/// `ManifestFetcher::with_insecure_localhost`. Never enable it in production.
pub fn renew_uri_from_manifest(
    manifest: &crate::manifest::Manifest,
    allow_insecure_localhost: bool,
) -> Option<url::Url> {
    manifest
        .extensions
        .as_ref()?
        .get(RENEW_URI_EXT)
        .and_then(|v| v.as_str())
        .and_then(|s| url::Url::parse(s).ok())
        .filter(|u| match u.scheme() {
            "https" => true,
            "http" => {
                allow_insecure_localhost && matches!(u.host_str(), Some("localhost" | "127.0.0.1"))
            }
            _ => false,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::AitpSigningKey;
    use crate::manifest::{IdentityHint, IdentityHintKind, ManifestBuilder};

    fn manifest(renew_uri: Option<serde_json::Value>) -> crate::manifest::Manifest {
        let key = AitpSigningKey::from_seed(&[0x5a; 32]);
        let mut b = ManifestBuilder::new(&key)
            .display_name("issuer")
            .handshake_endpoint("https://issuer.example/aitp/handshake".parse().unwrap())
            .identity_hint(IdentityHint {
                kind: IdentityHintKind::PinnedKey,
                subject: "issuer".into(),
                issuer: None,
                public_key: Some(crate::core::base64url::encode(
                    &key.verifying_key().try_to_ed25519_bytes().unwrap(),
                )),
            })
            .accept_identity_type("pinned_key")
            .offer("demo.echo");
        if let Some(v) = renew_uri {
            b = b.extension(RENEW_URI_EXT, v);
        }
        b.build().unwrap()
    }

    #[test]
    fn reads_advertised_https_uri() {
        let m = manifest(Some("https://issuer.example/renew-here".into()));
        assert_eq!(
            renew_uri_from_manifest(&m, false).unwrap().as_str(),
            "https://issuer.example/renew-here"
        );
    }

    #[test]
    fn absent_or_unusable_uri_is_none() {
        assert!(renew_uri_from_manifest(&manifest(None), true).is_none());
        for bad in [
            serde_json::json!("http://issuer.example/renew"),
            serde_json::json!("ftp://issuer.example/renew"),
            serde_json::json!("not a url"),
            serde_json::json!(42),
        ] {
            assert!(
                renew_uri_from_manifest(&manifest(Some(bad.clone())), true).is_none(),
                "{bad}"
            );
        }
    }

    #[test]
    fn loopback_http_needs_opt_in() {
        let m = manifest(Some("http://127.0.0.1:8080/aitp/handshake/renew".into()));
        assert!(renew_uri_from_manifest(&m, false).is_none());
        assert!(renew_uri_from_manifest(&m, true).is_some());
    }
}
