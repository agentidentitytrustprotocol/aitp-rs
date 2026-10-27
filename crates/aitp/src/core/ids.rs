//! UUID v4 identifiers: `jti`, voucher `src_jti`, envelope `message_id`
//! (RFC-AITP-0005 §2 and RFC-AITP-0001 §5.2, as revised by proposal
//! agentidentitytrustprotocol#72 Item 6b).
//!
//! The wire form is lowercase hyphenated 8-4-4-4-12 hex with version
//! nibble `4` and variant bits `10`. The remaining 122 bits are either
//! random ([`random_v4`]) or derived from a domain tag and an input
//! ([`derived_v4`]). A verifier cannot tell the two apart, and does not
//! try.

use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Why an identifier is not a valid v4 layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum V4Error {
    /// Not 36 characters of lowercase hex and hyphens in 8-4-4-4-12.
    #[error("identifier is not lowercase hyphenated 8-4-4-4-12 hex")]
    Format,
    /// Version nibble is not 4.
    #[error("identifier version is not 4")]
    Version,
    /// Variant bits are not `10`.
    #[error("identifier variant is not RFC 9562")]
    Variant,
}

/// A derivation tag outside printable ASCII `0x21..=0x7E`, or empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("derivation tag must be non-empty printable ASCII (0x21-0x7E)")]
pub struct InvalidTag;

/// True if `id` has version 4 and the RFC 9562 variant.
pub fn is_v4(id: &Uuid) -> bool {
    id.get_version_num() == 4 && id.get_variant() == uuid::Variant::RFC4122
}

/// Check a parsed identifier's layout.
pub fn check_v4(id: &Uuid) -> Result<(), V4Error> {
    if id.get_version_num() != 4 {
        Err(V4Error::Version)
    } else if id.get_variant() != uuid::Variant::RFC4122 {
        Err(V4Error::Variant)
    } else {
        Ok(())
    }
}

/// Parse the wire form strictly: lowercase hyphenated, version 4,
/// variant `10`. Braced, URN, simple and uppercase forms are refused.
pub fn parse_v4(s: &str) -> Result<Uuid, V4Error> {
    let b = s.as_bytes();
    let shape_ok = b.len() == 36
        && b.iter().enumerate().all(|(i, &c)| match i {
            8 | 13 | 18 | 23 => c == b'-',
            _ => c.is_ascii_digit() || (b'a'..=b'f').contains(&c),
        });
    if !shape_ok {
        return Err(V4Error::Format);
    }
    let id = Uuid::parse_str(s).map_err(|_| V4Error::Format)?;
    check_v4(&id)?;
    Ok(id)
}

/// A random v4 identifier from the OS CSPRNG.
pub fn random_v4() -> Uuid {
    Uuid::new_v4()
}

/// The domain-separated preimage `tag || 0x00 || input` of
/// [`derived_v4`].
pub fn derived_v4_preimage(tag: &str, input: &[u8]) -> Result<Vec<u8>, InvalidTag> {
    if tag.is_empty() || !tag.bytes().all(|c| (0x21..=0x7e).contains(&c)) {
        return Err(InvalidTag);
    }
    let mut pre = Vec::with_capacity(tag.len() + 1 + input.len());
    pre.extend_from_slice(tag.as_bytes());
    pre.push(0);
    pre.extend_from_slice(input);
    Ok(pre)
}

/// A deterministic v4-layout identifier: `h = SHA-256(tag || 0x00 ||
/// input)`, bytes `h[0..16]` with `h[6] = (h[6] & 0x0f) | 0x40` and
/// `h[8] = (h[8] & 0x3f) | 0x80`.
///
/// `tag` names the use (for example `com.example.decision-commit`); the
/// caller MUST guarantee distinct tokens never share an `input` under
/// one tag. Use this for idempotent re-issuance and archival
/// attestations; otherwise prefer [`random_v4`].
pub fn derived_v4(tag: &str, input: &[u8]) -> Result<Uuid, InvalidTag> {
    let h = Sha256::digest(derived_v4_preimage(tag, input)?);
    let mut b = [0u8; 16];
    b.copy_from_slice(&h[..16]);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    Ok(Uuid::from_bytes(b))
}

/// `#[serde(with = "crate::core::ids::serde_v4")]` for a `Uuid` field that
/// must be in the strict v4 wire form.
pub mod serde_v4 {
    use serde::{Deserialize, Deserializer, Serializer};
    use uuid::Uuid;

    /// Serialize as lowercase hyphenated.
    pub fn serialize<S: Serializer>(id: &Uuid, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(&id.hyphenated())
    }

    /// Deserialize via [`super::parse_v4`].
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Uuid, D::Error> {
        let s = <std::borrow::Cow<'de, str>>::deserialize(d)?;
        super::parse_v4(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_parse() {
        let ok = "770e8400-e29b-41d4-a716-446655440702";
        assert!(parse_v4(ok).is_ok());
        assert_eq!(parse_v4(&ok.to_uppercase()).unwrap_err(), V4Error::Format);
        assert_eq!(
            parse_v4("770e8400e29b41d4a716446655440702").unwrap_err(),
            V4Error::Format
        );
        assert_eq!(
            parse_v4("{770e8400-e29b-41d4-a716-446655440702}").unwrap_err(),
            V4Error::Format
        );
        // v7
        assert_eq!(
            parse_v4("01890a5d-ac96-774b-bcce-b302099a8057").unwrap_err(),
            V4Error::Version
        );
        // v4 nibble, variant 0b11x (Microsoft)
        assert_eq!(
            parse_v4("770e8400-e29b-41d4-c716-446655440702").unwrap_err(),
            V4Error::Variant
        );
        assert!(is_v4(&random_v4()));
    }

    #[test]
    fn derived_is_v4_and_domain_separated() {
        let a = derived_v4("a", b"bc").unwrap();
        let ab = derived_v4("ab", b"c").unwrap();
        assert_ne!(a, ab, "the 0x00 separator splits prefix tags");
        assert!(is_v4(&a) && is_v4(&ab));
        assert_eq!(a, derived_v4("a", b"bc").unwrap(), "deterministic");
        assert!(parse_v4(&a.hyphenated().to_string()).is_ok());
    }

    #[test]
    fn tag_must_be_printable_ascii() {
        for bad in ["", "has space", "nul\0", "tab\t", "é", "\x7f"] {
            assert_eq!(derived_v4(bad, b"x"), Err(InvalidTag), "{bad:?}");
        }
        assert!(derived_v4("!~", b"").is_ok());
    }

    #[test]
    fn serde_round_trip_and_rejects() {
        #[derive(serde::Serialize, serde::Deserialize)]
        struct T {
            #[serde(with = "serde_v4")]
            id: Uuid,
        }
        let id = random_v4();
        let j = serde_json::to_string(&T { id }).unwrap();
        assert_eq!(serde_json::from_str::<T>(&j).unwrap().id, id);
        assert!(
            serde_json::from_str::<T>(r#"{"id":"01890a5d-ac96-774b-bcce-b302099a8057"}"#).is_err()
        );
    }
}
