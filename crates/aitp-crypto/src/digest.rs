//! The 32-byte AITP signing digest `d` (RFC-AITP-0001 §5.4.6).

use sha2::{Digest as _, Sha256};

/// The AITP signing digest `d = SHA-256(signing_input)` (RFC-AITP-0001
/// §5.4.6).
///
/// Every non-JWS AITP signature (manifest, envelope, revocation, PoP,
/// pinned-key proof, session bundle) is computed over `d`. Ed25519 signs
/// the 32 bytes of `d` as its PureEdDSA message. P-256 uses `d` *as* the
/// ECDSA message hash `e`: it is **never hashed again**. 0.13.x and older
/// hashed `d` a second time on the P-256 path. That is the "double hash"
/// the proposal for agentidentitytrustprotocol#72 fixes.
///
/// A distinct type, rather than `&[u8]`, keeps a caller from passing the
/// unhashed signing input where `d` is expected, and from passing `d`
/// where a JWS signing input is expected ([`crate::AitpSigningKey::sign_raw`]).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Digest32([u8; 32]);

impl Digest32 {
    /// `d = SHA-256(signing_input)`: the one hash §5.4.6 applies.
    pub fn sha256(signing_input: &[u8]) -> Self {
        Self(Sha256::digest(signing_input).into())
    }

    /// Wrap a digest computed elsewhere, e.g. by a KMS client that
    /// streamed the signing input.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The 32 digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for Digest32 {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for Digest32 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for Digest32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Digest32(")?;
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_known_vector() {
        // SHA-256("abc"), FIPS 180-2 Appendix B.1.
        assert_eq!(
            format!("{:?}", Digest32::sha256(b"abc")),
            "Digest32(ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad)"
        );
    }
}
