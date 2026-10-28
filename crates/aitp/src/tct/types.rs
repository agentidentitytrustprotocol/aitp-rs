//! TCT and grant-voucher claim types (RFC-AITP-0005 /
//! `schemas/json/aitp-tct.schema.json`,
//! `schemas/json/aitp-grant-voucher.schema.json`).
//!
//! On the wire both artifacts are **opaque compact JWS strings**
//! (RFC-AITP-0001 §5.4.5); these types model the decoded payload
//! claims. Strictness lives in the serde derives: `deny_unknown_fields`
//! rejects unknown claims (the `ext` slot is the one sanctioned
//! exception) and serde's derive rejects duplicate claims.

use crate::core::{Aid, Timestamp};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// RFC 7800 confirmation claim, `jkt` form only (RFC-AITP-0001 §5.4.4).
///
/// `jkt` is the RFC 7638 JWK SHA-256 thumbprint (43-char unpadded
/// base64url) of the bound public key. It MUST match the key encoded in
/// the token's `sub` AID — the AID is authoritative; `jkt` is
/// deliberately redundant so JOSE-generic verifiers can perform PoP
/// without understanding AIDs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Cnf {
    /// RFC 7638 JWK thumbprint, unpadded base64url.
    pub jkt: String,
}

/// Decoded claims of a Trust Context Token (RFC-AITP-0005 §2).
///
/// Mint with [`crate::tct::TctBuilder`] (which returns the signed compact
/// string); verify a received compact string with [`crate::tct::verify_tct`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct TctClaims {
    /// Protocol version private claim. MUST be `"aitp/0.3"`.
    pub ver: String,
    /// UUID v4 unique token ID; the revocation handle (RFC-AITP-0008).
    /// Deserialization enforces the strict v4 wire form (proposal #72
    /// Item 6b).
    #[serde(with = "crate::core::ids::serde_v4")]
    pub jti: Uuid,
    /// Issuing peer's AID.
    pub iss: Aid,
    /// Subject peer's AID (the agent this TCT was issued for).
    pub sub: Aid,
    /// Intended consuming peer's AID. MUST equal `sub` for peer-issued
    /// TCTs.
    pub aud: Aid,
    /// Unix seconds of issuance.
    pub iat: Timestamp,
    /// Unix seconds of expiry. MUST NOT exceed the issuer Manifest's
    /// `expires_at` (RFC-AITP-0005 §10.4).
    pub exp: Timestamp,
    /// Capability strings granted to the subject. MUST be non-empty
    /// (RFC-AITP-0004 §4.1).
    pub grants: Vec<String>,
    /// Proof-of-possession binding to the subject's key (§3).
    pub cnf: Cnf,
    /// OPTIONAL extensions slot (RFC-AITP-0012). Unknown keys inside
    /// `ext` MUST be ignored; unknown claims outside it are rejected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ext: Option<crate::core::ExtensionsMap>,
}

/// Full set of top-level members `aitp-tct.schema.json` declares,
/// including the `ext` namespace key itself. Used by [`crate::tct::verify_tct`]'s
/// member-set check (RFC-AITP-0001 §7 / RFC-AITP-0005 §7.2) on the decoded
/// JWS payload, applied after `typ` enforcement (RFC-AITP-0005 §7.2 step
/// 2 — a `typ` mismatch means this claim registry doesn't even apply, see
/// fixture `tct-010`) but before AID-pinned `alg` checking and signature
/// verification — the RFC's "before any cryptographic step" guarantee
/// scopes to steps 3-4, not step 2.
///
/// Anchored to the vendored schema by `crates/aitp/tests/tct_schema.rs`,
/// which asserts this list equals the schema's top-level `properties`
/// keys — so this cannot silently drift from the spec.
pub const TCT_CLAIMS_MEMBERS: &[&str] = &[
    "ver", "jti", "iss", "sub", "aud", "iat", "exp", "grants", "cnf", "ext",
];

/// Decoded claims of a grant voucher (RFC-AITP-0005 §8).
///
/// Minted by the TCT issuer at TCT issuance time, alongside the TCT.
/// `iss`/`sub`/`grants`/`iat`/`exp` MUST equal the companion TCT's
/// values and `src_jti` its `jti`. The voucher has no `jti` of its own
/// (lifecycle is derived from the TCT via `src_jti`) and no `cnf` (it
/// is never presented under PoP by itself — only embedded verbatim
/// inside a delegation token whose outer signature binds it).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct GrantVoucherClaims {
    /// Protocol version private claim. MUST be `"aitp/0.3"`.
    pub ver: String,
    /// The TCT issuer's AID. The voucher is signed by this key.
    pub iss: Aid,
    /// The TCT subject's AID — the peer entitled to delegate against
    /// this voucher.
    pub sub: Aid,
    /// MUST equal the companion TCT's `grants`. Non-empty.
    pub grants: Vec<String>,
    /// MUST equal the companion TCT's `iat`.
    pub iat: Timestamp,
    /// MUST equal the companion TCT's `exp`.
    pub exp: Timestamp,
    /// The companion TCT's `jti`. Revocation rides on this: revoking
    /// the TCT kills every voucher and delegation derived from it.
    #[serde(with = "crate::core::ids::serde_v4")]
    pub src_jti: Uuid,
    /// OPTIONAL extensions slot, same semantics as the TCT `ext` claim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ext: Option<crate::core::ExtensionsMap>,
}

/// Full set of top-level members `aitp-grant-voucher.schema.json` declares,
/// including the `ext` namespace key itself. Used by [`crate::tct::verify_voucher`]'s
/// member-set check (RFC-AITP-0001 §7 / RFC-AITP-0005 §7.2) on the decoded
/// JWS payload, applied after `typ` enforcement (RFC-AITP-0005 §7.2 step
/// 2 — a `typ` mismatch means this claim registry doesn't even apply, see
/// fixture `tct-010`) but before AID-pinned `alg` checking and signature
/// verification — the RFC's "before any cryptographic step" guarantee
/// scopes to steps 3-4, not step 2.
///
/// Anchored to the vendored schema by `crates/aitp/tests/tct_schema.rs`,
/// which asserts this list equals the schema's top-level `properties`
/// keys — so this cannot silently drift from the spec.
pub const GRANT_VOUCHER_CLAIMS_MEMBERS: &[&str] = &[
    "ver", "iss", "sub", "grants", "iat", "exp", "src_jti", "ext",
];

/// A freshly issued TCT: the signed compact string, its decoded claims,
/// and the companion grant voucher (unless issuance policy declined to
/// mint one — RFC-AITP-0005 §8.2, in which case the subject cannot
/// delegate).
///
/// Only [`crate::tct::TctBuilder`] constructs it, and its fields are
/// read-only: [`Self::into_parts`] hands out the owned pieces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedTct {
    pub(crate) token: String,
    pub(crate) claims: TctClaims,
    pub(crate) voucher: Option<String>,
}

impl IssuedTct {
    /// The TCT as the opaque compact JWS string that goes on the wire.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Decoded claims of [`Self::token`], for issuer-side bookkeeping.
    pub fn claims(&self) -> &TctClaims {
        &self.claims
    }

    /// Companion grant voucher compact JWS, delivered alongside the TCT
    /// in the handshake commit payload.
    pub fn voucher(&self) -> Option<&str> {
        self.voucher.as_deref()
    }

    /// The owned pieces.
    pub fn into_parts(self) -> IssuedTctParts {
        IssuedTctParts {
            token: self.token,
            claims: self.claims,
            voucher: self.voucher,
        }
    }
}

/// The owned pieces of an [`IssuedTct`], from [`IssuedTct::into_parts`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct IssuedTctParts {
    /// See [`IssuedTct::token`].
    pub token: String,
    /// See [`IssuedTct::claims`].
    pub claims: TctClaims,
    /// See [`IssuedTct::voucher`].
    pub voucher: Option<String>,
}

/// A TCT that passed [`crate::tct::verify_tct`]: the verbatim token plus its
/// now-trusted decoded claims. Hold (and forward) [`Self::token`]; read
/// [`Self::claims`].
///
/// Only the verifiers construct it, and its fields are read-only:
/// [`Self::into_parts`] hands out the owned pieces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTct {
    pub(crate) token: String,
    pub(crate) claims: TctClaims,
    pub(crate) effective_grants: Vec<String>,
}

impl VerifiedTct {
    /// The verified compact JWS string, byte-for-byte as received.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Decoded claims, trusted after verification.
    pub fn claims(&self) -> &TctClaims {
        &self.claims
    }

    /// The capabilities this TCT may exercise: `claims.grants`, narrowed
    /// to the safe subset when the revocation source answered
    /// [`crate::tct::RevocationStatus::SoftFailSafeSubset`].
    pub fn effective_grants(&self) -> &[String] {
        &self.effective_grants
    }

    /// The owned pieces.
    pub fn into_parts(self) -> VerifiedTctParts {
        VerifiedTctParts {
            token: self.token,
            claims: self.claims,
            effective_grants: self.effective_grants,
        }
    }
}

/// The owned pieces of a [`VerifiedTct`], from [`VerifiedTct::into_parts`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerifiedTctParts {
    /// See [`VerifiedTct::token`].
    pub token: String,
    /// See [`VerifiedTct::claims`].
    pub claims: TctClaims,
    /// See [`VerifiedTct::effective_grants`].
    pub effective_grants: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_claims_json() -> serde_json::Value {
        json!({
            "ver": "aitp/0.3",
            "jti": "550e8400-e29b-41d4-a716-446655440000",
            "iss": "aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik",
            "sub": "aid:pubkey:A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
            "aud": "aid:pubkey:A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
            "iat": 1_711_900_000,
            "exp": 1_711_903_600,
            "grants": ["macp.mode.task.v1"],
            "cnf": { "jkt": "1IG2tMH7J2wbJZnOf8LJzQitKf7LMvoAElsuDMVM54Y" },
        })
    }

    #[test]
    fn claims_round_trip() {
        let claims: TctClaims = serde_json::from_value(sample_claims_json()).unwrap();
        let back = serde_json::to_value(&claims).unwrap();
        assert_eq!(back, sample_claims_json());
    }

    #[test]
    fn unknown_claim_rejected_outside_ext() {
        let mut v = sample_claims_json();
        v.as_object_mut().unwrap().insert("rogue".into(), json!(1));
        assert!(serde_json::from_value::<TctClaims>(v).is_err());
    }

    #[test]
    fn unknown_keys_inside_ext_are_carried() {
        let mut v = sample_claims_json();
        v.as_object_mut()
            .unwrap()
            .insert("ext".into(), json!({"x-foo": {"deep": true}}));
        let claims: TctClaims = serde_json::from_value(v).unwrap();
        assert!(claims.ext.unwrap().contains_key("x-foo"));
    }

    #[test]
    fn unknown_cnf_member_rejected() {
        let mut v = sample_claims_json();
        v["cnf"]
            .as_object_mut()
            .unwrap()
            .insert("jwk".into(), json!({}));
        assert!(serde_json::from_value::<TctClaims>(v).is_err());
    }

    #[test]
    fn voucher_claims_round_trip() {
        let v = json!({
            "ver": "aitp/0.3",
            "iss": "aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik",
            "sub": "aid:pubkey:A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
            "grants": ["macp.mode.task.v1"],
            "iat": 1_711_900_000,
            "exp": 1_711_903_600,
            "src_jti": "550e8400-e29b-41d4-a716-446655440001",
        });
        let claims: GrantVoucherClaims = serde_json::from_value(v.clone()).unwrap();
        assert_eq!(serde_json::to_value(&claims).unwrap(), v);
    }
}
