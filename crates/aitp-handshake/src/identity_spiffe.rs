//! SPIFFE identity verification (RFC-AITP-0002 §6).
//!
//! **Experimental.** `spiffe` is at registry status Proposed and this
//! module ships behind the `experimental-spiffe-identity` feature. Its
//! API can change in any release.
//!
//! A `spiffe` descriptor proves a SPIFFE ID with one of two SVID forms:
//!
//! - a JWT-SVID (§6.3), checked like an OIDC ID token with the subject
//!   trust domain's bundle in place of the issuer's JWKS; or
//! - an X509-SVID (§6.4): the `x5c` chain is path-validated against the
//!   bundle's X.509 CAs, the leaf is constrained, and `proof` is a
//!   signature by the leaf key over the handshake context (§6.4.1).
//!
//! Trust comes only from the verifier's own [`SpiffeBundleStore`] (§6.2).
//! Every check of §6.5 steps 1–4 (descriptor shape, canonical SPIFFE ID,
//! bundle lookup, keys of the right `use`) runs before any signature is
//! verified. Every failure is `IDENTITY_FAILED`
//! ([`HandshakeError::Identity`]).

use std::collections::BTreeMap;
use std::time::Duration;

use aitp_core::{base64url, Aid, Timestamp};
use aitp_crypto::{AitpVerifyingKey, Digest32, Signature};
use base64ct::Encoding as _;
use rustls_pki_types::{CertificateDer, UnixTime};
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;
use x509_parser::extensions::GeneralName;
use x509_parser::oid_registry::{OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY, OID_SIG_ED25519};

use crate::error::HandshakeError;
use crate::identity::{IdentityDescriptor, IdentityKind, SvidType};
use crate::identity_pinned::handshake_proof_input;
use crate::jwk::{verify_jws_signature, JwkParseError, JwkPublicKey};

/// Domain prefix of the X509-SVID proof input (RFC-AITP-0002 §6.4.1).
pub const SPIFFE_X509_PROOF_DOMAIN: &[u8] = b"aitp-spiffe-x509-v1\0";

/// JWT-SVID `alg` values JWT-SVID §2.1 allows. Anything else, `EdDSA`
/// included, is rejected before key selection; [`verify_jws_signature`]
/// verifies all nine.
const JWT_SVID_ALGS: &[&str] = &[
    "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512",
];

/// Maximum SPIFFE ID length in bytes (SPIFFE-ID §2.3).
const MAX_SPIFFE_ID_LEN: usize = 2048;
/// Maximum trust domain length in bytes (SPIFFE-ID §2.3).
const MAX_TRUST_DOMAIN_LEN: usize = 255;

/// Errors building a [`SpiffeBundleStore`] from configuration.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SpiffeConfigError {
    /// The same trust domain is listed twice (RFC-AITP-0002 §6.2).
    #[error("duplicate trust domain in spiffe_bundles: {0}")]
    DuplicateTrustDomain(String),
    /// A trust domain name is not a canonical SPIFFE trust domain.
    #[error("invalid trust domain: {0:?}")]
    InvalidTrustDomain(String),
    /// The configuration or a bundle is malformed.
    #[error("malformed spiffe bundle configuration: {0}")]
    Malformed(String),
}

/// One trust domain's SPIFFE bundle (RFC-AITP-0002 §6.2): its JWT-SVID
/// signing keys and its X.509 CA certificates.
#[derive(Debug, Clone, Default)]
pub struct SpiffeBundle {
    /// `use: jwt-svid` keys. Every entry has a `kid`, unique in the
    /// bundle.
    jwt_authorities: Vec<JwkPublicKey>,
    /// DER certificates of the `use: x509-svid` keys.
    x509_authorities: Vec<Vec<u8>>,
}

impl SpiffeBundle {
    /// Parse a SPIFFE bundle, an RFC 7517 JWK Set (SPIFFE Trust Domain
    /// and Bundle §4).
    ///
    /// - A `jwt-svid` JWK MUST carry a `kid`, unique among the
    ///   bundle's `jwt-svid` keys (JWT-SVID §6.1).
    /// - An `x509-svid` JWK MUST carry exactly one DER certificate in
    ///   `x5c` (X509-SVID §6.1).
    /// - A JWK whose `use` is missing or unknown is ignored (§4.2.2), as
    ///   is a `jwt-svid` key of a type this crate cannot verify.
    /// - `spiffe_sequence` and `spiffe_refresh_hint` are ignored.
    pub fn from_jwk_set(value: &Value) -> Result<Self, SpiffeConfigError> {
        let keys = value
            .get("keys")
            .and_then(Value::as_array)
            .ok_or_else(|| SpiffeConfigError::Malformed("bundle has no `keys` array".into()))?;
        let mut bundle = Self::default();
        for jwk in keys {
            match jwk.get("use").and_then(Value::as_str) {
                Some("jwt-svid") => {
                    let kid = jwk
                        .get("kid")
                        .and_then(Value::as_str)
                        .filter(|k| !k.is_empty())
                        .ok_or_else(|| {
                            SpiffeConfigError::Malformed("jwt-svid key has no `kid`".into())
                        })?;
                    if bundle
                        .jwt_authorities
                        .iter()
                        .any(|k| k.kid.as_deref() == Some(kid))
                    {
                        return Err(SpiffeConfigError::Malformed(format!(
                            "duplicate jwt-svid kid {kid:?}"
                        )));
                    }
                    match JwkPublicKey::from_jwk_json(jwk) {
                        Ok(key) => bundle.jwt_authorities.push(key),
                        Err(JwkParseError::Unsupported(_)) => {}
                        Err(e) => return Err(SpiffeConfigError::Malformed(e.to_string())),
                    }
                }
                Some("x509-svid") => {
                    let x5c = match jwk.get("x5c").and_then(Value::as_array).map(Vec::as_slice) {
                        Some([cert]) => cert.as_str().ok_or_else(|| {
                            SpiffeConfigError::Malformed(
                                "x509-svid x5c entry is not a string".into(),
                            )
                        })?,
                        _ => {
                            return Err(SpiffeConfigError::Malformed(
                                "x509-svid key must carry exactly one x5c certificate".into(),
                            ))
                        }
                    };
                    let der = decode_x5c_entry(x5c).map_err(SpiffeConfigError::Malformed)?;
                    parse_certificate(&der).map_err(SpiffeConfigError::Malformed)?;
                    bundle.x509_authorities.push(der);
                }
                _ => {}
            }
        }
        Ok(bundle)
    }
}

/// The verifier's local `spiffe_bundles` store (RFC-AITP-0002 §6.2),
/// keyed by trust domain.
#[derive(Debug, Clone, Default)]
pub struct SpiffeBundleStore {
    bundles: BTreeMap<String, SpiffeBundle>,
}

impl SpiffeBundleStore {
    /// An empty store: every `spiffe` identity fails.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a store from the trust-anchors configuration's
    /// `spiffe_bundles` array of `{trust_domain, bundle}` entries.
    /// Rejects a trust domain listed twice.
    pub fn from_config(spiffe_bundles: &Value) -> Result<Self, SpiffeConfigError> {
        let entries = spiffe_bundles
            .as_array()
            .ok_or_else(|| SpiffeConfigError::Malformed("spiffe_bundles is not an array".into()))?;
        let mut store = Self::new();
        for entry in entries {
            let trust_domain = entry
                .get("trust_domain")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    SpiffeConfigError::Malformed("spiffe_bundles entry has no trust_domain".into())
                })?;
            let bundle = entry.get("bundle").ok_or_else(|| {
                SpiffeConfigError::Malformed("spiffe_bundles entry has no bundle".into())
            })?;
            store.insert(trust_domain, SpiffeBundle::from_jwk_set(bundle)?)?;
        }
        Ok(store)
    }

    /// Add `trust_domain`'s bundle. Rejects a non-canonical trust domain
    /// and one already in the store.
    pub fn insert(
        &mut self,
        trust_domain: &str,
        bundle: SpiffeBundle,
    ) -> Result<(), SpiffeConfigError> {
        if !is_canonical_trust_domain(trust_domain) {
            return Err(SpiffeConfigError::InvalidTrustDomain(trust_domain.into()));
        }
        if self.bundles.contains_key(trust_domain) {
            return Err(SpiffeConfigError::DuplicateTrustDomain(trust_domain.into()));
        }
        self.bundles.insert(trust_domain.into(), bundle);
        Ok(())
    }

    /// The bundle for `trust_domain`, compared byte for byte.
    pub fn get(&self, trust_domain: &str) -> Option<&SpiffeBundle> {
        self.bundles.get(trust_domain)
    }
}

/// Inputs to [`verify_spiffe`].
pub struct SpiffeVerifyContext<'a> {
    /// The verifier's own bundle store, never peer-supplied material.
    pub bundles: &'a SpiffeBundleStore,
    /// The envelope's `sender.agent_id` (the AID whose thumbprint
    /// `cnf.jkt` must carry, and the §6.4.1 `sender`).
    pub sender_aid: &'a Aid,
    /// The verifying peer's own AID (JWT-SVID `aud`, §6.4.1 `receiver`).
    pub receiver_aid: &'a Aid,
    /// The envelope's `message_id`.
    pub message_id: &'a Uuid,
    /// The envelope's `timestamp`.
    pub timestamp: Timestamp,
    /// The handshake message's `pop_nonce`.
    pub pop_nonce: &'a str,
    /// Allowed JWT-SVID `iat` skew in seconds (RFC-AITP-0002 §2.2: 300).
    pub iat_tolerance_secs: i64,
    /// Current time (Unix seconds).
    pub now_unix_secs: i64,
}

/// Verify a `spiffe` identity descriptor (RFC-AITP-0002 §6.5).
pub fn verify_spiffe(
    identity: &IdentityDescriptor,
    ctx: &SpiffeVerifyContext<'_>,
) -> Result<(), HandshakeError> {
    // Step 1: descriptor shape (§6.1), including the canonical SPIFFE ID.
    if identity.kind != IdentityKind::Spiffe {
        return Err(fail("identity.type is not spiffe"));
    }
    if identity.issuer.is_some() {
        return Err(fail("descriptor must not carry issuer"));
    }
    if identity.public_key.is_some() {
        return Err(fail("descriptor must not carry public_key"));
    }
    let svid_type = identity
        .svid_type
        .ok_or_else(|| fail("descriptor is missing svid_type"))?;
    // Step 2: the trust domain of `subject`.
    let trust_domain = spiffe_id_trust_domain(&identity.subject)?;
    match (svid_type, identity.x5c.as_deref()) {
        (SvidType::JwtSvid, None) => {}
        (SvidType::JwtSvid, Some(_)) => return Err(fail("x5c must be absent for a jwt-svid")),
        (SvidType::X509Svid, Some([_, ..])) => {}
        (SvidType::X509Svid, _) => return Err(fail("x509-svid requires a non-empty x5c")),
    }
    // Step 3: that trust domain's bundle, and only that bundle.
    let bundle = ctx
        .bundles
        .get(trust_domain)
        .ok_or_else(|| fail(&format!("no bundle for trust domain {trust_domain}")))?;
    // Steps 4–5.
    match svid_type {
        SvidType::JwtSvid => {
            if bundle.jwt_authorities.is_empty() {
                return Err(fail("bundle has no jwt-svid keys"));
            }
            verify_jwt_svid(identity, bundle, ctx)
        }
        SvidType::X509Svid => {
            if bundle.x509_authorities.is_empty() {
                return Err(fail("bundle has no x509-svid CAs"));
            }
            verify_x509_svid(identity, bundle, ctx)
        }
    }
}

/// The RFC-AITP-0002 §6.4.1 proof input. Same fields as the pinned-key
/// input (§3.1), behind [`SPIFFE_X509_PROOF_DOMAIN`].
pub fn spiffe_x509_proof_input(
    sender_aid: &Aid,
    receiver_aid: &Aid,
    message_id: &Uuid,
    timestamp: Timestamp,
    pop_nonce: &str,
) -> Result<Vec<u8>, HandshakeError> {
    handshake_proof_input(
        SPIFFE_X509_PROOF_DOMAIN,
        sender_aid,
        receiver_aid,
        message_id,
        timestamp,
        pop_nonce,
    )
}

fn verify_jwt_svid(
    identity: &IdentityDescriptor,
    bundle: &SpiffeBundle,
    ctx: &SpiffeVerifyContext<'_>,
) -> Result<(), HandshakeError> {
    let segments: Vec<&str> = identity.proof.split('.').collect();
    let [header_b64, payload_b64, sig_b64] = segments[..] else {
        return Err(fail("JWT-SVID is not a three-segment compact JWS"));
    };
    let header_bytes = base64url::decode_strict(header_b64)
        .map_err(|e| fail(&format!("malformed JWT-SVID header b64: {e}")))?;
    let header: serde_json::Map<String, Value> = serde_json::from_slice(&header_bytes)
        .map_err(|e| fail(&format!("malformed JWT-SVID header json: {e}")))?;
    // JWT-SVID §2: the protected header holds only alg, kid and typ.
    if let Some(member) = header
        .keys()
        .find(|k| !matches!(k.as_str(), "alg" | "kid" | "typ"))
    {
        return Err(fail(&format!(
            "JWT-SVID header member {member:?} not allowed"
        )));
    }
    let alg = header
        .get("alg")
        .and_then(Value::as_str)
        .ok_or_else(|| fail("JWT-SVID header has no alg"))?;
    if !JWT_SVID_ALGS.contains(&alg) {
        return Err(fail(&format!("JWT-SVID alg {alg:?} not allowed")));
    }
    match header.get("typ") {
        None => {}
        Some(Value::String(t)) if t == "JWT" || t == "JOSE" => {}
        Some(_) => return Err(fail("JWT-SVID typ must be JWT or JOSE")),
    }
    // Tightening: `kid` is required and selects exactly one key.
    let kid = header
        .get("kid")
        .and_then(Value::as_str)
        .ok_or_else(|| fail("JWT-SVID header has no kid"))?;
    let key = bundle
        .jwt_authorities
        .iter()
        .find(|k| k.kid.as_deref() == Some(kid))
        .ok_or_else(|| fail(&format!("no jwt-svid key with kid {kid:?}")))?;

    let sig = base64url::decode_strict(sig_b64)
        .map_err(|e| fail(&format!("malformed JWT-SVID signature b64: {e}")))?;
    let signing_input = format!("{header_b64}.{payload_b64}");
    verify_jws_signature(key, alg, signing_input.as_bytes(), &sig)
        .map_err(|e| fail(&format!("JWT-SVID signature invalid: {e}")))?;

    let payload = base64url::decode_strict(payload_b64)
        .map_err(|e| fail(&format!("malformed JWT-SVID payload b64: {e}")))?;
    let claims: JwtSvidClaims = serde_json::from_slice(&payload)
        .map_err(|e| fail(&format!("malformed JWT-SVID claims: {e}")))?;
    if claims.sub != identity.subject {
        return Err(fail("sub mismatch"));
    }
    let aud = match &claims.aud {
        Aud::Single(a) => a.as_str(),
        Aud::Multi(v) => match v.as_slice() {
            [a] => a.as_str(),
            _ => return Err(fail("aud must hold exactly one value")),
        },
    };
    if aud != ctx.receiver_aid.as_str() {
        return Err(fail("aud mismatch"));
    }
    if claims.exp <= ctx.now_unix_secs {
        return Err(fail("exp in the past"));
    }
    if (ctx.now_unix_secs - claims.iat).abs() > ctx.iat_tolerance_secs {
        return Err(fail("iat outside tolerance"));
    }
    if claims.nonce != ctx.pop_nonce {
        return Err(fail("nonce mismatch"));
    }
    let expected_jkt = AitpVerifyingKey::from_aid(ctx.sender_aid)
        .and_then(|k| k.to_jwk_thumbprint())
        .map_err(|e| fail(&format!("sender AID thumbprint: {e}")))?;
    if claims.cnf.jkt != expected_jkt {
        return Err(fail("cnf.jkt mismatch"));
    }
    Ok(())
}

fn verify_x509_svid(
    identity: &IdentityDescriptor,
    bundle: &SpiffeBundle,
    ctx: &SpiffeVerifyContext<'_>,
) -> Result<(), HandshakeError> {
    let chain = identity
        .x5c
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|c| decode_x5c_entry(c).map_err(|e| fail(&e)))
        .collect::<Result<Vec<_>, _>>()?;
    let (leaf_der, intermediates) = chain
        .split_first()
        .ok_or_else(|| fail("x509-svid requires a non-empty x5c"))?;

    // Steps 2–4 of §6.4 read only the leaf.
    let leaf = parse_certificate(leaf_der).map_err(|e| fail(&e))?;
    let leaf_key = check_leaf(&leaf, &identity.subject)?;

    // Step 1: RFC 5280 path validation against this trust domain's CAs,
    // with intermediates only from x5c[1..]. No revocation (§6.4).
    let anchor_ders: Vec<CertificateDer<'_>> = bundle
        .x509_authorities
        .iter()
        .map(|d| CertificateDer::from(d.as_slice()))
        .collect();
    let anchors = anchor_ders
        .iter()
        .map(webpki::anchor_from_trusted_cert)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| fail(&format!("bundle CA: {e}")))?;
    let intermediates: Vec<CertificateDer<'_>> = intermediates
        .iter()
        .map(|d| CertificateDer::from(d.as_slice()))
        .collect();
    let leaf_cert_der = CertificateDer::from(leaf_der.as_slice());
    let ee = webpki::EndEntityCert::try_from(&leaf_cert_der)
        .map_err(|e| fail(&format!("leaf certificate: {e}")))?;
    let now = u64::try_from(ctx.now_unix_secs).map_err(|_| fail("current time before epoch"))?;
    let time = UnixTime::since_unix_epoch(Duration::from_secs(now));
    // X509-SVID §4.4 lets a leaf carry the serverAuth or clientAuth
    // EKU, or none. webpki checks one purpose at a time.
    let verify = |usage| {
        ee.verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &anchors,
            &intermediates,
            time,
            usage,
            None,
            None,
        )
        .map(|_| ())
    };
    verify(webpki::KeyUsage::client_auth())
        .or_else(|_| verify(webpki::KeyUsage::server_auth()))
        .map_err(|e| fail(&format!("path validation: {e}")))?;

    // §6.4.1: the proof under the leaf key over the handshake context.
    let input = spiffe_x509_proof_input(
        ctx.sender_aid,
        ctx.receiver_aid,
        ctx.message_id,
        ctx.timestamp,
        ctx.pop_nonce,
    )?;
    let sig = Signature::parse(&identity.proof).map_err(|e| fail(&format!("proof: {e}")))?;
    leaf_key
        .verify_jcs(&Digest32::sha256(&input), &sig)
        .map_err(|_| fail("x509-svid proof does not verify under the leaf key"))
}

/// RFC-AITP-0002 §6.4 steps 2–4 on the leaf. Returns the leaf key.
fn check_leaf(
    leaf: &x509_parser::certificate::X509Certificate<'_>,
    subject: &str,
) -> Result<AitpVerifyingKey, HandshakeError> {
    // Step 2: exactly one URI SAN, equal to `subject` byte for byte.
    let san = leaf
        .subject_alternative_name()
        .map_err(|e| fail(&format!("leaf SAN: {e}")))?
        .ok_or_else(|| fail("leaf has no subjectAltName"))?;
    let uris: Vec<&str> = san
        .value
        .general_names
        .iter()
        .filter_map(|n| match n {
            GeneralName::URI(u) => Some(*u),
            _ => None,
        })
        .collect();
    match uris.as_slice() {
        [uri] if *uri == subject => {}
        [_] => return Err(fail("leaf URI SAN does not equal identity.subject")),
        _ => return Err(fail("leaf must carry exactly one URI SAN")),
    }
    // Step 3: not a CA; digitalSignature, no keyCertSign or cRLSign.
    let bc = leaf
        .basic_constraints()
        .map_err(|e| fail(&format!("leaf basicConstraints: {e}")))?;
    if bc.is_some_and(|bc| bc.value.ca) {
        return Err(fail("leaf is a CA certificate"));
    }
    let ku = leaf
        .key_usage()
        .map_err(|e| fail(&format!("leaf keyUsage: {e}")))?
        .ok_or_else(|| fail("leaf has no keyUsage"))?
        .value;
    if !ku.digital_signature() {
        return Err(fail("leaf keyUsage lacks digitalSignature"));
    }
    if ku.key_cert_sign() || ku.crl_sign() {
        return Err(fail("leaf keyUsage has keyCertSign or cRLSign"));
    }
    // Step 4: an Ed25519 or P-256 key.
    let spki = leaf.public_key();
    let key_bytes = spki.subject_public_key.data.as_ref();
    if spki.algorithm.algorithm == OID_SIG_ED25519 {
        let x: &[u8; 32] = key_bytes
            .try_into()
            .map_err(|_| fail("leaf Ed25519 key is not 32 bytes"))?;
        AitpVerifyingKey::from_bytes(x).map_err(|e| fail(&format!("leaf key: {e}")))
    } else if spki.algorithm.algorithm == OID_KEY_TYPE_EC_PUBLIC_KEY {
        let curve = spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.as_oid().ok());
        if curve.as_ref() != Some(&OID_EC_P256) {
            return Err(fail("leaf EC key is not P-256"));
        }
        // Uncompressed SEC1 point: 0x04 || x || y.
        let (Some((&4, xy)), 65) = (key_bytes.split_first(), key_bytes.len()) else {
            return Err(fail("leaf P-256 key is not an uncompressed point"));
        };
        let (x, y) = xy.split_at(32);
        AitpVerifyingKey::from_p256_affine(
            x.try_into().expect("32 bytes"),
            y.try_into().expect("32 bytes"),
        )
        .map_err(|e| fail(&format!("leaf key: {e}")))
    } else {
        Err(fail("leaf key is neither Ed25519 nor P-256"))
    }
}

/// The trust domain of a canonical SPIFFE ID with a workload path
/// (RFC-AITP-0002 §6.1). Rejects, without folding case, anything that is
/// not in canonical form.
fn spiffe_id_trust_domain(id: &str) -> Result<&str, HandshakeError> {
    if id.len() > MAX_SPIFFE_ID_LEN {
        return Err(fail("SPIFFE ID longer than 2048 bytes"));
    }
    let rest = id
        .strip_prefix("spiffe://")
        .ok_or_else(|| fail("subject is not a canonical spiffe:// ID"))?;
    let (trust_domain, path) = rest
        .find('/')
        .map(|i| rest.split_at(i))
        .ok_or_else(|| fail("SPIFFE ID has no workload path"))?;
    if !is_canonical_trust_domain(trust_domain) {
        return Err(fail("SPIFFE ID trust domain is not canonical"));
    }
    // `path` starts with '/'; every segment must be non-empty, not a
    // dot segment, and use only letters, digits, '.', '-' and '_'.
    for segment in path[1..].split('/') {
        let valid = !segment.is_empty()
            && segment != "."
            && segment != ".."
            && segment
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
        if !valid {
            return Err(fail("SPIFFE ID path is not canonical"));
        }
    }
    Ok(trust_domain)
}

fn is_canonical_trust_domain(td: &str) -> bool {
    !td.is_empty()
        && td.len() <= MAX_TRUST_DOMAIN_LEN
        && td.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_')
        })
}

/// Decode one `x5c` entry: a DER certificate in standard padded base64
/// (RFC 7517 §4.7).
fn decode_x5c_entry(entry: &str) -> Result<Vec<u8>, String> {
    base64ct::Base64::decode_vec(entry)
        .map_err(|e| format!("x5c entry is not standard base64: {e}"))
}

fn parse_certificate(der: &[u8]) -> Result<x509_parser::certificate::X509Certificate<'_>, String> {
    match x509_parser::parse_x509_certificate(der) {
        Ok(([], cert)) => Ok(cert),
        Ok(_) => Err("trailing bytes after certificate".into()),
        Err(e) => Err(format!("malformed certificate: {e}")),
    }
}

fn fail(msg: &str) -> HandshakeError {
    HandshakeError::Identity(format!("spiffe: {msg}"))
}

#[derive(Debug, Deserialize)]
struct JwtSvidClaims {
    sub: String,
    aud: Aud,
    exp: i64,
    iat: i64,
    nonce: String,
    cnf: Cnf,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Aud {
    Single(String),
    Multi(Vec<String>),
}

#[derive(Debug, Deserialize)]
struct Cnf {
    jkt: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwk::test_signers;
    use base64ct::{Base64UrlUnpadded, Encoding};
    use serde_json::json;

    /// Mints a JWT-SVID with header `alg`, signed by `sign`, verifies
    /// it against a bundle holding `jwk` as its one jwt-svid key.
    fn verify_jwt_svid_under(
        alg: &str,
        mut jwk: Value,
        sign: &dyn Fn(&[u8]) -> Vec<u8>,
    ) -> Result<(), HandshakeError> {
        let sender = Aid::parse("aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik").unwrap();
        let receiver =
            Aid::parse("aid:pubkey:A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg").unwrap();
        let subject = "spiffe://prod.example.com/ns/payments/sa/agent";
        let (now, nonce, message_id) = (1_800_000_000, "bQ88kiChryTKduskLXSCNg", Uuid::nil());
        let jkt = AitpVerifyingKey::from_aid(&sender)
            .and_then(|k| k.to_jwk_thumbprint())
            .unwrap();
        jwk["use"] = "jwt-svid".into();
        jwk["kid"] = "k1".into();
        let bundles = SpiffeBundleStore::from_config(
            &json!([{"trust_domain": "prod.example.com", "bundle": {"keys": [jwk]}}]),
        )
        .unwrap();
        let b64 = |v: Value| Base64UrlUnpadded::encode_string(v.to_string().as_bytes());
        let input = format!(
            "{}.{}",
            b64(json!({"alg": alg, "kid": "k1", "typ": "JWT"})),
            b64(
                json!({"sub": subject, "aud": receiver.as_str(), "exp": now + 60,
                "iat": now, "nonce": nonce, "cnf": {"jkt": jkt}})
            ),
        );
        let sig = Base64UrlUnpadded::encode_string(&sign(input.as_bytes()));
        let identity: IdentityDescriptor = serde_json::from_value(json!({
            "type": "spiffe", "subject": subject, "svid_type": "jwt-svid",
            "proof": format!("{input}.{sig}"),
        }))
        .unwrap();
        let ctx = SpiffeVerifyContext {
            bundles: &bundles,
            sender_aid: &sender,
            receiver_aid: &receiver,
            message_id: &message_id,
            timestamp: Timestamp(now),
            pop_nonce: nonce,
            iat_tolerance_secs: 300,
            now_unix_secs: now,
        };
        verify_spiffe(&identity, &ctx)
    }

    /// RFC-AITP-0002 §6.3: a JWT-SVID under each of the nine JWT-SVID
    /// §2.1 algorithms verifies end to end against its bundle key.
    #[test]
    fn jwt_svid_verifies_under_every_allowed_alg() {
        for alg in test_signers::JWT_SVID_ALGS {
            let (jwk, sign) = test_signers::signer(alg);
            verify_jwt_svid_under(alg.as_str(), jwk, &sign)
                .unwrap_or_else(|e| panic!("{alg}: {e}"));
        }
    }

    /// RFC-AITP-0002 §6.3: EdDSA is rejected for a JWT-SVID even when
    /// the bundle key is Ed25519 and the signature is valid, although
    /// `verify_jws_signature` accepts that pair (OIDC allows it).
    #[test]
    fn jwt_svid_rejects_eddsa_under_an_ed25519_key() {
        let key = aitp_crypto::AitpSigningKey::from_seed(&[4u8; 32]);
        let x = key.verifying_key().try_to_ed25519_bytes().unwrap();
        let jwk = json!({"kty": "OKP", "crv": "Ed25519",
            "x": Base64UrlUnpadded::encode_string(&x)});
        let sign = |m: &[u8]| key.sign_raw(m).to_vec();
        let err = verify_jwt_svid_under("EdDSA", jwk.clone(), &sign).unwrap_err();
        assert!(
            err.to_string().contains("alg \"EdDSA\" not allowed"),
            "{err}"
        );
        // The same pair passes the generic JWS check, so the rejection
        // above is the JWT-SVID allow-list, not a bad signature.
        let input = b"a.b";
        verify_jws_signature(
            &JwkPublicKey::from_jwk_json(&jwk).unwrap(),
            "EdDSA",
            input,
            &sign(input),
        )
        .unwrap();
    }

    #[test]
    fn trust_domain_of_canonical_id() {
        assert_eq!(
            spiffe_id_trust_domain("spiffe://prod.example.com/ns/payments/sa/agent").unwrap(),
            "prod.example.com"
        );
    }

    #[test]
    fn rejects_non_canonical_ids() {
        for id in [
            "SPIFFE://prod.example.com/a",
            "spiffe://Prod.example.com/a",
            "spiffe://prod.example.com",
            "spiffe://prod.example.com/",
            "spiffe://prod.example.com/a/",
            "spiffe://prod.example.com//a",
            "spiffe://prod.example.com/./a",
            "spiffe://prod.example.com/a/..",
            "spiffe://prod.example.com:8443/a",
            "spiffe://user@prod.example.com/a",
            "spiffe://prod.example.com/a?q=1",
            "spiffe://prod.example.com/a#f",
            "spiffe:///a",
            "https://prod.example.com/a",
        ] {
            assert!(spiffe_id_trust_domain(id).is_err(), "{id}");
        }
        let long = format!("spiffe://td/{}", "a".repeat(2048));
        assert!(spiffe_id_trust_domain(&long).is_err());
    }

    #[test]
    fn store_rejects_duplicate_trust_domain() {
        let cfg = json!([
            {"trust_domain": "prod.example.com", "bundle": {"keys": []}},
            {"trust_domain": "prod.example.com", "bundle": {"keys": []}}
        ]);
        assert!(matches!(
            SpiffeBundleStore::from_config(&cfg),
            Err(SpiffeConfigError::DuplicateTrustDomain(td)) if td == "prod.example.com"
        ));
    }

    #[test]
    fn store_rejects_non_canonical_trust_domain() {
        let cfg = json!([{"trust_domain": "Prod.example.com", "bundle": {"keys": []}}]);
        assert!(matches!(
            SpiffeBundleStore::from_config(&cfg),
            Err(SpiffeConfigError::InvalidTrustDomain(_))
        ));
    }

    #[test]
    fn bundle_requires_kid_on_jwt_svid_keys_and_ignores_unknown_use() {
        let key = json!({"kty": "EC", "crv": "P-256", "use": "jwt-svid",
            "x": base64url::encode(&[1u8; 32]), "y": base64url::encode(&[2u8; 32])});
        assert!(SpiffeBundle::from_jwk_set(&json!({"keys": [key]})).is_err());
        let mut unknown = key.clone();
        unknown["use"] = json!("sig");
        let b = SpiffeBundle::from_jwk_set(&json!({"keys": [unknown]})).unwrap();
        assert!(b.jwt_authorities.is_empty() && b.x509_authorities.is_empty());
    }

    #[test]
    fn bundle_rejects_x509_key_without_single_cert() {
        let key = json!({"kty": "EC", "crv": "P-256", "use": "x509-svid", "x5c": []});
        assert!(SpiffeBundle::from_jwk_set(&json!({"keys": [key]})).is_err());
    }
}
