//! Minting for the `spiffe` identity fixtures (`id-024` to `id-030`,
//! PLACEHOLDERS.md "SPIFFE test authorities").
//!
//! Two test authorities for the trust domain `prod.example.com`:
//!
//! - a P-256 JWT-SVID signing key (`ES256`, `kid`
//!   `aitp-test-spiffe-jwt-1`), from a fixed scalar, so its JWK and every
//!   JWT-SVID signature are byte-stable; and
//! - a self-signed P-256 X.509 CA. rcgen draws its key and ECDSA nonces at
//!   random, so the CA is generated once per process and its JWK and the
//!   leaves it issues agree within a run, not across runs.
//!
//! The X509-SVID leaf key is kat-keypair-003 (Ed25519, seed `0xff` × 32),
//! the signer of `kat-spiffe-x509-proof-001`.

use std::sync::OnceLock;

use aitp_core::base64url;
use aitp_crypto::{AitpSigningKey, AitpVerifyingKey, Digest32};
use base64ct::Encoding as _;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    PublicKeyData, SanType, SignatureAlgorithm,
};
use serde_json::{json, Map, Value};

use super::placeholder::handshake_proof_input;

pub(super) const JWT_AUTHORITY_JWK: &str = "__TEST_SPIFFE_JWT_AUTHORITY_JWK__";
pub(super) const X509_CA_JWK: &str = "__TEST_SPIFFE_X509_CA_JWK__";
const VALID_JWT_SVID: &str = "__VALID_JWT_SVID__";
const JWT_SVID_WRONG_NONCE: &str = "__JWT_SVID_WRONG_NONCE__";
const JWT_SVID_EXPIRED: &str = "__JWT_SVID_EXPIRED__";
const JWT_SVID_AUD_DIFFERENT_PEER: &str = "__JWT_SVID_AUD_DIFFERENT_PEER__";
const JWT_SVID_STAGING_SUBJECT: &str = "__JWT_SVID_STAGING_SUBJECT_PROD_KEY__";
const X509_SVID_LEAF: &str = "__X509_SVID_LEAF__";
const X509_SVID_LEAF_TWO_URI_SANS: &str = "__X509_SVID_LEAF_TWO_URI_SANS__";
const VALID_X509_SVID_PROOF: &str = "__VALID_X509_SVID_PROOF__";

/// JWT-SVID authority `kid` (PLACEHOLDERS.md).
const JWT_AUTHORITY_KID: &str = "aitp-test-spiffe-jwt-1";
/// JWT-SVID authority private scalar. Any valid P-256 scalar would do;
/// this one is not a KAT key.
const JWT_AUTHORITY_SCALAR: [u8; 32] = [0x5au8; 32];
/// `__JWT_SVID_WRONG_NONCE__`'s `nonce`: the 16 bytes `aitp-spiffe-jwt9`.
const WRONG_NONCE: &str = "YWl0cC1zcGlmZmUtand0OQ";
/// `__JWT_SVID_AUD_DIFFERENT_PEER__`'s audience: kat-keypair-004.
const OTHER_PEER_AUD: &str = "aid:pubkey:iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w";
/// The second URI SAN of `__X509_SVID_LEAF_TWO_URI_SANS__`.
const SECOND_URI_SAN: &str = "spiffe://prod.example.com/ns/payments/sa/other";
/// kat-keypair-003's seed: the X509-SVID leaf key.
const LEAF_SEED: [u8; 32] = [0xffu8; 32];
/// RFC-AITP-0002 §6.4.1 domain prefix.
pub(super) const X509_PROOF_DOMAIN: &[u8] = b"aitp-spiffe-x509-v1\0";

pub(super) fn is_spiffe_placeholder(s: &str) -> bool {
    matches!(
        s,
        JWT_AUTHORITY_JWK
            | X509_CA_JWK
            | VALID_JWT_SVID
            | JWT_SVID_WRONG_NONCE
            | JWT_SVID_EXPIRED
            | JWT_SVID_AUD_DIFFERENT_PEER
            | JWT_SVID_STAGING_SUBJECT
            | X509_SVID_LEAF
            | X509_SVID_LEAF_TWO_URI_SANS
            | VALID_X509_SVID_PROOF
    )
}

/// Mint every SPIFFE placeholder under `value`. `self_aid` is the
/// fixture's verifier (JWT-SVID `aud`, §6.4.1 `receiver`).
pub(super) fn substitute(value: &mut Value, self_aid: Option<&str>, now: i64) {
    match value {
        Value::String(s) if s == JWT_AUTHORITY_JWK => *value = jwt_authority_jwk(),
        Value::String(s) if s == X509_CA_JWK => *value = x509_ca_jwk(now),
        Value::Array(items) => {
            for item in items {
                substitute(item, self_aid, now);
            }
        }
        Value::Object(map) => {
            for v in map.values_mut() {
                substitute(v, self_aid, now);
            }
            if let Some(self_aid) = self_aid {
                mint_at_envelope(map, self_aid, now);
            }
        }
        _ => {}
    }
}

/// If `map` is an envelope carrying a `spiffe` identity, mint its
/// JWT-SVID, its `x5c` leaves and its X509-SVID proof.
fn mint_at_envelope(map: &mut Map<String, Value>, self_aid: &str, now: i64) {
    let Some(ctx) = EnvelopeCtx::read(map) else {
        return;
    };
    let Some(identity) = map
        .get_mut("payload")
        .and_then(|p| p.get_mut("identity"))
        .and_then(Value::as_object_mut)
    else {
        return;
    };
    let subject = identity
        .get("subject")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    if let Some(Value::Array(x5c)) = identity.get_mut("x5c") {
        for entry in x5c.iter_mut() {
            let extra_san = match entry.as_str() {
                Some(X509_SVID_LEAF) => None,
                Some(X509_SVID_LEAF_TWO_URI_SANS) => Some(SECOND_URI_SAN),
                _ => continue,
            };
            *entry = Value::from(mint_leaf(&subject, extra_san, now));
        }
    }
    let minted = match identity.get("proof").and_then(Value::as_str) {
        Some(VALID_X509_SVID_PROOF) => ctx.x509_proof(self_aid),
        Some(
            p @ (VALID_JWT_SVID
            | JWT_SVID_WRONG_NONCE
            | JWT_SVID_EXPIRED
            | JWT_SVID_AUD_DIFFERENT_PEER
            | JWT_SVID_STAGING_SUBJECT),
        ) => ctx.jwt_svid(p, &subject, self_aid, now),
        _ => None,
    };
    if let Some(minted) = minted {
        identity.insert("proof".into(), Value::from(minted));
    }
}

struct EnvelopeCtx {
    sender: String,
    message_id: String,
    timestamp: i64,
    pop_nonce: String,
}

impl EnvelopeCtx {
    fn read(map: &Map<String, Value>) -> Option<Self> {
        let payload = map.get("payload")?;
        Some(Self {
            sender: map.get("sender")?.get("agent_id")?.as_str()?.to_owned(),
            message_id: map.get("message_id")?.as_str()?.to_owned(),
            timestamp: map.get("timestamp")?.as_i64()?,
            pop_nonce: payload.get("pop_nonce")?.as_str()?.to_owned(),
        })
    }

    /// The §6.4.1 proof by the leaf key over this envelope.
    fn x509_proof(&self, self_aid: &str) -> Option<String> {
        let input = handshake_proof_input(
            X509_PROOF_DOMAIN,
            &self.sender,
            self_aid,
            &self.message_id,
            self.timestamp,
            &self.pop_nonce,
        )?;
        let key = AitpSigningKey::from_seed(&LEAF_SEED);
        Some(key.sign_jcs(&Digest32::sha256(&input)).into_string())
    }

    /// A JWT-SVID per `__VALID_JWT_SVID__`, broken as `placeholder` says.
    fn jwt_svid(
        &self,
        placeholder: &str,
        subject: &str,
        self_aid: &str,
        now: i64,
    ) -> Option<String> {
        let sender = aitp_core::Aid::parse(&self.sender).ok()?;
        let jkt = AitpVerifyingKey::from_aid(&sender)
            .ok()?
            .to_jwk_thumbprint()
            .ok()?;
        let (aud, iat, exp, nonce) = match placeholder {
            JWT_SVID_WRONG_NONCE => (self_aid, now, now + 300, WRONG_NONCE),
            JWT_SVID_EXPIRED => (self_aid, now - 360, now - 60, self.pop_nonce.as_str()),
            JWT_SVID_AUD_DIFFERENT_PEER => {
                (OTHER_PEER_AUD, now, now + 300, self.pop_nonce.as_str())
            }
            // `__JWT_SVID_STAGING_SUBJECT_PROD_KEY__` differs only in the
            // fixture's subject, which `sub` already copies.
            _ => (self_aid, now, now + 300, self.pop_nonce.as_str()),
        };
        let claims = json!({
            "sub": subject,
            "aud": [aud],
            "iat": iat,
            "exp": exp,
            "nonce": nonce,
            "cnf": { "jkt": jkt },
        });
        let header = format!(r#"{{"alg":"ES256","kid":"{JWT_AUTHORITY_KID}","typ":"JWT"}}"#);
        let signing_input = format!(
            "{}.{}",
            base64url::encode(header.as_bytes()),
            base64url::encode(claims.to_string().as_bytes())
        );
        let sig = jwt_authority_key().sign_raw(signing_input.as_bytes());
        Some(format!("{signing_input}.{}", base64url::encode(&sig)))
    }
}

fn jwt_authority_key() -> AitpSigningKey {
    AitpSigningKey::from_p256_seed(&JWT_AUTHORITY_SCALAR).expect("valid P-256 scalar")
}

/// `__TEST_SPIFFE_JWT_AUTHORITY_JWK__`.
fn jwt_authority_jwk() -> Value {
    let secret = p256::ecdsa::SigningKey::from_bytes(&JWT_AUTHORITY_SCALAR.into())
        .expect("valid P-256 scalar");
    let point = secret.verifying_key().to_sec1_point(false);
    let (x, y) = point.as_bytes()[1..].split_at(32);
    json!({
        "kty": "EC",
        "crv": "P-256",
        "x": base64url::encode(x),
        "y": base64url::encode(y),
        "kid": JWT_AUTHORITY_KID,
        "use": "jwt-svid",
        "alg": "ES256",
    })
}

struct TestCa {
    der: Vec<u8>,
    issuer: Issuer<'static, KeyPair>,
}

/// The process-wide test CA, valid from an hour before `now` for a day.
fn test_ca(now: i64) -> &'static TestCa {
    static CA: OnceLock<TestCa> = OnceLock::new();
    CA.get_or_init(|| {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("P-256 key");
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "aitp-conformance SPIFFE test CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.subject_alt_names = vec![SanType::URI(
            "spiffe://prod.example.com".try_into().expect("ia5 string"),
        )];
        params.not_before = unix(now - 3600);
        params.not_after = unix(now + 86_400);
        let der = params
            .self_signed(&key)
            .expect("self-signed CA")
            .der()
            .to_vec();
        TestCa {
            der,
            issuer: Issuer::new(params, key),
        }
    })
}

/// `__TEST_SPIFFE_X509_CA_JWK__`: the CA's public JWK with the CA
/// certificate as its one `x5c` entry.
fn x509_ca_jwk(now: i64) -> Value {
    let ca = test_ca(now);
    let point = ca.issuer.key().public_key_raw();
    let (x, y) = point[1..].split_at(32);
    json!({
        "kty": "EC",
        "crv": "P-256",
        "x": base64url::encode(x),
        "y": base64url::encode(y),
        "use": "x509-svid",
        "x5c": [base64ct::Base64::encode_string(&ca.der)],
    })
}

/// kat-keypair-003's Ed25519 public key, as rcgen subject key data.
struct LeafKey([u8; 32]);

impl PublicKeyData for LeafKey {
    fn der_bytes(&self) -> &[u8] {
        &self.0
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &rcgen::PKCS_ED25519
    }
}

/// An X509-SVID for `subject` (plus `extra_san`, if any), issued by the
/// test CA, in standard base64.
fn mint_leaf(subject: &str, extra_san: Option<&str>, now: i64) -> String {
    let leaf_key = LeafKey(
        AitpSigningKey::from_seed(&LEAF_SEED)
            .verifying_key()
            .try_to_ed25519_bytes()
            .expect("kat-keypair-003 is Ed25519"),
    );
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.subject_alt_names = std::iter::once(subject)
        .chain(extra_san)
        .map(|uri| SanType::URI(uri.try_into().expect("ia5 string")))
        .collect();
    params.not_before = unix(now - 60);
    params.not_after = unix(now + 3600);
    let cert = params
        .signed_by(&leaf_key, &test_ca(now).issuer)
        .expect("leaf certificate");
    base64ct::Base64::encode_string(cert.der())
}

fn unix(secs: i64) -> time::OffsetDateTime {
    time::OffsetDateTime::from_unix_timestamp(secs).expect("in range")
}
