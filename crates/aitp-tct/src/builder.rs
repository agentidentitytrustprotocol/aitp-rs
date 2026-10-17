//! TCT + grant-voucher issuance (RFC-AITP-0005 §1 / §8).

use crate::types::{Cnf, GrantVoucherClaims, IssuedTct, TctClaims};
use crate::TctError;
use aitp_core::{Aid, Timestamp, PROTOCOL_VERSION};
use aitp_crypto::{jws, AitpSigner, AitpVerifyingKey, DynAsyncAitpSigner};
use uuid::Uuid;

/// Fluent builder for issuing a TCT and its companion grant voucher.
///
/// ```ignore
/// let issued = TctBuilder::new(&issuer_key)
///     .subject(subject_aid.clone())
///     .audience(subject_aid.clone())          // v0.2: audience == subject
///     .grants(["demo.echo"])
///     .ttl_secs(3600)
///     .subject_pubkey(subject_verifying_key)
///     .build()?;
/// // issued.token   — the TCT compact JWS
/// // issued.voucher — the grant voucher compact JWS (Some by default)
/// ```
///
/// With an async (KMS, HSM) signer, start from [`TctBuilder::new_async`]
/// and finish with [`TctBuilder::build_async`]; the setters are shared.
/// The signer kind is a type parameter, so a sync builder has no
/// `build_async` and an async one has no `build`.
pub struct TctBuilder<'a, S: ?Sized + 'a = dyn AitpSigner + 'a> {
    issuer_key: &'a S,
    subject: Option<Aid>,
    audience: Option<Aid>,
    grants: Vec<String>,
    ttl_secs: i64,
    subject_pubkey: Option<AitpVerifyingKey>,
    mint_voucher: bool,
    /// Override `issued_at` for tests / fixed-clock scenarios.
    now_override: Option<Timestamp>,
    /// Override `jti` for tests / fixtures.
    jti_override: Option<Uuid>,
}

impl<'a> TctBuilder<'a, dyn AitpSigner + 'a> {
    /// Begin a new TCT, signed by `issuer_key`.
    ///
    /// Accepts any [`AitpSigner`] (in-process key, KMS, HSM); a backend
    /// failure surfaces from [`Self::build`] as
    /// `TctError::Crypto(CryptoError::Signer(_))`.
    pub fn new(issuer_key: &'a dyn AitpSigner) -> Self {
        Self::with_issuer(issuer_key)
    }

    /// Construct, sign, and return the TCT (and companion voucher).
    pub fn build(self) -> Result<IssuedTct, TctError> {
        let (draft, signer) = self.draft()?;
        let token =
            jws::sign_compact(signer, jws::TYP_TCT, &draft.claims).map_err(TctError::Crypto)?;
        let voucher = match &draft.voucher {
            Some(v) => Some(
                jws::sign_compact(signer, jws::TYP_GRANT_VOUCHER, v).map_err(TctError::Crypto)?,
            ),
            None => None,
        };
        Ok(draft.finish(token, voucher))
    }
}

impl<'a> TctBuilder<'a, dyn DynAsyncAitpSigner + 'a> {
    /// Begin a new TCT signed by an async backend, for example
    /// `TctBuilder::new_async(&*arc_kms_signer)`. Finish with
    /// [`Self::build_async`].
    pub fn new_async(issuer_key: &'a dyn DynAsyncAitpSigner) -> Self {
        Self::with_issuer(issuer_key)
    }

    /// As [`TctBuilder::build`], awaiting the backend. The TCT and the
    /// voucher are two sequential backend calls; the future is `Send`.
    pub async fn build_async(self) -> Result<IssuedTct, TctError> {
        let (draft, signer) = self.draft()?;
        let token = jws::sign_compact_async(signer, jws::TYP_TCT, &draft.claims)
            .await
            .map_err(TctError::Crypto)?;
        let voucher = match &draft.voucher {
            Some(v) => Some(
                jws::sign_compact_async(signer, jws::TYP_GRANT_VOUCHER, v)
                    .await
                    .map_err(TctError::Crypto)?,
            ),
            None => None,
        };
        Ok(draft.finish(token, voucher))
    }
}

/// Claims ready to sign.
struct Draft {
    claims: TctClaims,
    voucher: Option<GrantVoucherClaims>,
}

impl Draft {
    fn finish(self, token: String, voucher: Option<String>) -> IssuedTct {
        IssuedTct {
            token,
            claims: self.claims,
            voucher,
        }
    }
}

/// The issuer's AID, whichever signer kind holds it.
trait IssuerAid {
    fn issuer_aid(&self) -> &Aid;
}
impl IssuerAid for dyn AitpSigner + '_ {
    fn issuer_aid(&self) -> &Aid {
        self.aid()
    }
}
impl IssuerAid for dyn DynAsyncAitpSigner + '_ {
    fn issuer_aid(&self) -> &Aid {
        self.aid()
    }
}

#[allow(private_bounds)]
impl<'a, S: ?Sized + IssuerAid> TctBuilder<'a, S> {
    fn with_issuer(issuer_key: &'a S) -> Self {
        Self {
            issuer_key,
            subject: None,
            audience: None,
            grants: Vec::new(),
            ttl_secs: crate::DEFAULT_TCT_TTL_SECS,
            subject_pubkey: None,
            mint_voucher: true,
            now_override: None,
            jti_override: None,
        }
    }

    /// Set the subject AID.
    pub fn subject(mut self, subject: Aid) -> Self {
        self.subject = Some(subject);
        self
    }

    /// Set the audience AID. In v0.2 audience MUST equal subject.
    pub fn audience(mut self, audience: Aid) -> Self {
        self.audience = Some(audience);
        self
    }

    /// Set the granted capabilities.
    pub fn grants<I, G>(mut self, grants: I) -> Self
    where
        I: IntoIterator<Item = G>,
        G: Into<String>,
    {
        self.grants = grants.into_iter().map(Into::into).collect();
        self
    }

    /// Override the default TTL.
    pub fn ttl_secs(mut self, ttl: i64) -> Self {
        self.ttl_secs = ttl;
        self
    }

    /// Set the subject's verifying key, used to derive `cnf.jkt`.
    pub fn subject_pubkey(mut self, pk: AitpVerifyingKey) -> Self {
        self.subject_pubkey = Some(pk);
        self
    }

    /// Decline to mint the companion grant voucher (RFC-AITP-0005
    /// §8.2: issuer policy MAY forbid the subject from delegating; the
    /// commit payload then carries only the TCT).
    pub fn without_voucher(mut self) -> Self {
        self.mint_voucher = false;
        self
    }

    /// Override `issued_at`. Tests/fixtures only.
    pub fn issued_at(mut self, ts: Timestamp) -> Self {
        self.now_override = Some(ts);
        self
    }

    /// Override the generated `jti`. Tests/fixtures only.
    pub fn jti(mut self, jti: Uuid) -> Self {
        self.jti_override = Some(jti);
        self
    }

    /// Validate and assemble the claims; signing is the caller's.
    fn draft(self) -> Result<(Draft, &'a S), TctError> {
        let issuer = self.issuer_key.issuer_aid().clone();
        let subject = self.subject.ok_or(TctError::MissingField("subject"))?;
        let audience = self.audience.ok_or(TctError::MissingField("audience"))?;
        let subject_pk = self
            .subject_pubkey
            .ok_or(TctError::MissingField("subject_pubkey"))?;
        if self.grants.is_empty() {
            return Err(TctError::EmptyGrants);
        }
        // RFC-AITP-0005 §4.2: "Grants MUST NOT contain whitespace."
        for g in &self.grants {
            if g.chars().any(char::is_whitespace) {
                return Err(TctError::GrantWhitespace(g.clone()));
            }
        }
        if subject != audience {
            // v0.2 invariant: audience must equal subject.
            return Err(TctError::AudienceMismatch);
        }
        // §3: cnf.jkt MUST be the thumbprint of the key the subject AID
        // encodes — refuse to mint a TCT that binds a different key.
        if subject_pk.to_compressed() != subject.pubkey_compressed_bytes() {
            return Err(TctError::CnfMalformed);
        }

        let jkt = subject_pk.to_jwk_thumbprint().map_err(TctError::Crypto)?;
        let jti = self.jti_override.unwrap_or_else(Uuid::new_v4);
        let issued_at = self.now_override.unwrap_or_else(Timestamp::now);
        let expires_at = issued_at.plus_secs(self.ttl_secs);

        let claims = TctClaims {
            ver: PROTOCOL_VERSION.into(),
            jti,
            iss: issuer.clone(),
            sub: subject.clone(),
            aud: audience,
            iat: issued_at,
            exp: expires_at,
            grants: self.grants.clone(),
            cnf: Cnf { jkt },
            ext: None,
        };
        // §8.2: voucher claims mirror the companion TCT exactly.
        let voucher = self.mint_voucher.then(|| GrantVoucherClaims {
            ver: PROTOCOL_VERSION.into(),
            iss: issuer,
            sub: subject,
            grants: self.grants,
            iat: issued_at,
            exp: expires_at,
            src_jti: jti,
            ext: None,
        });
        Ok((Draft { claims, voucher }, self.issuer_key))
    }
}
