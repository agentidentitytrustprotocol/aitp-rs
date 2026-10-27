//! Shared helpers: JWKS resolvers and `PeerConfig` construction.
//!
//! A pinned-key-only handshake uses [`NoOpJwksResolver`], which fails
//! every JWKS resolution so an unexpected OIDC peer is rejected rather
//! than silently trusted. OIDC-mode sessions supply a real resolver via
//! [`crate::oidc::PyJwksProvider`] threaded through `make_peer_config`.

use aitp::core::{RawUrl, Timestamp};
use aitp::crypto::AitpSigningKey;
use aitp::handshake::{JwkPublicKey, JwksResolver, PeerConfig, PinnedKeyStore, ResolveError};
use aitp::manifest::Manifest;
use url::Url;

/// A JWKS resolver that always fails. Used for pinned-key-only sessions.
pub struct NoOpJwksResolver;

impl JwksResolver for NoOpJwksResolver {
    fn resolve(&self, _issuer: &Url) -> Result<Vec<JwkPublicKey>, ResolveError> {
        Err(ResolveError::NetworkError(
            "no JWKS resolver configured for this session (pinned-key only)".into(),
        ))
    }
}

/// Build a [`PeerConfig`] with the supplied resolver, trust anchors and
/// pinned-key trust store.
///
/// SDK sessions pass `&NoOpJwksResolver` for pinned-key mode and a real
/// resolver (e.g. `JwksProvider`) for OIDC mode. `pinned_keys` is the
/// session's local pinned-key trust store (RFC-AITP-0002 §3.2): a
/// `pinned_key` peer is accepted only if its key is in it, and the store
/// is consulted before the proof is verified. It is REQUIRED; an empty
/// store rejects every pinned-key peer. `revocation` is the step's
/// revocation source (see [`BindingRevocation`]); `grant_policy` stays
/// unset for the binding surface.
pub fn make_peer_config<'a>(
    key: &'a AitpSigningKey,
    manifest: &'a Manifest,
    jwks: &'a (dyn JwksResolver + 'a),
    trust_anchors: &'a [RawUrl],
    pinned_keys: &'a dyn PinnedKeyStore,
    revocation: aitp::handshake::RevocationSource<'a>,
) -> PeerConfig<'a> {
    PeerConfig::new(
        key,
        manifest,
        jwks,
        pinned_keys,
        revocation,
        Timestamp::now(),
    )
    .with_trust_anchors(trust_anchors)
}

/// Parse a wire-bound UUID v4 strictly (RFC-AITP-0001 §5.2): lowercase
/// hyphenated, version 4, RFC 9562 variant, via
/// [`aitp::core::ids::parse_v4`]. Uppercase, braced, `urn:uuid:`,
/// unhyphenated and non-v4 forms are refused: the value is signed or sent
/// as given, so it must already be in wire form. The error names `field`.
pub fn parse_strict_v4(field: &str, s: &str) -> Result<uuid::Uuid, String> {
    aitp::core::ids::parse_v4(s)
        .map_err(|e| format!("{field} is not a lowercase UUID v4: {s} ({e})"))
}

/// Parse a revoked-`jti` deny list into a lookup set.
///
/// The set is a lookup key only, never signed or sent, so it is lenient:
/// an entry may be in any RFC 9562 text form (uppercase, braced,
/// `urn:uuid:`, unhyphenated) and is normalized before matching. A non-v4
/// entry is accepted but can never match, since every verified `jti` is
/// v4. An entry that is not a UUID at all is refused rather than dropped,
/// so a malformed list fails closed.
pub fn parse_revoked_jtis<'a, I>(jtis: I) -> Result<std::collections::HashSet<uuid::Uuid>, String>
where
    I: IntoIterator<Item = &'a str>,
{
    jtis.into_iter()
        .map(|s| {
            uuid::Uuid::parse_str(s)
                .map_err(|e| format!("revoked_jtis entry is not a UUID: {s} ({e})"))
        })
        .collect()
}

/// How a binding call sources revocation status (RFC-AITP-0008 §3.1).
///
/// Built by [`binding_revocation`] from the caller's optional deny list
/// and `revocation` mode. With no deny list the default is `fail_closed`:
/// every lookup reports the status as unavailable, so the TCT (or
/// delegation) is rejected with the revocation code rather than accepted.
pub enum BindingRevocation {
    /// The issuer's deny list as supplied: a `jti` in it is revoked,
    /// anything else is not.
    DenyList(std::collections::HashSet<uuid::Uuid>),
    /// No deny list under `fail_closed`.
    Unavailable,
    /// No deny list under an explicit `fail_open`: no lookup at all.
    FailOpen,
}

/// The `RevocationUnavailable` reason a binding reports when no deny list
/// was supplied under `fail_closed`.
pub const NO_DENY_LIST: &str =
    "no revoked_jtis supplied (pass revocation=\"fail_open\" to opt out)";

/// Parse the caller's deny list and `revocation` mode (`"fail_closed"`,
/// the default, or `"fail_open"`). A supplied list, even an empty one, is
/// authoritative in either mode; the mode only decides what an absent
/// list means.
pub fn binding_revocation<'a, I>(
    revoked_jtis: Option<I>,
    mode: Option<&str>,
) -> Result<BindingRevocation, String>
where
    I: IntoIterator<Item = &'a str>,
{
    let fail_open = match mode.unwrap_or("fail_closed") {
        "fail_closed" => false,
        "fail_open" => true,
        other => {
            return Err(format!(
                "revocation must be \"fail_closed\" or \"fail_open\", got {other:?}"
            ))
        }
    };
    Ok(match revoked_jtis {
        Some(jtis) => BindingRevocation::DenyList(parse_revoked_jtis(jtis)?),
        None if fail_open => BindingRevocation::FailOpen,
        None => BindingRevocation::Unavailable,
    })
}

impl BindingRevocation {
    /// TCT-verifier lookup ([`aitp::tct::RevocationCheckFn`] contract).
    pub fn tct_status(&self, jti: &uuid::Uuid) -> Result<bool, aitp::tct::TctError> {
        match self {
            Self::DenyList(set) => Ok(set.contains(jti)),
            Self::Unavailable => Err(aitp::tct::TctError::RevocationUnavailable(
                NO_DENY_LIST.into(),
            )),
            Self::FailOpen => Ok(false),
        }
    }

    /// Delegation-verifier lookup ([`aitp::delegation::SourceRevocationCheck`]
    /// contract).
    pub fn delegation_status(
        &self,
        jti: &uuid::Uuid,
    ) -> Result<bool, aitp::delegation::DelegationError> {
        match self {
            Self::DenyList(set) => Ok(set.contains(jti)),
            Self::Unavailable => Err(aitp::delegation::DelegationError::RevocationUnavailable(
                NO_DENY_LIST.into(),
            )),
            Self::FailOpen => Ok(false),
        }
    }

    /// Handshake lookup ([`aitp::handshake::RevocationCheckFn`] contract).
    /// The deny list is the peer issuer's, so the issuer is not consulted.
    pub fn handshake_decision(
        &self,
        jti: &uuid::Uuid,
    ) -> Result<aitp::handshake::HandshakeRevocationDecision, aitp::handshake::HandshakeError> {
        use aitp::handshake::HandshakeRevocationDecision::{Clear, Revoked};
        self.tct_status(jti)
            .map(|revoked| if revoked { Revoked } else { Clear })
            .map_err(aitp::handshake::HandshakeError::Tct)
    }

    /// Whether this is the explicit `fail_open` opt-out.
    pub fn is_fail_open(&self) -> bool {
        matches!(self, Self::FailOpen)
    }
}

/// The wire error code for a revocation rejection, or `None` for any
/// other failure. Matches the Rust adapter's mapping: revoked and
/// unavailable share the code, and the message tells them apart.
pub fn tct_revocation_code(e: &aitp::tct::TctError) -> Option<&'static str> {
    use aitp::tct::TctError::{RevocationUnavailable, Revoked};
    matches!(e, Revoked | RevocationUnavailable(_)).then_some("TCT_REVOKED")
}

/// The wire error code for a handshake failure (`IDENTITY_FAILED`,
/// `INCOMPATIBLE_IDENTITY_TYPE`, `TCT_REVOKED`, ...), as the HTTP
/// transport reports it.
pub fn handshake_code(e: &aitp::handshake::HandshakeError) -> Option<String> {
    serde_json::to_value(e.error_code())
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
}

/// [`tct_revocation_code`] for a delegation failure (RFC-AITP-0006 §4
/// step 7).
pub fn delegation_revocation_code(e: &aitp::delegation::DelegationError) -> Option<&'static str> {
    use aitp::delegation::DelegationError::{RevocationUnavailable, SourceTctRevoked};
    matches!(e, SourceTctRevoked | RevocationUnavailable(_))
        .then_some("DELEGATION_SOURCE_TCT_REVOKED")
}

/// Revocation lookup for a handshake step that verifies no TCT (HELLO,
/// HELLO_ACK). Never called; if it were, it would fail closed.
fn no_tct_step(
    _: &aitp::core::Aid,
    _: &uuid::Uuid,
) -> Result<aitp::handshake::HandshakeRevocationDecision, aitp::handshake::HandshakeError> {
    Err(aitp::handshake::HandshakeError::Tct(
        aitp::tct::TctError::RevocationUnavailable("no TCT is verified at this step".into()),
    ))
}

/// [`aitp::handshake::RevocationSource`] for the steps that verify no TCT.
pub const NO_TCT_STEP: aitp::handshake::RevocationSource<'static> =
    aitp::handshake::RevocationSource::Check(&no_tct_step);

/// A `RuntimeError` carrying `code` as a stable `code` attribute when one
/// applies (see [`tct_revocation_code`]); branch on `code`, not the text.
pub fn runtime_error(message: String, code: Option<&str>) -> pyo3::PyErr {
    use pyo3::prelude::*;
    let err = pyo3::exceptions::PyRuntimeError::new_err(message);
    if let Some(code) = code {
        Python::attach(|py| {
            // Best-effort, as elsewhere: the exception still fails closed.
            let _ = err.value(py).setattr("code", code);
        });
    }
    err
}
