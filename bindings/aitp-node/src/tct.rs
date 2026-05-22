//! TCT verification binding.

use aitp_core::Timestamp;
use aitp_crypto::{AitpSigningKey, AitpVerifyingKey};
use aitp_tct::{verify_tct, TctEnvelope, TctVerifyContext};
use napi::bindgen_prelude::*;
use napi_derive::napi;

/// The verified peer identity carried by a TCT.
#[napi(object)]
pub struct JsTctIdentity {
    /// AID of the agent that issued (and is bound by) the TCT.
    pub peer_aid: String,
    /// Capability grants the TCT authorizes.
    pub grants: Vec<String>,
    /// Expiry, Unix seconds.
    pub expires_at: f64,
    /// TCT unique identifier (`jti`).
    pub jti: String,
}

/// Verify `tct_json` against `our_key` as the audience, requiring
/// `required_grant`. Returns a rejected `Result` on any failure.
pub fn js_verify_tct(
    our_key: &AitpSigningKey,
    tct_json: &str,
    required_grant: &str,
) -> Result<JsTctIdentity> {
    let envelope: TctEnvelope = serde_json::from_str(tct_json)
        .map_err(|e| Error::from_reason(format!("invalid TCT JSON: {e}")))?;

    let issuer_pk = AitpVerifyingKey::from_aid(&envelope.tct.issuer)
        .map_err(|e| Error::from_reason(format!("bad issuer AID: {e}")))?;

    let ctx = TctVerifyContext {
        expected_audience: our_key.aid(),
        issuer_pubkey: &issuer_pk,
        now: Timestamp::now(),
        issuer_manifest_expires_at: None,
        revocation_check: None,
    };

    let tct = verify_tct(&envelope.tct, &ctx)
        .map_err(|e| Error::from_reason(format!("TCT verification failed: {e}")))?;

    if !tct.grants.iter().any(|g| g == required_grant) {
        return Err(Error::from_reason(format!(
            "TCT does not grant '{required_grant}'; grants: {:?}",
            tct.grants
        )));
    }

    Ok(JsTctIdentity {
        peer_aid: tct.issuer.to_string(),
        grants: tct.grants.clone(),
        expires_at: tct.expires_at.0 as f64,
        jti: tct.jti.to_string(),
    })
}
