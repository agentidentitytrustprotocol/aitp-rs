//! TCT verification binding.

use aitp_core::{Aid, Timestamp};
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

/// Verify `tct_json`, requiring `required_grant`.
///
/// The audience check is controlled by `expected_audience`:
/// - `None`: use `our_key.aid()` — the **holder-receipt** model from
///   RFC-AITP-0005 §9, where the holder verifies a TCT it received as its
///   own receipt.
/// - `Some(aid)`: use the supplied AID — the **presented-TCT** model used by
///   resource servers verifying a TCT a peer presents in `X-AITP-TCT`.
///
/// The signature check is the security gate in either mode: the TCT is
/// verified against `tct.issuer`'s pubkey.
pub fn js_verify_tct(
    our_key: &AitpSigningKey,
    tct_json: &str,
    required_grant: &str,
    expected_audience: Option<&str>,
) -> Result<JsTctIdentity> {
    let envelope: TctEnvelope = serde_json::from_str(tct_json)
        .map_err(|e| Error::from_reason(format!("invalid TCT JSON: {e}")))?;

    let issuer_pk = AitpVerifyingKey::from_aid(&envelope.tct.issuer)
        .map_err(|e| Error::from_reason(format!("bad issuer AID: {e}")))?;

    let audience_owned: Aid;
    let aud_ref: &Aid = match expected_audience {
        Some(s) => {
            audience_owned = Aid::parse(s)
                .map_err(|e| Error::from_reason(format!("bad expected_audience AID '{s}': {e}")))?;
            &audience_owned
        }
        None => our_key.aid(),
    };

    let ctx = TctVerifyContext {
        expected_audience: aud_ref,
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
