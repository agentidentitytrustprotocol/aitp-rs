//! Wire-form parsing for the Session Trust Bundle transport envelope
//! (RFC-AITP-0010 §3).

use crate::error::SessionBundleError;
use crate::types::{SessionBundleEnvelope, SessionTrustBundle};
use serde_json::Value;

/// Parse a session bundle from its on-the-wire JSON.
///
/// Accepts the spec transport envelope `{"session_bundle": {<body incl.
/// `signature`>}}` and, for internal callers that never wrap, a bare
/// body. The wrapper is `additionalProperties: false`: any member
/// besides `session_bundle` — notably the pre-erratum sibling
/// `signature` — is rejected with
/// [`SessionBundleError::WireFormInvalid`], which the error-code
/// mapping surfaces as `SESSION_BUNDLE_INVALID`.
pub fn parse_session_bundle_wire(value: &Value) -> Result<SessionTrustBundle, SessionBundleError> {
    if value.get("session_bundle").is_some() {
        let env: SessionBundleEnvelope = serde_json::from_value(value.clone()).map_err(|e| {
            SessionBundleError::WireFormInvalid(format!(
                "transport envelope: {e} (RFC-AITP-0010 §3 places `signature` \
                 inside the signed body, never beside the wrapper)"
            ))
        })?;
        Ok(env.session_bundle)
    } else {
        serde_json::from_value(value.clone())
            .map_err(|e| SessionBundleError::WireFormInvalid(format!("bundle body: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn valid_body() -> Value {
        json!({
            "version": "aitp/0.2",
            "session_id": "00000000-0000-4000-8000-000000000000",
            "coordinator": "aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik",
            "issued_at": 1_700_000_000,
            "expires_at": 1_700_010_000,
            "participants": [],
            "signature": "A".repeat(86),
        })
    }

    #[test]
    fn wrapped_with_signature_inside_parses() {
        let wire = json!({ "session_bundle": valid_body() });
        assert!(parse_session_bundle_wire(&wire).is_ok());
    }

    #[test]
    fn bare_body_parses() {
        assert!(parse_session_bundle_wire(&valid_body()).is_ok());
    }

    #[test]
    fn sibling_signature_is_rejected() {
        let mut body = valid_body();
        let signature = body.as_object_mut().unwrap().remove("signature").unwrap();
        let wire = json!({ "session_bundle": body, "signature": signature });
        assert!(matches!(
            parse_session_bundle_wire(&wire),
            Err(SessionBundleError::WireFormInvalid(_))
        ));
    }

    #[test]
    fn unexpected_sibling_key_is_rejected() {
        let wire = json!({ "session_bundle": valid_body(), "extra": "nope" });
        assert!(matches!(
            parse_session_bundle_wire(&wire),
            Err(SessionBundleError::WireFormInvalid(_))
        ));
    }

    #[test]
    fn bare_body_missing_signature_is_rejected() {
        let mut body = valid_body();
        body.as_object_mut().unwrap().remove("signature");
        assert!(matches!(
            parse_session_bundle_wire(&body),
            Err(SessionBundleError::WireFormInvalid(_))
        ));
    }
}
