//! Session Trust Bundle (RFC-AITP-0010) — Node SDK.
//!
//! Gated by the `experimental-bundle` Cargo feature.

use std::sync::Arc;

use aitp_core::{Aid, Timestamp};
use aitp_crypto::AitpSigningKey;
use aitp_session_bundle::{
    verify_session_bundle, BundleOutcome, ParticipantEntry, SessionBundleBuilder,
    SessionBundleEnvelope, VerifySessionBundleContext,
};
use aitp_tct::TctEnvelope;
use napi::bindgen_prelude::*;
use napi::{Env, JsBoolean, JsFunction, JsString, JsUnknown};
use napi_derive::napi;
use uuid::Uuid;

use crate::agent::AitpAgent;
use crate::helpers::JsFnRef;

/// Outcome shape returned by `verifySessionBundle`. `kind` is `"clear"`
/// or `"degraded"`; `droppedAids` is empty in the `"clear"` case.
#[napi(object)]
pub struct JsBundleOutcome {
    pub kind: String,
    pub active_aids: Vec<String>,
    pub dropped_aids: Vec<String>,
}

/// Fluent builder for issuing a `SessionBundleEnvelope`. Constructed
/// from the coordinator's `AitpAgent`.
///
/// The Rust struct is suffixed `Js` to avoid a name collision with the
/// `aitp_session_bundle::SessionBundleBuilder` imported above; the
/// `#[napi(js_name)]` attribute exposes it to JavaScript under the
/// plain name `SessionBundleBuilder` for parity with the Python SDK.
#[napi(js_name = "SessionBundleBuilder")]
pub struct SessionBundleBuilderJs {
    key: Arc<AitpSigningKey>,
    session_id: Option<Uuid>,
    issued_at: Option<Timestamp>,
    participants: Vec<ParticipantEntry>,
}

#[napi]
impl SessionBundleBuilderJs {
    /// Construct a builder backed by `coordinator`'s signing key.
    #[napi(constructor)]
    pub fn new(coordinator: &AitpAgent) -> Self {
        Self {
            key: coordinator.signing_key(),
            session_id: None,
            issued_at: None,
            participants: Vec::new(),
        }
    }

    /// Set the session ID (UUIDv4 string). Defaults to a fresh one.
    #[napi]
    pub fn session_id(&mut self, uuid_str: String) -> Result<&Self> {
        let id = Uuid::parse_str(&uuid_str)
            .map_err(|e| Error::from_reason(format!("invalid uuid: {e}")))?;
        self.session_id = Some(id);
        Ok(self)
    }

    /// Override `issued_at` (unix seconds). Defaults to "now" at build.
    #[napi]
    pub fn issued_at(&mut self, unix_secs: i64) -> &Self {
        self.issued_at = Some(Timestamp(unix_secs));
        self
    }

    /// Add a participant entry. `tctEnvelopeJson` is a TctEnvelope JSON.
    #[napi]
    pub fn participant(&mut self, aid: String, tct_envelope_json: String) -> Result<&Self> {
        let participant_aid = Aid::parse(&aid)
            .map_err(|e| Error::from_reason(format!("invalid participant AID: {e}")))?;
        let envelope: TctEnvelope = serde_json::from_str(&tct_envelope_json)
            .map_err(|e| Error::from_reason(format!("invalid participant TCT JSON: {e}")))?;
        self.participants.push(ParticipantEntry {
            aid: participant_aid,
            tct: envelope.tct,
        });
        Ok(self)
    }

    /// Construct, sign, and return the `SessionBundleEnvelope` JSON.
    #[napi]
    pub fn build(&self) -> Result<String> {
        let mut builder = SessionBundleBuilder::new(&self.key);
        if let Some(id) = self.session_id {
            builder = builder.session_id(id);
        }
        if let Some(ts) = self.issued_at {
            builder = builder.issued_at(ts);
        }
        for entry in &self.participants {
            builder = builder.participant(entry.aid.clone(), entry.tct.clone());
        }
        let bundle = builder
            .build()
            .map_err(|e| Error::from_reason(format!("bundle build failed: {e}")))?;
        serde_json::to_string(&SessionBundleEnvelope {
            session_bundle: bundle,
        })
        .map_err(|e| Error::from_reason(e.to_string()))
    }
}

/// Verify a `SessionBundleEnvelope` JSON. `nowUnixSecs` defaults to
/// the system clock. `revocationCheck` receives a JTI string and
/// returns true if revoked.
#[napi(js_name = "verifySessionBundle")]
pub fn verify_session_bundle_js(
    env: Env,
    bundle_envelope_json: String,
    verifier_aid: String,
    now_unix_secs: Option<i64>,
    revocation_check: Option<JsFunction>,
) -> Result<JsBundleOutcome> {
    let envelope: SessionBundleEnvelope = serde_json::from_str(&bundle_envelope_json)
        .map_err(|e| Error::from_reason(format!("invalid bundle envelope JSON: {e}")))?;
    let verifier = Aid::parse(&verifier_aid)
        .map_err(|e| Error::from_reason(format!("invalid verifier AID: {e}")))?;
    let now = Timestamp(now_unix_secs.unwrap_or_else(|| Timestamp::now().0));

    // Wrap the JS callback in a Drop-aware guard moved into the
    // closure. When the closure drops (end of scope OR early error
    // exit), the guard drops and unrefs the napi Ref. The verifier may
    // never invoke the closure (e.g. version mismatch returns before
    // iterating participants) — the guard handles that case cleanly.
    let closure: Option<Box<dyn Fn(&Uuid) -> bool>> = match revocation_check {
        Some(cb) => {
            let guard = JsFnRef::new(env, cb)?;
            let env_raw = env.raw();
            let f: Box<dyn Fn(&Uuid) -> bool> = Box::new(move |jti: &Uuid| {
                // SAFETY: env_raw is valid for the duration of this
                // `#[napi]` method call; the closure is never sent
                // across threads.
                let env = unsafe { Env::from_raw(env_raw) };
                let callable: JsFunction = match guard.get() {
                    Ok(c) => c,
                    Err(_) => return false,
                };
                let js_jti: JsString = match env.create_string(&jti.to_string()) {
                    Ok(s) => s,
                    Err(_) => return false,
                };
                let res: JsUnknown = match callable.call(None, &[js_jti.into_unknown()]) {
                    Ok(r) => r,
                    Err(_) => return false,
                };
                let res_bool: JsBoolean = match res.try_into() {
                    Ok(b) => b,
                    Err(_) => return false,
                };
                res_bool.get_value().unwrap_or(false)
            });
            Some(f)
        }
        None => None,
    };

    let outcome = verify_session_bundle(
        &envelope.session_bundle,
        &VerifySessionBundleContext {
            verifier_aid: &verifier,
            now,
            revocation_check: closure.as_deref(),
        },
    )
    .map_err(|e| Error::from_reason(format!("bundle verification failed: {e}")))?;
    drop(closure); // explicit: guard unrefs on drop

    let result = match outcome {
        BundleOutcome::Clear { active_aids } => JsBundleOutcome {
            kind: "clear".into(),
            active_aids: active_aids.iter().map(|a| a.to_string()).collect(),
            dropped_aids: vec![],
        },
        BundleOutcome::DegradedSubset {
            active_aids,
            dropped_aids,
        } => JsBundleOutcome {
            kind: "degraded".into(),
            active_aids: active_aids.iter().map(|a| a.to_string()).collect(),
            dropped_aids: dropped_aids.iter().map(|a| a.to_string()).collect(),
        },
    };
    Ok(result)
}
