//! Session Trust Bundle (RFC-AITP-0010) — Node SDK.
//!
//! Gated by the `experimental-session-bundle` Cargo feature, which the
//! published package does not enable. No stability promise.

use std::sync::Arc;

use aitp::core::{Aid, Timestamp};
use aitp::crypto::AitpSigningKey;
use aitp_experimental::session_bundle::{
    verify_session_bundle, BundleOutcome, CoordinatorKeySource, ParticipantEntry,
    SessionBundleBuilder, SessionBundleEnvelope, VerifySessionBundleContext,
};

use crate::wire;
use napi::bindgen_prelude::*;
use napi::Env;
use napi_derive::napi;
use uuid::Uuid;

use crate::agent::AitpAgent;

/// Revocation-check closure: maps a TCT `jti` to "is it revoked?".
type RevocationFn = Box<dyn Fn(&Uuid) -> bool>;

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
/// `aitp_experimental::session_bundle::SessionBundleBuilder` imported above; the
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

    /// Set the session ID. It is signed into the bundle, so it must be the
    /// lowercase hyphenated UUID v4 wire form (RFC-AITP-0010 §3); uppercase,
    /// braced, `urn:uuid:`, unhyphenated and non-v4 forms are refused, not
    /// normalized. Defaults to a fresh one.
    #[napi]
    pub fn session_id(&mut self, uuid_str: String) -> Result<&Self> {
        let id =
            crate::helpers::parse_strict_v4("session_id", &uuid_str).map_err(Error::from_reason)?;
        self.session_id = Some(id);
        Ok(self)
    }

    /// Override `issued_at` (unix seconds). Defaults to "now" at build.
    #[napi]
    pub fn issued_at(&mut self, unix_secs: i64) -> &Self {
        self.issued_at = Some(Timestamp(unix_secs));
        self
    }

    /// Add a participant entry. `tctToken` is the participant's TCT as an
    /// opaque compact-JWS string (the `tct` field returned by `complete()`
    /// / `processCommit()`), carried into the bundle verbatim.
    #[napi]
    pub fn participant(&mut self, aid: String, tct_token: String) -> Result<&Self> {
        let participant_aid = Aid::parse(&aid)
            .map_err(|e| Error::from_reason(format!("invalid participant AID: {e}")))?;
        self.participants.push(ParticipantEntry {
            aid: participant_aid,
            tct: tct_token,
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
/// returns true if revoked. `coordinatorManifestJson` (required) is the
/// coordinator's `ManifestEnvelope` JSON: it is verified (RFC-AITP-0003
/// §5), must designate the bundle's `coordinator`, and the coordinator
/// key is resolved from it (RFC-AITP-0010 §5 step 5). There is no
/// AID-only fallback.
#[napi(js_name = "verifySessionBundle")]
pub fn verify_session_bundle_js(
    env: Env,
    bundle_envelope_json: String,
    verifier_aid: String,
    coordinator_manifest_json: String,
    now_unix_secs: Option<i64>,
    revocation_check: Option<FunctionRef<String, bool>>,
) -> Result<JsBundleOutcome> {
    let bundle = wire::session_bundle(&bundle_envelope_json)
        .map_err(|e| Error::from_reason(format!("invalid bundle envelope JSON: {e}")))?;
    let coordinator_manifest = wire::manifest(&coordinator_manifest_json)
        .map_err(|e| Error::from_reason(format!("invalid coordinator manifest JSON: {e}")))?;
    let verifier = Aid::parse(&verifier_aid)
        .map_err(|e| Error::from_reason(format!("invalid verifier AID: {e}")))?;
    let now = Timestamp(now_unix_secs.unwrap_or_else(|| Timestamp::now().0));

    // `revocation_check` is a `FunctionRef`, napi 3's Drop-safe typed
    // function reference. The verifier may never invoke the closure
    // (e.g. version mismatch returns before iterating participants) —
    // `FunctionRef`'s own `Drop` impl handles that case cleanly, unlike
    // napi 2's `Ref`, which panicked if dropped without an explicit
    // `unref`.
    let closure: Option<RevocationFn> = match revocation_check {
        Some(cb) => {
            let f: RevocationFn = Box::new(move |jti: &Uuid| {
                cb.borrow_back(&env)
                    .and_then(|f| f.call(jti.to_string()))
                    .unwrap_or(false)
            });
            Some(f)
        }
        None => None,
    };

    let outcome = verify_session_bundle(
        &bundle,
        &VerifySessionBundleContext {
            verifier_aid: &verifier,
            now,
            revocation_check: closure.as_deref(),
            coordinator_key: CoordinatorKeySource::Manifest(&coordinator_manifest),
        },
    )
    .map_err(|e| Error::from_reason(format!("bundle verification failed: {e}")))?;
    drop(closure); // explicit: FunctionRef unrefs itself on drop

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
