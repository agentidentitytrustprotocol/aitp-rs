//! `AitpAgent` — an Ed25519 or P-256 identity plus its published Manifest.

use std::sync::Arc;

use aitp::core::{Aid, RawUrl, Timestamp};
use aitp::crypto::{AitpSigningKey, AitpVerifyingKey};
use aitp::handshake::StaticPinnedKeyStore;
use aitp::manifest::{IdentityHint, IdentityHintKind, Manifest, ManifestBuilder, ManifestEnvelope};
use aitp::tct::{sign_revocation_list, RevocationEntry, RevocationList};
use napi::bindgen_prelude::*;
use napi_derive::napi;

use crate::delegation::{
    build_delegation_token_json, issue_tct_for_delegatee_json, JsDelegationVerified,
};
use crate::envelope::{sign_envelope_js, SignEnvelopeOpts};
use crate::oidc::JwksProvider;
use crate::pop::{new_pop_challenge_js, sign_pop_response_js, PopExchange};
#[cfg(feature = "experimental-renewal")]
use crate::renewal::{build_renewal_request_js, process_renewal_request_js};
use crate::session::{JsInitiatorSession, JsResponderSession, SessionContext};
use crate::tct::{js_verify_tct, js_verify_tct_cached, JsIssuedTct, JsTctIdentity, JsTctStore};

/// Input shape for `signRevocationList`. Field names map to spec
/// `RevocationEntry` (jti, revoked_at, reason).
#[napi(object)]
pub struct RevocationEntryInput {
    /// JTI of the revoked TCT (UUID string).
    pub jti: String,
    /// Unix seconds when the issuing peer revoked the TCT.
    /// Defaults to the current time when omitted.
    pub revoked_at: Option<f64>,
    /// Optional human-readable reason. Not used in trust decisions.
    pub reason: Option<String>,
}

/// Options for `buildManifest`.
#[napi(object)]
pub struct ManifestOpts {
    /// Human-readable agent name; also the pinned-key identity subject.
    pub display_name: String,
    /// Absolute URL of this agent's handshake endpoint.
    pub handshake_endpoint: String,
    /// Capabilities this agent offers to peers.
    pub offered_caps: Vec<String>,
    /// Capabilities a peer must grant back (optional).
    pub required_caps: Option<Vec<String>>,
    /// Manifest TTL in seconds (optional; defaults to 3600).
    pub ttl_secs: Option<i32>,
    /// Identity presentation type — `"pinned_key"` (default) or `"oidc"`.
    pub identity_type: Option<String>,
    /// OIDC issuer URL (required when `identityType="oidc"`).
    pub oidc_issuer: Option<String>,
    /// OIDC subject identifier (required when `identityType="oidc"`).
    pub oidc_subject: Option<String>,
    /// Override the manifest's accepted_trust_anchors list. Defaults to
    /// `[oidc_issuer]` for OIDC mode and `[]` for pinned-key mode.
    pub accepted_trust_anchors: Option<Vec<String>>,
    /// This agent's `ListRevoked` URL, advertised as
    /// `rfc-aitp-0008.revocation_list_uri` in the signed Manifest. Every
    /// agent that issues TCTs MUST set it (RFC-AITP-0005 §11,
    /// RFC-AITP-0008 §1.4); without it a `fail_closed` verifier that
    /// discovers lists through the Manifest rejects this agent's TCTs as
    /// `TCT_REVOKED`. An absolute HTTPS URL, conventionally the origin
    /// plus `REVOCATION_LIST_PATH`.
    pub revocation_list_uri: Option<String>,
    /// Peer identity types this agent accepts (RFC-AITP-0004 §5.1 step 8).
    /// Defaults to `[identityType]`; `[]` accepts nothing.
    pub accepted_identity_types: Option<Vec<String>>,
}

/// Options for `newSession` / `newResponder`: trust-anchor override and
/// the pinned-key trust store.
///
/// JWKS provider is passed as a separate argument (napi-rs can't put a
/// class reference inside an `#[napi(object)]` struct).
#[napi(object)]
pub struct SessionOpts {
    /// Override the agent manifest's accepted_trust_anchors. `null`
    /// reuses the manifest's list.
    pub trust_anchors: Option<Vec<String>>,
    /// Local pinned-key trust store (RFC-AITP-0002 §3.2): peer AID
    /// strings (`aid:pubkey:ed25519:...` or `aid:pubkey:p256:...`). A
    /// peer presenting a `pinned_key` identity is accepted only if its
    /// AID is listed; the check runs before the proof is verified.
    /// Omitted or `[]` trusts no pinned key, so every `pinned_key` peer
    /// is rejected (fail closed). An invalid AID entry throws.
    pub pinned_keys: Option<Vec<String>>,
}

/// Options for `AitpAgent.generate` and `AitpAgent.fromSeed`.
///
/// Mirrors the Python SDK's `suite="ed25519"|"p256"` keyword argument so
/// the two SDKs share one shape per operation. `null`/omitted defaults
/// to `"ed25519"`.
#[napi(object)]
pub struct GenerateOpts {
    /// Signing suite. Accepted values: `"ed25519"` (default) or
    /// `"p256"` (RFC-AITP-0001 §5.4.3).
    pub suite: Option<String>,
}

fn suite_from_opts(opts: Option<GenerateOpts>) -> String {
    opts.and_then(|o| o.suite)
        .unwrap_or_else(|| "ed25519".to_string())
}

/// An AITP agent: a signing key and (once built) its Manifest.
#[napi]
pub struct AitpAgent {
    key: Arc<AitpSigningKey>,
    manifest: Option<Manifest>,
}

#[napi]
impl AitpAgent {
    /// Generate an agent with a fresh random signing key.
    ///
    /// `opts.suite` selects the algorithm — `"ed25519"` (default) or
    /// `"p256"`. Symmetric with the Python SDK's
    /// `AitpAgent.generate(suite="ed25519")`.
    ///
    /// ```ts
    /// const ed = AitpAgent.generate();                       // Ed25519
    /// const p  = AitpAgent.generate({ suite: 'p256' });      // P-256
    /// ```
    #[napi(factory)]
    pub fn generate(opts: Option<GenerateOpts>) -> Result<Self> {
        let suite = suite_from_opts(opts);
        let key = match suite.as_str() {
            "ed25519" => AitpSigningKey::generate_ed25519(),
            "p256" => AitpSigningKey::generate_p256(),
            other => {
                return Err(Error::from_reason(format!(
                    "unknown suite '{other}': expected 'ed25519' or 'p256'"
                )))
            }
        };
        Ok(Self {
            key: Arc::new(key),
            manifest: None,
        })
    }

    /// Construct an agent from a 32-byte seed (deterministic).
    ///
    /// `opts.suite` matches `AitpAgent.generate`. For `"p256"`, a tiny
    /// fraction of 32-byte seeds are not valid private scalars (zero
    /// or ≥ curve order) and raise.
    ///
    /// Note: the prior `AitpAgent.fromP256Seed` factory and the
    /// no-arg `AitpAgent.generate*` variants were removed in favor of
    /// this parameterized API so the Node SDK matches the Python SDK
    /// surface (CLAUDE.md mandates SDK symmetry).
    #[napi(factory)]
    pub fn from_seed(seed: Buffer, opts: Option<GenerateOpts>) -> Result<Self> {
        let arr: [u8; 32] = seed
            .as_ref()
            .try_into()
            .map_err(|_| Error::from_reason("seed must be exactly 32 bytes"))?;
        let suite = suite_from_opts(opts);
        let key = match suite.as_str() {
            "ed25519" => AitpSigningKey::from_ed25519_seed(&arr),
            "p256" => AitpSigningKey::from_p256_seed(&arr)
                .map_err(|e| Error::from_reason(format!("invalid P-256 seed: {e}")))?,
            other => {
                return Err(Error::from_reason(format!(
                    "unknown suite '{other}': expected 'ed25519' or 'p256'"
                )))
            }
        };
        Ok(Self {
            key: Arc::new(key),
            manifest: None,
        })
    }

    /// The agent's AID string (`aid:pubkey:...`).
    #[napi(getter)]
    pub fn aid(&self) -> String {
        self.key.aid().to_string()
    }

    /// Build and sign the agent's Manifest. Returns `ManifestEnvelope`
    /// JSON and caches the Manifest for `newSession` / `newResponder`.
    ///
    /// See `ManifestOpts.identityType` for the OIDC switch.
    #[napi]
    pub fn build_manifest(&mut self, opts: ManifestOpts) -> Result<String> {
        let endpoint: url::Url = opts
            .handshake_endpoint
            .parse()
            .map_err(|e| Error::from_reason(format!("invalid handshakeEndpoint URL: {e}")))?;

        let identity_type = opts.identity_type.as_deref().unwrap_or("pinned_key");
        let (hint, accepted_type, default_anchors) = match identity_type {
            "pinned_key" => {
                // The pinned-key `public_key` is the AID-identifier form
                // of the key (RFC-AITP-0002 §3.3): 32 raw bytes for
                // Ed25519, the 33-byte SEC1 compressed point for P-256.
                let pk_bytes = self.key.verifying_key().to_compressed();
                (
                    IdentityHint::new(IdentityHintKind::PinnedKey, opts.display_name.clone())
                        .with_public_key(aitp::core::base64url::encode(&pk_bytes)),
                    "pinned_key",
                    Vec::<url::Url>::new(),
                )
            }
            "oidc" => {
                let iss_str = opts.oidc_issuer.as_ref().ok_or_else(|| {
                    Error::from_reason("oidcIssuer is required when identityType='oidc'")
                })?;
                let sub = opts.oidc_subject.as_ref().ok_or_else(|| {
                    Error::from_reason("oidcSubject is required when identityType='oidc'")
                })?;
                let iss: url::Url = iss_str
                    .parse()
                    .map_err(|e| Error::from_reason(format!("invalid oidcIssuer URL: {e}")))?;
                (
                    IdentityHint::new(IdentityHintKind::Oidc, sub)
                        .with_issuer(RawUrl::from(iss.clone())),
                    "oidc",
                    vec![iss],
                )
            }
            other => {
                return Err(Error::from_reason(format!(
                    "unknown identityType '{other}': expected 'pinned_key' or 'oidc'"
                )))
            }
        };

        let (published_at, ttl) = crate::helpers::ttl_window(
            aitp::core::Timestamp::now(),
            i64::from(opts.ttl_secs.unwrap_or(3600)),
        );
        let mut builder = ManifestBuilder::new(&self.key)
            .display_name(&opts.display_name)
            .handshake_endpoint(endpoint)
            .identity_hint(hint)
            .published_at(published_at)
            .ttl(ttl);
        builder = match opts.accepted_identity_types {
            None => builder.accept_identity_type(accepted_type),
            Some(types) if types.is_empty() => builder.accept_no_identity_types(),
            Some(types) => types
                .into_iter()
                .fold(builder, |b, t| b.accept_identity_type(t)),
        };

        let anchors: Vec<url::Url> = match opts.accepted_trust_anchors {
            Some(list) => list
                .into_iter()
                .map(|s| s.parse::<url::Url>())
                .collect::<std::result::Result<_, _>>()
                .map_err(|e| {
                    Error::from_reason(format!("invalid acceptedTrustAnchors URL: {e}"))
                })?,
            None => default_anchors,
        };
        for a in anchors {
            builder = builder.accept_trust_anchor(a);
        }

        for cap in opts.offered_caps {
            builder = builder.offer(cap);
        }
        for cap in opts.required_caps.unwrap_or_default() {
            builder = builder.require(cap);
        }
        if let Some(uri) = opts.revocation_list_uri {
            let uri: url::Url = uri
                .parse()
                .map_err(|e| Error::from_reason(format!("invalid revocationListUri URL: {e}")))?;
            builder = builder.revocation_list_uri(uri);
        }

        let manifest = builder
            .build()
            .map_err(|e| Error::from_reason(format!("manifest build failed: {e}")))?;
        self.manifest = Some(manifest.clone());

        serde_json::to_string(&ManifestEnvelope::new(manifest))
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    /// Create a new outbound (initiator) handshake session.
    ///
    /// `jwks` is an optional `JwksProvider` used when the peer's
    /// manifest advertises an OIDC identity. `opts.trustAnchors`
    /// overrides the manifest's `accepted_trust_anchors`.
    /// `opts.pinnedKeys` lists the peer AIDs trusted for `pinned_key`
    /// identities; omitted ⇒ every `pinned_key` peer is rejected.
    #[napi]
    pub fn new_session(
        &self,
        jwks: Option<&JwksProvider>,
        opts: Option<SessionOpts>,
    ) -> Result<JsInitiatorSession> {
        let manifest = self.cached_manifest()?;
        let ctx = build_session_context(&manifest, jwks, opts)?;
        Ok(JsInitiatorSession::new(self.key.clone(), manifest, ctx))
    }

    /// Create a new inbound (responder) handshake session. Mirror of
    /// `newSession`, including `opts.pinnedKeys`: omitted ⇒ every
    /// `pinned_key` initiator is rejected.
    #[napi]
    pub fn new_responder(
        &self,
        jwks: Option<&JwksProvider>,
        opts: Option<SessionOpts>,
    ) -> Result<JsResponderSession> {
        let manifest = self.cached_manifest()?;
        let ctx = build_session_context(&manifest, jwks, opts)?;
        Ok(JsResponderSession::new(self.key.clone(), manifest, ctx))
    }

    /// Verify a compact-JWS TCT token and require `requiredGrant`.
    /// Rejects on an invalid, mis-audienced, expired, revoked, or
    /// under-scoped TCT.
    ///
    /// `expectedAudience` defaults to `null`, which means "verify as the
    /// holder" (RFC-AITP-0005 §9 receipt model — `this.aid` is used).
    /// Resource servers verifying a TCT presented by a peer pass
    /// `pop: { challenge, response }` (the presented-TCT path): the
    /// challenge from `newPopChallenge` and the presenter's
    /// `signPopResponse` reply. The TCT and the PoP response are verified
    /// together (RFC-AITP-0005 §6.2) and the audience is pinned to the
    /// proven holder AID (`sub`). A PoP failure throws with `code ===
    /// 'POP_CHALLENGE_INVALID'` or `'POP_RESPONSE_INVALID'`. `pop` and
    /// `expectedAudience` are mutually exclusive. If you pass
    /// `expectedAudience` instead, that AID MUST come from an authenticated
    /// source, never from the token: a verified PoP response or an
    /// equivalent channel binding. Passing the TCT's own `aud` back makes
    /// the audience check vacuous.
    ///
    /// `revokedJtis` (F-1) is the issuer's deny list of revoked TCT `jti`
    /// strings; any TCT whose `jti` is in the list is rejected even if
    /// otherwise valid. Revocation is `fail_closed`: **without `revokedJtis`
    /// every TCT is rejected** with `code === 'TCT_REVOKED'` and a "revocation
    /// source unavailable" message. Pass `[]` when nothing is revoked, or
    /// `'fail_open'` as `revocation` to skip the check. The caller is
    /// responsible for sourcing the revoked set (e.g. from a `RevocationList`
    /// it fetched and verified). Entries are lookup keys and are normalized:
    /// any RFC 9562 text form (uppercase, braced, `urn:uuid:`, unhyphenated)
    /// matches. An entry that is not a UUID throws rather than being ignored.
    #[napi]
    #[allow(clippy::too_many_arguments)]
    pub fn verify_tct(
        &self,
        env: Env,
        tct_token: String,
        required_grant: String,
        expected_audience: Option<String>,
        revoked_jtis: Option<Vec<String>>,
        revocation: Option<String>,
        pop: Option<PopExchange>,
    ) -> Result<JsTctIdentity> {
        js_verify_tct(
            env,
            &self.key,
            &tct_token,
            &required_grant,
            expected_audience.as_deref(),
            revoked_jtis,
            revocation,
            pop.as_ref(),
        )
    }

    /// Like `verifyTct`, but consults a `TctStore` first: a byte-identical,
    /// already-verified, still-valid TCT skips the signature check (the
    /// verification hot path for an agent that sees the same TCT on many
    /// requests). All cheap policy checks (expiry, audience, required grant,
    /// and the `fail_closed` revocation gate) still run on every call; only
    /// the signature check is elided. `revokedJtis`, `revocation` and `pop`
    /// behave as in `verifyTct`; `pop` is checked on every call.
    #[napi]
    #[allow(clippy::too_many_arguments)]
    pub fn verify_tct_cached(
        &self,
        env: Env,
        tct_token: String,
        required_grant: String,
        store: &JsTctStore,
        expected_audience: Option<String>,
        revoked_jtis: Option<Vec<String>>,
        revocation: Option<String>,
        pop: Option<PopExchange>,
    ) -> Result<JsTctIdentity> {
        js_verify_tct_cached(
            env,
            &self.key,
            &tct_token,
            &required_grant,
            store,
            expected_audience.as_deref(),
            revoked_jtis,
            revocation,
            pop.as_ref(),
        )
    }

    /// Consumer side of downstream proof of possession (RFC-AITP-0005 §6):
    /// a `pop_challenge` payload JSON for the presented `tctToken`
    /// (`tct_jti`, a CSPRNG 128-bit base64url `nonce`, `expires_at`
    /// `ttlSecs` from now, default 60). Send it to the presenter, then pass
    /// it with the reply as `pop` to `verifyTct`. Accept a response to each
    /// challenge at most once: the SDK keeps no replay cache.
    #[napi]
    pub fn new_pop_challenge(&self, tct_token: String, ttl_secs: Option<i64>) -> Result<String> {
        new_pop_challenge_js(&tct_token, ttl_secs.unwrap_or(60))
    }

    /// Holder side of downstream proof of possession (RFC-AITP-0005 §6.1):
    /// sign a received `pop_challenge` payload with this agent's key over
    /// `sha256` of the decoded nonce bytes, and return the `pop_response`
    /// payload JSON. A malformed or expired challenge throws with `code ===
    /// 'POP_CHALLENGE_INVALID'`.
    #[napi]
    pub fn sign_pop_response(&self, env: Env, challenge_json: String) -> Result<String> {
        sign_pop_response_js(env, &self.key, &challenge_json)
    }

    /// Build a delegation compact-JWS token from a held **grant voucher**
    /// (RFC-AITP-0006). `voucherToken` is the `grantVoucher` surfaced by
    /// `complete()` / `processCommit()`. The delegatee's key binding is
    /// derived from `delegateeAid` itself, so no separate public-key
    /// argument is needed in v0.2.
    #[napi]
    pub fn build_delegation(
        &self,
        voucher_token: String,
        delegatee_aid: String,
        scope: Vec<String>,
        ttl_secs: Option<i64>,
    ) -> Result<String> {
        build_delegation_token_json(&self.key, &voucher_token, &delegatee_aid, scope, ttl_secs)
    }

    /// Mint a fresh TCT for a delegatee after the verifier has confirmed
    /// the delegation. Returns `{ tct, grantVoucher }` — the compact-JWS
    /// TCT plus its companion grant voucher (`null` when none was minted).
    /// The subject-key binding is derived from the verified delegation's
    /// `delegatee` AID.
    #[napi]
    pub fn issue_tct_for_delegatee(
        &self,
        verified: JsDelegationVerified,
        ttl_secs: Option<i64>,
    ) -> Result<JsIssuedTct> {
        issue_tct_for_delegatee_json(&self.key, &verified, ttl_secs)
    }

    /// Sign an `AitpEnvelope` (RFC-AITP-0001 §5.4) from this agent and
    /// return its JSON. `messageType` is the wire string (e.g.
    /// `"mutual_hello"`) and `payloadJson` a JSON object; `opts` carries
    /// the optional `extensionsJson`, `messageId` (lowercase hyphenated
    /// UUID v4, strictly: other forms throw; default fresh)
    /// and `timestamp` (unix seconds, default now). The counterpart of
    /// `verifyEnvelope`.
    #[napi]
    pub fn sign_envelope(
        &self,
        message_type: String,
        payload_json: String,
        opts: Option<SignEnvelopeOpts>,
    ) -> Result<String> {
        sign_envelope_js(&self.key, &message_type, &payload_json, opts)
    }

    /// Sign a `RevocationList` with this agent's key. `entries` carries
    /// the revoked-TCT records; `expiresInSecs` defaults to 3600 s.
    /// Returns the on-wire `RevocationListEnvelope` JSON.
    #[napi]
    pub fn sign_revocation_list(
        &self,
        entries: Vec<RevocationEntryInput>,
        expires_in_secs: Option<i64>,
    ) -> Result<String> {
        let now = Timestamp::now();
        let rust_entries: Vec<RevocationEntry> = entries
            .iter()
            .map(|e| {
                // Strict wire form (#268): lowercase hyphenated UUID v4.
                // A lenient parse would sign an uppercase jti in normalized
                // form, or a non-v4 jti that verifyRevocationList rejects.
                let jti = aitp::core::ids::parse_v4(&e.jti).map_err(|err| {
                    Error::from_reason(format!("jti is not a lowercase UUID v4: {} ({err})", e.jti))
                })?;
                let revoked_at = match e.revoked_at {
                    None => now,
                    Some(v) if v.is_finite() => Timestamp(v as i64),
                    Some(v) => {
                        return Err(Error::from_reason(format!(
                            "revoked_at must be finite seconds-since-epoch (got {v})"
                        )));
                    }
                };
                Ok::<_, Error>({
                    let mut entry = RevocationEntry::new(jti, revoked_at);
                    entry.reason = e.reason.clone();
                    entry
                })
            })
            .collect::<Result<_>>()?;
        let body = RevocationList::new(
            self.key.aid().clone(),
            now,
            Timestamp(now.0 + expires_in_secs.unwrap_or(3600)),
            rust_entries,
        );
        let envelope = sign_revocation_list(body, &self.key)
            .map_err(|e| Error::from_reason(format!("sign_revocation_list failed: {e}")))?;
        serde_json::to_string(&envelope).map_err(|e| Error::from_reason(e.to_string()))
    }
}

// Renewal methods live in their own feature-gated `#[napi] impl` block.
// Keeping `#[cfg]` on individual methods *inside* the main `#[napi] impl`
// breaks the default (feature-off) build: the impl-level `#[napi]` macro
// emits a `__napi__build_renewal_request` registration from the token
// stream, but the method definition is `cfg`-stripped — a dangling
// reference. Gating the whole impl block removes both together.
#[cfg(feature = "experimental-renewal")]
#[napi]
impl AitpAgent {
    /// Holder side: build a `TctRenewalPayload` JSON for an in-band
    /// renewal of `currentTctToken` — the holder's current TCT as a
    /// compact-JWS string (RFC-AITP-0013).
    ///
    /// Behind the `experimental-renewal` Cargo feature (off by default).
    #[napi]
    pub fn build_renewal_request(&self, current_tct_token: String) -> Result<String> {
        build_renewal_request_js(&self.key, &current_tct_token)
    }

    /// Issuer side: verify a `TctRenewalPayload` JSON request and mint a
    /// fresh TCT. Returns `{ tct, grantVoucher }` — the compact-JWS TCT plus
    /// its companion grant voucher (`null` when none was minted).
    ///
    /// Renewal re-evaluates policy (RFC-AITP-0013): grants this
    /// agent's Manifest (from `buildManifest()`, required) no longer
    /// offers are dropped, a TCT whose `jti` is in `revokedJtis` is
    /// refused, and a replayed request (same `pop_nonce`) is refused.
    /// `revokedJtis` entries are normalized as in `verifyTct`; one that is
    /// not a UUID throws.
    ///
    /// Behind the `experimental-renewal` Cargo feature (off by default).
    #[napi]
    pub fn process_renewal_request(
        &self,
        request_payload_json: String,
        manifest_exp_unix_secs: i64,
        new_ttl_secs: i64,
        revoked_jtis: Option<Vec<String>>,
    ) -> Result<JsIssuedTct> {
        let manifest = self
            .manifest
            .as_ref()
            .ok_or_else(|| Error::from_reason("call buildManifest() before processing renewals"))?;
        process_renewal_request_js(
            &self.key,
            &request_payload_json,
            manifest_exp_unix_secs,
            new_ttl_secs,
            &manifest.offered_capabilities,
            revoked_jtis.as_deref().unwrap_or_default(),
        )
    }
}

impl AitpAgent {
    /// Crate-internal accessor used by the session-bundle module, which
    /// needs to sign with the agent's long-term key. Gated to match its
    /// only caller so the default (feature-off) build stays warning-free.
    #[cfg(feature = "experimental-session-bundle")]
    pub(crate) fn signing_key(&self) -> Arc<AitpSigningKey> {
        self.key.clone()
    }

    fn cached_manifest(&self) -> Result<Arc<Manifest>> {
        self.manifest
            .clone()
            .map(Arc::new)
            .ok_or_else(|| Error::from_reason("call buildManifest() before creating a session"))
    }
}

/// Build the per-session OIDC/trust-anchor context from the manifest,
/// JWKS provider, and optional caller overrides.
fn build_session_context(
    manifest: &Manifest,
    jwks: Option<&JwksProvider>,
    opts: Option<SessionOpts>,
) -> Result<SessionContext> {
    let (trust_anchors, pinned_keys) = match opts {
        Some(o) => (o.trust_anchors, o.pinned_keys),
        None => (None, None),
    };
    let pinned_keys = parse_pinned_keys(pinned_keys.unwrap_or_default())?;
    let anchors: Vec<RawUrl> = match trust_anchors {
        Some(list) => list
            .into_iter()
            .map(|s| {
                s.parse::<url::Url>()
                    .map(RawUrl::from)
                    .map_err(|e| Error::from_reason(format!("invalid trustAnchors URL: {e}")))
            })
            .collect::<Result<_>>()?,
        None => manifest.accepted_trust_anchors.clone(),
    };
    Ok(SessionContext {
        jwks: jwks.map(|p| p.as_resolver()),
        trust_anchors: anchors,
        identity_kind: manifest.identity_hint.kind,
        identity_subject: manifest.identity_hint.subject.clone(),
        identity_issuer: manifest.identity_hint.issuer.clone(),
        pinned_keys,
    })
}

/// Parse `pinnedKeys` AID strings into a [`StaticPinnedKeyStore`]. Any
/// entry that is not a valid AID (or whose key does not decode) is an
/// error, never silently skipped.
fn parse_pinned_keys(aids: Vec<String>) -> Result<StaticPinnedKeyStore> {
    aids.iter()
        .map(|s| {
            let aid = Aid::parse(s)
                .map_err(|e| Error::from_reason(format!("invalid pinnedKeys AID {s:?}: {e}")))?;
            AitpVerifyingKey::from_aid(&aid)
                .map_err(|e| Error::from_reason(format!("invalid pinnedKeys AID {s:?}: {e}")))
        })
        .collect()
}
