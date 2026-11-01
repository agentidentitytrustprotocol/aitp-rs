//! A2A Agent Card binding, client verification (RFC-AITP-0014 §4.2 steps
//! 1 to 5 and §4.3, Draft). **No stability promise.** Needs feature
//! `a2a-agent-card`.
//!
//! An Agent Card is a pointer, never evidence of identity (§4.2 step 1).
//! The Card names an AID and a Manifest URL; the agent's own signed
//! Manifest then has to confirm the AID and list the interface the client
//! intends to call. Only then may that interface receive a TCT.
//!
//! This module does no I/O. The caller fetches the Manifest, which takes
//! two calls because the URL comes out of the Card:
//!
//! ```
//! # use aitp::core::{CheckedJson, Timestamp};
//! # use aitp_experimental::a2a::*;
//! # fn demo(card: &CheckedJson, fetch: impl Fn(&url::Url) -> Option<Vec<u8>>) -> Result<(), A2aBindingError> {
//! let pointer = locate_aitp_extension(card)?;
//! let body = fetch(pointer.manifest_url());
//! let outcome = match &body {
//!     Some(bytes) => ManifestFetch::Fetched(bytes),
//!     None => ManifestFetch::Unreachable,
//! };
//! let bound = bind_manifest(
//!     &pointer,
//!     outcome,
//!     "https://b.agents.example.com/a2a/v1",
//!     &BindingContext::at(Timestamp::now()),
//! )?;
//! let _handshake_with = bound.handshake_endpoint();
//! # Ok(()) }
//! ```
//!
//! What stays with the caller:
//!
//! - **Fetching.** `manifest_url` is chosen by whoever wrote the Card, so
//!   fetch it the way any untrusted URL is fetched, through `HostGuard`
//!   (`aitp::transport`) or an equivalent.
//! - **Step 6**, which needs the client's own identity (RFC-AITP-0003 §5
//!   step 6): an OIDC client checks that
//!   [`BoundAgentCard::accepted_trust_anchors`] overlaps its own; any other
//!   client calls [`aitp::manifest::check_identity_type_compatibility`].
//! - **Step 7**, the handshake, against
//!   [`BoundAgentCard::handshake_endpoint`] and no URL from the Card.
//! - **§5.1**: send the TCT in [`AITP_TCT_HEADER`] over TLS, list
//!   [`AITP_A2A_EXTENSION_URI`] in `A2A-Extensions`, and send only the
//!   TCT this server issued.
//!
//! An error's `Display` never quotes the Card or the Manifest: their text
//! is written by the party being checked and may reach logs or a model's
//! context (§9.3). The offending detail of a rejected Manifest stays on
//! [`std::error::Error::source`] and in `Debug`, so log `Display` or
//! [`A2aBindingError::code`].

use aitp::core::{Aid, CheckedJson, ErrorCode, RawUrl, Timestamp};
use aitp::manifest::{
    parse_manifest_wire, verify_manifest, ManifestError, ManifestVerifyContext, VerifiedManifest,
};
use serde_json::Value;
use url::Url;

/// The AITP extension's `uri` in `capabilities.extensions`, compared byte
/// for byte (RFC-AITP-0014 §3.1).
pub const AITP_A2A_EXTENSION_URI: &str = "https://agentidentitytrustprotocol.io/ext/a2a/v1";

/// The Manifest `extensions` key listing the agent's AITP-capable A2A
/// interface URLs (RFC-AITP-0014 §4.1).
pub const A2A_INTERFACES_KEY: &str = "rfc-aitp-0014.a2a_interfaces";

/// The request header carrying the TCT (RFC-AITP-0014 §3.3).
pub const AITP_TCT_HEADER: &str = "x-aitp-tct";

/// Why a Card did not bind. [`Self::code`] gives the registered error code
/// (RFC-AITP-0014 §6).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum A2aBindingError {
    /// Step 2: no `capabilities.extensions` entry has the AITP URI.
    #[error("agent card has no AITP extension")]
    ExtensionMissing,
    /// Step 2: more than one entry has the AITP URI.
    #[error("agent card has more than one AITP extension")]
    ExtensionNotUnique,
    /// Step 2: the extension's `params` is not what §3.2 requires. Names
    /// the member at fault.
    #[error("AITP extension params malformed: {0}")]
    ParamsMalformed(&'static str),
    /// Step 2: `params.securityScheme` names no `apiKeySecurityScheme` in
    /// header `x-aitp-tct` (§3.3).
    #[error("AITP security scheme missing or wrong")]
    SecuritySchemeInvalid,
    /// Step 3: the Manifest could not be retrieved.
    #[error("manifest could not be retrieved")]
    ManifestNotFound,
    /// Step 3: the Manifest failed RFC-AITP-0003 §5. The detail is on
    /// `source()` and is not printed: it can hold text from the Manifest.
    #[error("manifest rejected: {}", manifest_code(.0).as_str())]
    Manifest(#[source] ManifestError),
    /// Step 4: the Manifest's AID and the Card's are different keys.
    #[error("manifest AID does not denote the card's AID")]
    AidMismatch,
    /// Step 4: the Manifest's AID is not the one the client pinned.
    #[error("manifest AID does not denote the pinned AID")]
    PinnedAidMismatch,
    /// Step 5: the interfaces key is absent or not an array of strings, or
    /// the matching entry is not an HTTPS URL (§4.1).
    #[error("manifest A2A interfaces key missing or invalid")]
    InterfacesKeyInvalid,
    /// Step 5: the selected interface URL is not in the Manifest's list.
    #[error("selected interface is not listed in the manifest")]
    InterfaceNotListed,
}

impl A2aBindingError {
    /// The registered error code (RFC-AITP-0014 §6).
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::ManifestNotFound => ErrorCode::ManifestNotFound,
            Self::Manifest(e) => manifest_code(e),
            Self::ExtensionMissing
            | Self::ExtensionNotUnique
            | Self::ParamsMalformed(_)
            | Self::SecuritySchemeInvalid
            | Self::AidMismatch
            | Self::PinnedAidMismatch
            | Self::InterfacesKeyInvalid
            | Self::InterfaceNotListed => ErrorCode::IdentityFailed,
        }
    }
}

/// The RFC-AITP-0003 §10 code of a failed Manifest (or `UNKNOWN_FIELD`).
fn manifest_code(e: &ManifestError) -> ErrorCode {
    match e {
        ManifestError::VersionUnknown => ErrorCode::ManifestVersionUnknown,
        ManifestError::UnknownField(_) => ErrorCode::UnknownField,
        ManifestError::Expired => ErrorCode::ManifestExpired,
        // `verify_manifest` loads the key from `aid` for the PoP check, the
        // first step that uses it (RFC-AITP-0003 §5 step 4).
        ManifestError::PopFailed | ManifestError::Crypto(_) => ErrorCode::ManifestPopFailed,
        ManifestError::SignatureInvalid => ErrorCode::ManifestSignatureInvalid,
        // Not raised here, but the §6 code of a caller's own step 6 or fetch.
        ManifestError::IncompatibleIdentityType(_) => ErrorCode::IncompatibleIdentityType,
        ManifestError::NotFound => ErrorCode::ManifestNotFound,
        _ => ErrorCode::ManifestInvalid,
    }
}

/// What step 2 read from the Card: where to get the Manifest, and the AID
/// it has to denote. Still unverified.
#[derive(Debug, Clone)]
pub struct CardPointer {
    aid: Aid,
    manifest_url: Url,
}

impl CardPointer {
    /// `params.aid`.
    pub fn aid(&self) -> &Aid {
        &self.aid
    }

    /// `params.manifestUrl`, an HTTPS URL chosen by the Card's author.
    pub fn manifest_url(&self) -> &Url {
        &self.manifest_url
    }
}

/// Step 2: find the AITP extension in an Agent Card and check its `params`
/// and security scheme. Other Card members are not read.
pub fn locate_aitp_extension(card: &CheckedJson) -> Result<CardPointer, A2aBindingError> {
    let card = card.as_value();
    let mut entries = card
        .pointer("/capabilities/extensions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|e| e.get("uri").and_then(Value::as_str) == Some(AITP_A2A_EXTENSION_URI));
    let entry = entries.next().ok_or(A2aBindingError::ExtensionMissing)?;
    if entries.next().is_some() {
        return Err(A2aBindingError::ExtensionNotUnique);
    }

    let malformed = A2aBindingError::ParamsMalformed;
    let params = entry
        .get("params")
        .filter(|p| p.is_object())
        .ok_or(malformed("params"))?;
    let aid = params
        .get("aid")
        .and_then(Value::as_str)
        .and_then(|s| Aid::parse(s).ok())
        .ok_or(malformed("aid"))?;
    let manifest_url = params
        .get("manifestUrl")
        .and_then(Value::as_str)
        .and_then(https_url)
        .ok_or(malformed("manifestUrl"))?;
    let scheme_name = params
        .get("securityScheme")
        .and_then(Value::as_str)
        .ok_or(malformed("securityScheme"))?;

    let scheme_ok = card
        .get("securitySchemes")
        .and_then(|s| s.get(scheme_name))
        .and_then(Value::as_object)
        // A SecurityScheme holds exactly one variant (RFC-AITP-0014 §2.2).
        .filter(|variants| variants.len() == 1)
        .and_then(|variants| variants.get("apiKeySecurityScheme"))
        .is_some_and(|s| {
            s.get("location").and_then(Value::as_str) == Some("header")
                && s.get("name").and_then(Value::as_str) == Some(AITP_TCT_HEADER)
        });
    if !scheme_ok {
        return Err(A2aBindingError::SecuritySchemeInvalid);
    }

    Ok(CardPointer { aid, manifest_url })
}

/// `s` as a plain `https://` URL. Stricter than the URL parser, which
/// repairs whitespace, backslashes, extra slashes, percent-encoded and
/// invisible host characters, and numeric hosts: the caller's HTTP client
/// might read such a string differently. Credentials are refused too. An
/// internationalized host has to be written as punycode.
fn https_url(s: &str) -> Option<Url> {
    let rest = s.strip_prefix("https://")?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let plain = !authority.is_empty()
        && authority.is_ascii()
        && !authority.contains(['@', '%'])
        && !s
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == '\\');
    if !plain {
        return None;
    }
    let url = Url::parse(s).ok()?;
    // The parser rewrites numeric IPv4 spellings (`010.0.0.1` to `8.0.0.1`).
    // An IPv6 literal has one meaning however it is written.
    let raw_host = authority.split(':').next().unwrap_or_default();
    let same = authority.starts_with('[')
        || url
            .host_str()
            .is_some_and(|h| h.eq_ignore_ascii_case(raw_host));
    same.then_some(url)
}

/// The outcome of getting the Manifest at `params.manifestUrl`.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum ManifestFetch<'a> {
    /// A 2xx response's body: the Manifest or its `{"manifest": {...}}`
    /// wrapper. Bytes that are not valid JSON, or that repeat a key, are
    /// `MANIFEST_INVALID`, not `MANIFEST_NOT_FOUND`: a retry will not help.
    Fetched(&'a [u8]),
    /// A Manifest the client already holds verified (§4.2 step 3's MAY).
    /// Its expiry is checked again against the context's `now`.
    Verified(&'a VerifiedManifest),
    /// Non-2xx, DNS, TLS or network failure.
    Unreachable,
}

/// Inputs for [`bind_manifest`] other than the Manifest.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct BindingContext {
    /// The time the Manifest's expiry is checked against.
    pub now: Timestamp,
    /// The AID the client pins for this server by configuration, if any
    /// (§4.2 step 4).
    pub expected_aid: Option<Aid>,
}

impl BindingContext {
    /// A context at `now`, with no pinned AID.
    pub fn at(now: Timestamp) -> Self {
        Self {
            now,
            expected_aid: None,
        }
    }

    /// Pin the server's AID.
    pub fn with_expected_aid(mut self, aid: Aid) -> Self {
        self.expected_aid = Some(aid);
        self
    }
}

/// Steps 3 to 5: verify the Manifest, bind the AID, bind the interface.
///
/// `selected_interface_url` is the `url` of the AgentInterface the client
/// intends to call. It is matched byte for byte, without normalizing.
pub fn bind_manifest(
    pointer: &CardPointer,
    fetch: ManifestFetch<'_>,
    selected_interface_url: &str,
    ctx: &BindingContext,
) -> Result<BoundAgentCard, A2aBindingError> {
    let manifest = match fetch {
        ManifestFetch::Unreachable => return Err(A2aBindingError::ManifestNotFound),
        ManifestFetch::Fetched(bytes) => verify_fetched(bytes, ctx.now)?,
        ManifestFetch::Verified(held) => {
            if held.manifest().expires_at.is_in_the_past(ctx.now) {
                return Err(A2aBindingError::Manifest(ManifestError::Expired));
            }
            held.clone()
        }
    };
    // Step 7 sends the handshake here, so hold it to the same bar as the
    // interface URL (RFC-AITP-0003 §5 step 2).
    if https_url(manifest.manifest().handshake_endpoint.as_str()).is_none() {
        return Err(A2aBindingError::Manifest(ManifestError::Malformed(
            "handshake_endpoint is not an HTTPS URL".to_owned(),
        )));
    }

    let manifest_aid = &manifest.manifest().aid;
    if !same_key(manifest_aid, &pointer.aid) {
        return Err(A2aBindingError::AidMismatch);
    }
    if let Some(pinned) = &ctx.expected_aid {
        if !same_key(manifest_aid, pinned) {
            return Err(A2aBindingError::PinnedAidMismatch);
        }
    }

    let interfaces = manifest
        .manifest()
        .extensions
        .as_ref()
        .and_then(|e| e.get(A2A_INTERFACES_KEY))
        .and_then(Value::as_array)
        .ok_or(A2aBindingError::InterfacesKeyInvalid)?;
    let mut listed = false;
    for entry in interfaces {
        let entry = entry
            .as_str()
            .ok_or(A2aBindingError::InterfacesKeyInvalid)?;
        listed |= entry == selected_interface_url;
    }
    if !listed {
        return Err(A2aBindingError::InterfaceNotListed);
    }
    // A signed `http://` entry is still no place to send a credential.
    if https_url(selected_interface_url).is_none() {
        return Err(A2aBindingError::InterfacesKeyInvalid);
    }

    Ok(BoundAgentCard {
        manifest,
        interface_url: selected_interface_url.to_owned(),
    })
}

/// Steps 2 to 5 in one call, for a client that has the fetch outcome
/// already. A client that needs the Manifest URL first calls
/// [`locate_aitp_extension`] and [`bind_manifest`].
pub fn verify_agent_card_binding(
    card: &CheckedJson,
    selected_interface_url: &str,
    fetch: ManifestFetch<'_>,
    ctx: &BindingContext,
) -> Result<BoundAgentCard, A2aBindingError> {
    let pointer = locate_aitp_extension(card)?;
    bind_manifest(&pointer, fetch, selected_interface_url, ctx)
}

fn verify_fetched(bytes: &[u8], now: Timestamp) -> Result<VerifiedManifest, A2aBindingError> {
    let body = CheckedJson::from_slice(bytes)
        .map_err(|e| A2aBindingError::Manifest(ManifestError::Malformed(e.to_string())))?;
    let manifest = parse_manifest_wire(&body).map_err(A2aBindingError::Manifest)?;
    verify_manifest(&manifest, &ManifestVerifyContext::at(now)).map_err(A2aBindingError::Manifest)
}

/// Whether two AIDs denote one key: by algorithm and key, so the legacy
/// and `ed25519:` forms are equal (RFC-AITP-0001 §5.3). `Aid`'s `==`
/// compares the strings and would call them different.
fn same_key(a: &Aid, b: &Aid) -> bool {
    a.algorithm() == b.algorithm() && a.identifier() == b.identifier()
}

/// A Card that passed steps 1 to 5 (§4.2 calls it *bound*). Only
/// [`bind_manifest`] produces one. Its accessors are the effective values
/// of §4.3, all from the verified Manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundAgentCard {
    manifest: VerifiedManifest,
    interface_url: String,
}

impl BoundAgentCard {
    /// The server's identity: the Manifest's own AID string.
    pub fn aid(&self) -> &Aid {
        &self.manifest.manifest().aid
    }

    /// The identity types the server accepts. An absent member means
    /// `["oidc"]` (RFC-AITP-0003 §3.2).
    pub fn accepted_identity_types(&self) -> Vec<String> {
        self.manifest
            .manifest()
            .accepted_identity_types
            .clone()
            .unwrap_or_else(|| vec!["oidc".to_owned()])
    }

    /// The trust anchors the server accepts.
    pub fn accepted_trust_anchors(&self) -> &[RawUrl] {
        &self.manifest.manifest().accepted_trust_anchors
    }

    /// The capabilities the server can grant. The issued TCT's `grants`
    /// decide what it does grant.
    pub fn offered_capabilities(&self) -> &[String] {
        &self.manifest.manifest().offered_capabilities
    }

    /// The endpoint to run the Mutual Handshake against (step 7).
    pub fn handshake_endpoint(&self) -> &RawUrl {
        &self.manifest.manifest().handshake_endpoint
    }

    /// The interface URL step 5 accepted, the only one that may receive
    /// the TCT.
    pub fn interface_url(&self) -> &str {
        &self.interface_url
    }

    /// The verified Manifest.
    pub fn manifest(&self) -> &VerifiedManifest {
        &self.manifest
    }
}
