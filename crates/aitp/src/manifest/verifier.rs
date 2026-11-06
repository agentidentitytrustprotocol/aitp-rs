//! Manifest verification per RFC-AITP-0003 §5.

use crate::core::{base64url, check_members, from_serde_error, CheckedJson, Timestamp};
use crate::crypto::{AitpVerifyingKey, Signature};
use crate::handshake::IdentityKind;
use crate::manifest::builder::{manifest_signing_bytes, ManifestSigningView};
use crate::manifest::types::{Manifest, MANIFEST_MEMBERS};
use crate::manifest::ManifestError;

/// Inputs for verifying a Manifest.
#[non_exhaustive]
pub struct ManifestVerifyContext {
    /// Current time, used for expiry check. Pass `Timestamp::now()` in
    /// production; pass a pinned value in tests.
    pub now: Timestamp,
    /// Set by [`Self::with_insecure_localhost_dangerous`].
    pub(crate) insecure_localhost: bool,
}

impl ManifestVerifyContext {
    /// Build a context using the system clock.
    pub fn now() -> Self {
        Self::at(Timestamp::now())
    }

    /// Build a context at `now`.
    pub fn at(now: Timestamp) -> Self {
        Self {
            now,
            insecure_localhost: false,
        }
    }

    /// Accept an `http://localhost` / `http://127.0.0.1`
    /// `handshake_endpoint`. For local demos and tests; RFC-AITP-0003 §3
    /// requires HTTPS.
    pub fn with_insecure_localhost_dangerous(mut self) -> Self {
        self.insecure_localhost = true;
        self
    }
}

/// A Manifest that has passed [`verify_manifest`]. Only
/// [`verify_manifest`] produces one, so a value of this type is a
/// Manifest that was verified (at the context's `now`); its expiry
/// still applies afterwards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedManifest {
    manifest: Manifest,
}

impl VerifiedManifest {
    /// The verified Manifest.
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// Unwrap the verified Manifest.
    pub fn into_manifest(self) -> Manifest {
        self.manifest
    }
}

/// Verify a Manifest per RFC-AITP-0003 §5 and return it as a
/// [`VerifiedManifest`].
///
/// Verification order:
///
/// 1. **Version** — `manifest.version == "aitp/0.3"`. Else
///    [`ManifestError::VersionUnknown`].
/// 2. **Grammar** — every value is inside the grammar of
///    `aitp-manifest.schema.json` (RFC-AITP-0003 §5 step 2). Else
///    [`ManifestError::Malformed`], or
///    [`ManifestError::IdentityHintMalformed`] for the `identity_hint`
///    members its type requires or forbids. The member-set check is
///    [`parse_manifest_wire`]'s.
/// 3. **Expiry** — `manifest.expires_at` is in the future relative to
///    `ctx.now`. Else [`ManifestError::Expired`].
/// 4. **PoP** — verify `proof_of_possession.signature` covers
///    `sha256(base64url_decode(challenge))` using the public key encoded
///    in `manifest.aid` (RFC-AITP-0001 §5.4.2 unified signing-input
///    convention; RFC-AITP-0003 §3, §5). The hash input is the raw
///    decoded challenge bytes, NOT the ASCII bytes of the base64url
///    string. Else [`ManifestError::PopFailed`].
/// 5. **Outer signature** — re-canonicalize the Manifest minus signature
///    via JCS, hash with SHA-256, verify with the same key. Else
///    [`ManifestError::SignatureInvalid`].
///
/// Identity-proof verification (the actual JWT or pinned-key signature
/// check) does NOT happen here. That's done in the Mutual Handshake using
/// the fresh `payload.identity` field.
pub fn verify_manifest(
    manifest: &Manifest,
    ctx: &ManifestVerifyContext,
) -> Result<VerifiedManifest, ManifestError> {
    // 1. Version check.
    if manifest.version != crate::core::PROTOCOL_VERSION {
        return Err(ManifestError::VersionUnknown);
    }

    // 2. Grammar check.
    check_grammar(manifest, ctx)?;

    // 3. Expiry check.
    if manifest.expires_at.is_in_the_past(ctx.now) {
        return Err(ManifestError::Expired);
    }

    // Resolve the issuer pubkey early — both the PoP and outer
    // signature verify against it, and the AID parse can fail
    // before either check.
    let issuer_pubkey = AitpVerifyingKey::from_aid(&manifest.aid)?;

    // 4. PoP signature check, before the outer signature
    //    (RFC-AITP-0003 §5 steps 4 and 5): a Manifest failing both
    //    is `MANIFEST_POP_FAILED`. RFC-AITP-0001 §5.4.2: the signing
    //    input for every PoP construction is
    //    `sha256(base64url_decode(x))` — decode the challenge to its
    //    raw bytes before hashing.
    let challenge_bytes = base64url::decode_strict(&manifest.proof_of_possession.challenge)
        .map_err(|_| ManifestError::PopFailed)?;
    let pop_input = crate::crypto::Digest32::sha256(&challenge_bytes);
    let pop_sig = Signature::parse(&manifest.proof_of_possession.signature)
        .map_err(|_| ManifestError::PopFailed)?;
    issuer_pubkey
        .verify_jcs(&pop_input, &pop_sig)
        .map_err(|_| ManifestError::PopFailed)?;

    // 5. Outer signature check.
    let view = ManifestSigningView::from(manifest);
    let canonical = manifest_signing_bytes(&view)?;
    let digest = crate::crypto::Digest32::sha256(&canonical);
    let outer_sig =
        Signature::parse(&manifest.signature).map_err(|_| ManifestError::SignatureInvalid)?;
    issuer_pubkey
        .verify_jcs(&digest, &outer_sig)
        .map_err(|_| ManifestError::SignatureInvalid)?;

    Ok(VerifiedManifest {
        manifest: manifest.clone(),
    })
}

/// RFC-AITP-0003 §5 step 2: the value grammar of
/// `aitp-manifest.schema.json`. A hand-written check rather than a schema
/// validator so `aitp` takes no dependency for it; `tests/manifest_grammar.rs`
/// holds it to the schema. Errors name the member, never its value.
fn check_grammar(m: &Manifest, ctx: &ManifestVerifyContext) -> Result<(), ManifestError> {
    fn outside(member: &str) -> ManifestError {
        ManifestError::Malformed(format!("`{member}` is outside its grammar"))
    }
    fn ensure(ok: bool, member: &str) -> Result<(), ManifestError> {
        ok.then_some(()).ok_or_else(|| outside(member))
    }

    if let Some(name) = &m.display_name {
        ensure(name.chars().count() <= 128, "display_name")?;
    }
    let endpoint = m.handshake_endpoint.as_str();
    ensure(
        is_https_uri(endpoint) || (ctx.insecure_localhost && is_localhost_http(endpoint)),
        "handshake_endpoint",
    )?;
    ensure(
        m.accepted_trust_anchors.iter().all(|a| is_uri(a.as_str()))
            && all_unique(m.accepted_trust_anchors.iter().map(|a| a.as_str())),
        "accepted_trust_anchors",
    )?;
    ensure(
        is_capability_list(&m.offered_capabilities),
        "offered_capabilities",
    )?;
    if let Some(required) = &m.required_peer_capabilities {
        ensure(is_capability_list(required), "required_peer_capabilities")?;
    }
    if let Some(types) = &m.accepted_identity_types {
        ensure(
            types
                .iter()
                .all(|t| matches!(t.as_str(), "oidc" | "pinned_key" | "spiffe"))
                && all_unique(types.iter().map(String::as_str)),
            "accepted_identity_types",
        )?;
    }
    if let Some(algorithms) = &m.accepted_signature_algorithms {
        ensure(
            algorithms
                .iter()
                .all(|a| matches!(a.as_str(), "ed25519" | "p256"))
                && all_unique(algorithms.iter().map(String::as_str)),
            "accepted_signature_algorithms",
        )?;
    }
    ensure(
        m.proof_of_possession.challenge.len() == 22
            && is_base64url(&m.proof_of_possession.challenge),
        "proof_of_possession.challenge",
    )?;
    ensure(
        is_signature(&m.proof_of_possession.signature),
        "proof_of_possession.signature",
    )?;
    ensure(m.published_at.0 >= 0, "published_at")?;
    ensure(m.expires_at.0 >= 1, "expires_at")?;
    ensure(is_signature(&m.signature), "signature")?;

    let hint = &m.identity_hint;
    ensure(!hint.subject.is_empty(), "identity_hint.subject")?;
    if let Some(issuer) = &hint.issuer {
        ensure(is_uri(issuer.as_str()), "identity_hint.issuer")?;
    }
    if let Some(key) = &hint.public_key {
        ensure(
            matches!(key.len(), 43 | 44) && is_base64url(key),
            "identity_hint.public_key",
        )?;
    }
    match hint.kind {
        IdentityKind::Oidc => {
            if hint.issuer.is_none() {
                return Err(ManifestError::IdentityHintMalformed(
                    "oidc requires `issuer`",
                ));
            }
            if hint.public_key.is_some() {
                return Err(ManifestError::IdentityHintMalformed(
                    "oidc must not include `public_key`",
                ));
            }
        }
        IdentityKind::PinnedKey => {
            if hint.public_key.is_none() {
                return Err(ManifestError::IdentityHintMalformed(
                    "pinned_key requires `public_key`",
                ));
            }
        }
        IdentityKind::Spiffe => {
            // RFC-AITP-0002 §6.6: `type` and `subject` only.
            if hint.issuer.is_some() {
                return Err(ManifestError::IdentityHintMalformed(
                    "spiffe must not include `issuer`",
                ));
            }
            if hint.public_key.is_some() {
                return Err(ManifestError::IdentityHintMalformed(
                    "spiffe must not include `public_key`",
                ));
            }
            ensure(is_spiffe_id(&hint.subject), "identity_hint.subject")?;
        }
    }
    Ok(())
}

/// The schema's `format: uri`: an absolute RFC 3986 URI. `url::Url` alone
/// is too lenient, it strips or percent-encodes what RFC 3986 forbids, and
/// it passes bad escapes through. It also refuses a few URIs the schema
/// admits that name no reachable host, such as `https://` or a port above
/// 65535.
fn is_uri(s: &str) -> bool {
    // RFC 3986 §3: an authority follows only a `//` right after the scheme,
    // and brackets belong only to its host.
    let rest = s.split_once(':').map_or(s, |(_, rest)| rest);
    let (userinfo, after_authority) = match rest.strip_prefix("//") {
        Some(after) => {
            let (authority, tail) =
                after.split_at(after.find(['/', '?', '#']).unwrap_or(after.len()));
            (authority.rsplit_once('@').map_or("", |(u, _)| u), tail)
        }
        None => ("", rest),
    };
    s.bytes().all(|b| {
        b.is_ascii_graphic()
            && !matches!(
                b,
                b'"' | b'<' | b'>' | b'\\' | b'^' | b'`' | b'{' | b'|' | b'}'
            )
    }) && s.split('%').skip(1).all(|escaped| {
        escaped.len() >= 2 && escaped.as_bytes()[..2].iter().all(u8::is_ascii_hexdigit)
    }) && !userinfo.contains(['[', ']', '@'])
        && !after_authority.contains(['[', ']'])
        && after_authority.matches('#').count() <= 1
        && url::Url::parse(s).is_ok()
}

/// `handshake_endpoint`: `format: uri` and `pattern: ^https://`.
fn is_https_uri(s: &str) -> bool {
    s.starts_with("https://") && is_uri(s)
}

/// An `http://` URL naming `localhost` or `127.0.0.1`, the hosts the
/// insecure-localhost switches admit.
fn is_localhost_http(s: &str) -> bool {
    s.starts_with("http://")
        && is_uri(s)
        && url::Url::parse(s).is_ok_and(|u| matches!(u.host_str(), Some("localhost" | "127.0.0.1")))
}

fn all_unique<'a>(items: impl Iterator<Item = &'a str>) -> bool {
    let mut seen = std::collections::HashSet::new();
    items.into_iter().all(|i| seen.insert(i))
}

/// `pattern: ^[^\\s]+$` on every item, and `uniqueItems`.
fn is_capability_list(capabilities: &[String]) -> bool {
    capabilities
        .iter()
        .all(|c| !c.is_empty() && !c.chars().any(is_ecma_space))
        && all_unique(capabilities.iter().map(String::as_str))
}

/// ECMA-262 `\s`, the schema's dialect: Unicode whitespace without U+0085,
/// with U+FEFF.
fn is_ecma_space(ch: char) -> bool {
    (ch.is_whitespace() && ch != '\u{85}') || ch == '\u{feff}'
}

fn is_base64url(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

/// `pattern: ^((ed25519|p256)\\.)?[A-Za-z0-9_-]{86}$`.
fn is_signature(s: &str) -> bool {
    let bare = s
        .strip_prefix("ed25519.")
        .or_else(|| s.strip_prefix("p256."))
        .unwrap_or(s);
    bare.len() == 86 && is_base64url(bare)
}

/// The schema's `type: spiffe` subject (RFC-AITP-0002 §6.1): at most 2048
/// characters, `spiffe://`, a trust domain of 1 to 255 of `[a-z0-9._-]`,
/// and one or more path segments that are not `.`, `..` or empty.
fn is_spiffe_id(s: &str) -> bool {
    if s.chars().count() > 2048 {
        return false;
    }
    let Some(rest) = s.strip_prefix("spiffe://") else {
        return false;
    };
    let Some((domain, path)) = rest.split_once('/') else {
        return false;
    };
    (1..=255).contains(&domain.len())
        && domain.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
        && path.split('/').all(|segment| {
            segment
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
                && (segment.len() >= 3 || segment.bytes().any(|b| b != b'.'))
                && !segment.is_empty()
        })
}

/// Parse a raw wire-form JSON value into a [`Manifest`], enforcing
/// RFC-AITP-0001 §7's member-set check before typed deserialization.
///
/// RFC-AITP-0003 §5 makes the member-set check **step 2**, ahead of expiry
/// (step 3), PoP (step 4), and signature (step 5). Calling this before
/// [`verify_manifest`] makes that ordering structural: an unknown top-level
/// member is rejected before the manifest is ever deserialized, let alone
/// cryptographically checked.
///
/// `value` may be either shape:
/// - the bare inner Manifest body (what the conformance fixtures and the
///   adapter's `verify_manifest` op supply), or
/// - the `{"manifest": {...}}` HTTP transport wrapper (RFC-AITP-0003 §6.1,
///   [`crate::manifest::ManifestEnvelope`]) — detected structurally: no valid Manifest
///   body has a top-level `manifest` key (it is not in [`MANIFEST_MEMBERS`]),
///   so an object with that key is unambiguously the wrapper shape. When
///   present, the wrapper's own member set (`["manifest"]`) is checked
///   first, then the inner body's.
///
/// Order of operations:
/// 1. If wrapped, [`check_members`] the wrapper against `["manifest"]`.
/// 2. A `version` other than [`PROTOCOL_VERSION`](crate::core::PROTOCOL_VERSION)
///    is [`ManifestError::VersionUnknown`] (RFC-AITP-0003 §5 step 1): a newer
///    Manifest's new members are a version problem, not unknown fields.
/// 3. [`check_members`] the (unwrapped) body against [`MANIFEST_MEMBERS`] —
///    rejects any top-level member the schema does not declare.
/// 4. `serde_json::from_value` into [`Manifest`].
/// 5. On a residual serde error (which, now that the top-level check has
///    already passed, can only come from a nested closed object —
///    `identity_hint` or `proof_of_possession`), [`from_serde_error`]
///    recovers the offending field name so the caller still gets
///    [`ManifestError::UnknownField`] rather than a generic parse failure.
pub fn parse_manifest_wire(value: &CheckedJson) -> Result<Manifest, ManifestError> {
    let value = value.as_value();
    const WRAPPER_MEMBERS: &[&str] = &["manifest"];

    let body = match value.as_object() {
        Some(obj) if obj.contains_key("manifest") => {
            check_members("ManifestEnvelope", value, WRAPPER_MEMBERS)
                .map_err(|e| ManifestError::UnknownField(e.field))?;
            obj.get("manifest").expect("checked contains_key above")
        }
        _ => value,
    };

    if body
        .get("version")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|v| v != crate::core::PROTOCOL_VERSION)
    {
        return Err(ManifestError::VersionUnknown);
    }

    check_members("Manifest", body, MANIFEST_MEMBERS)
        .map_err(|e| ManifestError::UnknownField(e.field))?;

    serde_json::from_value(body.clone()).map_err(|e| {
        if let Some(field) = from_serde_error(&e) {
            ManifestError::UnknownField(field)
        } else {
            ManifestError::Malformed(e.to_string())
        }
    })
}

/// Check that `peer_manifest.accepted_identity_types` includes
/// `our_identity_type` (RFC-AITP-0003 §3.2 / §5 step 5).
///
/// Initiators MUST call this after fetching a peer's Manifest and
/// before initiating the Mutual Handshake. Without this check, a
/// pinned-key peer might attempt to present pinned-key identity to a
/// peer that only accepts OIDC, only to be rejected after several
/// round trips (RFC-AITP-0003 §5 step 5 makes the responder reject
/// the HELLO at that point — pre-checking saves the round trips and
/// produces a cleaner error code).
///
/// Field semantics (RFC-AITP-0003 §3.2):
/// - **Absent / not present** (`None`): defaults to `["oidc"]`
///   per the spec's backward-compatibility rule.
/// - **Empty array** (`Some(vec![])`): explicit "accept nothing"
///   — rejects every peer regardless of presented type.
/// - **Non-empty array** (`Some(non_empty)`): peer must present
///   a type from the list.
///
/// `our_identity_type` is compared by its RFC-AITP-0002 §2 wire name.
pub fn check_identity_type_compatibility(
    peer_manifest: &crate::manifest::Manifest,
    our_identity_type: crate::handshake::IdentityKind,
) -> Result<(), ManifestError> {
    let ours = our_identity_type.as_str();
    let accepted = match peer_manifest.accepted_identity_types.as_deref() {
        // Absent → spec default ["oidc"].
        None => our_identity_type == crate::handshake::IdentityKind::Oidc,
        // Explicit empty → reject every peer; otherwise the list decides.
        Some(list) => list.iter().any(|t| t == ours),
    };
    if !accepted {
        return Err(ManifestError::IncompatibleIdentityType(our_identity_type));
    }
    Ok(())
}
