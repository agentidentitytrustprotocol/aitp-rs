//! Networked commands (`http-client` feature): `aitp handshake` and
//! `aitp manifest fetch`.
//!
//! Both go through the SSRF-guarded `aitp::transport` client: TLS roots
//! come from webpki-roots (no system trust store), redirects are
//! refused, and `HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY` are honoured.

use std::fmt;
use std::time::Duration;

use aitp::core::{base64url, Aid, ErrorCode};
use aitp::crypto::AitpSigningKey;
use aitp::facade::{
    run_initiator_handshake, FacadeError, IdentityMode, InitiatorConfig, TrustMode,
};
use aitp::handshake::{HandshakeError, StaticPinnedKeyStore};
use aitp::manifest::{
    IdentityHint, IdentityHintKind, Manifest, ManifestBuilder, ManifestEnvelope, ManifestError,
};
use aitp::transport::{ManifestFetcher, RevocationFailMode, RevocationPolicy};

use crate::CliResult;

/// The initiator runs no server, but a Manifest must name a handshake
/// endpoint. The responder never calls back on it during the handshake.
const UNUSED_HANDSHAKE_ENDPOINT: &str = "https://localhost/aitp/handshake/";

/// Subject presented in the CLI's pinned-key identity hint.
const CLI_SUBJECT: &str = "aitp-cli";

/// Transport knobs shared by `handshake` and `manifest fetch`.
pub(crate) struct NetOpts {
    pub timeout: Duration,
    pub insecure_localhost: bool,
}

impl NetOpts {
    fn fetcher(&self) -> ManifestFetcher {
        ManifestFetcher::new()
            .with_timeout(self.timeout)
            .with_insecure_localhost(self.insecure_localhost)
    }
}

/// Inputs to `aitp handshake`.
pub(crate) struct HandshakeArgs {
    pub peer: url::Url,
    pub key: AitpSigningKey,
    pub ephemeral: bool,
    pub peer_aid: Option<Aid>,
    pub grants: Vec<String>,
    pub offers: Vec<String>,
    pub revocation_fail_open: bool,
    pub net: NetOpts,
}

/// A failure that carries a registered AITP error code (the peer's
/// rejection, or our own verification of the peer), plus an optional
/// hint for the operator.
#[derive(Debug)]
struct CodedError {
    code: String,
    error: FacadeError,
    hint: Option<&'static str>,
}

impl fmt::Display for CodedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.error {
            // The peer's code is already in our `code`; don't repeat it.
            FacadeError::Protocol { message, .. } => {
                write!(f, "{}: peer rejected the handshake: {message}", self.code)?
            }
            other => write!(f, "{}: {other}", self.code)?,
        }
        if let Some(hint) = self.hint {
            write!(f, "\nhint: {hint}")?;
        }
        Ok(())
    }
}

impl std::error::Error for CodedError {}

const ENROL_HINT: &str = "the peer does not trust this ephemeral key. A peer that pins \
    keys must enrol yours first: create a persistent key with `aitp keygen > agent.key`, \
    have the peer enrol its AID (e.g. through the peer's /enroll endpoint), then rerun \
    with `--key agent.key`.";

const OFFER_HINT: &str = "the handshake is mutual: we issue the peer a TCT too, granting \
    the capabilities it requests that we offer, and none overlapped. Offer what the peer \
    requests with `--offer <cap>`.";

const GRANT_HINT: &str = "the peer grants only capabilities it offers; request one with \
    `--grant <cap>` (`aitp manifest fetch <url>` lists them under offered_capabilities).";

pub(crate) fn handshake(args: HandshakeArgs) -> CliResult {
    runtime()?.block_on(handshake_async(args))
}

async fn handshake_async(args: HandshakeArgs) -> CliResult {
    let peer_aid = match args.peer_aid {
        Some(aid) => aid,
        None => {
            // Trust on first use: the Manifest is self-signed by the AID
            // it names, so this pins whoever answers at `peer` right now.
            let manifest = args
                .net
                .fetcher()
                .fetch(&args.peer)
                .await
                .map_err(FacadeError::from)?;
            eprintln!(
                "aitp: trusting peer {} from its Manifest (trust on first use; \
                 pass --peer-aid to pin it)",
                manifest.aid
            );
            manifest.aid
        }
    };
    let trusted = StaticPinnedKeyStore::from_aids([&peer_aid])?;
    let own_manifest = initiator_manifest(&args.key, &args.offers)?;

    let mut config = InitiatorConfig::new(
        &args.key,
        &own_manifest,
        args.peer,
        TrustMode::PinnedKeys(&trusted),
        IdentityMode::PinnedKey {
            subject: CLI_SUBJECT.into(),
        },
        args.grants,
    )
    .with_http_timeout(args.net.timeout)
    .with_insecure_localhost(args.net.insecure_localhost);
    if args.revocation_fail_open {
        config = config.with_revocation_policy(RevocationPolicy {
            fail_mode: RevocationFailMode::FailOpen,
            ..Default::default()
        });
    }

    let session = match run_initiator_handshake(config).await {
        Ok(session) => session,
        Err(error) => {
            return Err(match error_code(&error) {
                Some(code) => {
                    let hint = match &error {
                        FacadeError::Protocol { .. }
                            if args.ephemeral && code == "IDENTITY_FAILED" =>
                        {
                            Some(ENROL_HINT)
                        }
                        FacadeError::Protocol { .. } if code == "POLICY_VIOLATION" => {
                            Some(GRANT_HINT)
                        }
                        // Raised by us, not the peer: the peer asked for
                        // nothing we offer.
                        FacadeError::Handshake(HandshakeError::PolicyViolation) => Some(OFFER_HINT),
                        _ => None,
                    };
                    Box::new(CodedError { code, error, hint })
                }
                None => Box::new(error),
            });
        }
    };

    eprintln!("aitp: handshake complete with {}", session.peer_aid);
    println!(
        "{}",
        serde_json::to_string_pretty(&session.held_tct.claims)?
    );
    Ok(())
}

pub(crate) fn manifest_fetch(peer: url::Url, net: NetOpts) -> CliResult {
    let manifest = runtime()?
        .block_on(net.fetcher().fetch(&peer))
        .map_err(FacadeError::from)?;
    // Same envelope shape `aitp manifest verify` reads, so the two pipe.
    let envelope = ManifestEnvelope { manifest };
    println!("{}", serde_json::to_string_pretty(&envelope)?);
    Ok(())
}

/// The Manifest the CLI presents as initiator: a pinned-key identity
/// over `key`, offering `offers`, accepting only pinned-key peers.
fn initiator_manifest(key: &AitpSigningKey, offers: &[String]) -> Result<Manifest, ManifestError> {
    let mut builder = ManifestBuilder::new(key);
    for cap in offers {
        builder = builder.offer(cap.clone());
    }
    builder
        .display_name(CLI_SUBJECT)
        .handshake_endpoint(
            UNUSED_HANDSHAKE_ENDPOINT
                .parse()
                .expect("constant is a valid URL"),
        )
        .identity_hint(IdentityHint {
            kind: IdentityHintKind::PinnedKey,
            subject: CLI_SUBJECT.into(),
            issuer: None,
            // AID-identifier form of the key (RFC-AITP-0002 §3.3).
            public_key: Some(base64url::encode(&key.verifying_key().to_compressed())),
        })
        .accept_identity_type("pinned_key")
        .build()
}

/// The registered AITP error code for `error`, when it has one: the
/// peer's own code for a rejection, or the code our verification of the
/// peer maps to. Transport failures (unreachable host, TLS, HTTP status)
/// have none.
fn error_code(error: &FacadeError) -> Option<String> {
    let code = match error {
        FacadeError::Protocol { code, .. } => return Some(code.clone()),
        FacadeError::Handshake(e) => e.error_code(),
        FacadeError::ManifestVerify(ManifestError::IncompatibleIdentityType(_)) => {
            ErrorCode::IncompatibleIdentityType
        }
        _ => return None,
    };
    serde_json::to_value(code)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
}

fn runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}
