//! Networked commands (`http-client` feature): `aitp handshake`,
//! `aitp manifest fetch`, `aitp enroll` and `aitp echo`.
//!
//! The first two go through the SSRF-guarded `aitp::transport` client:
//! TLS roots come from webpki-roots (no system trust store), redirects
//! are refused, and `HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY` are
//! honoured. `aitp enroll` and `aitp echo` talk to the interop peer's
//! own endpoints with a plain reqwest client set up the same way (webpki
//! roots, no redirects, HTTPS unless `--insecure-localhost`).

use std::fmt;
use std::time::Duration;

use aitp::core::{base64url, Aid, AitpEnvelope, ErrorCode};
use aitp::crypto::AitpSigningKey;
use aitp::facade::{
    run_initiator_handshake, FacadeError, IdentityMode, InitiatorConfig, SessionContext, TrustMode,
};
use aitp::handshake::{HandshakeError, StaticPinnedKeyStore};
use aitp::manifest::{
    IdentityHint, IdentityHintKind, Manifest, ManifestBuilder, ManifestEnvelope, ManifestError,
};
use aitp::transport::{ManifestFetcher, RevocationFailMode, RevocationPolicy};

use crate::echo::{self, ChallengeRequest, EchoRequest};
use crate::enrol::{self, Challenge, Enrolled, ErrorBody};
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
    runtime()?.block_on(async {
        let session = run_handshake(&args).await?;
        println!(
            "{}",
            serde_json::to_string_pretty(&session.held_tct.claims)?
        );
        Ok(())
    })
}

/// Handshake with `args.peer` and present the TCT it issues us back to
/// its `/echo`, proving possession of our key (see [`crate::echo`]).
/// Prints the claims the peer verified.
pub(crate) fn echo(mut args: HandshakeArgs) -> CliResult {
    args.grants = vec![echo::ECHO_CAP.into()];
    runtime()?.block_on(async {
        let peer = &args.peer;
        let client = interop_client(peer, &args.net)?;
        let session = run_handshake(&args).await?;
        let tct = session.held_tct.token.clone();
        let challenge: AitpEnvelope = post(
            &client,
            peer,
            echo::CHALLENGE_PATH,
            &ChallengeRequest { tct: tct.clone() },
        )
        .await?;
        let response = echo::respond(
            &args.key,
            &session.peer_aid,
            session.held_tct.claims.jti,
            challenge,
        )?;
        let echoed: serde_json::Value = post(
            &client,
            peer,
            echo::ECHO_PATH,
            &EchoRequest {
                tct,
                pop_response: serde_json::to_value(response)?,
            },
        )
        .await?;
        eprintln!(
            "aitp: {} verified our TCT and proof of possession",
            session.peer_aid
        );
        println!("{}", serde_json::to_string_pretty(&echoed)?);
        Ok(())
    })
}

/// Run the handshake as initiator; a peer rejection becomes an error
/// naming its AITP code, with a hint where one helps.
async fn run_handshake(args: &HandshakeArgs) -> Result<SessionContext, Box<dyn std::error::Error>> {
    let peer_aid = match &args.peer_aid {
        Some(aid) => aid.clone(),
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
    // The TCT we issue authorizes nothing (we run no service), so by
    // default offer back what we ask for: interop peers request the
    // capability they grant. Said on stderr so the default is not silent.
    let offers = if args.offers.is_empty() && !args.grants.is_empty() {
        eprintln!(
            "aitp: offering the requested capabilities: {} (pass --offer to choose)",
            args.grants.join(", ")
        );
        args.grants.clone()
    } else {
        args.offers.clone()
    };
    let own_manifest = initiator_manifest(&args.key, &offers)?;

    let mut config = InitiatorConfig::new(
        &args.key,
        &own_manifest,
        args.peer.clone(),
        TrustMode::PinnedKeys(&trusted),
        IdentityMode::PinnedKey {
            subject: CLI_SUBJECT.into(),
        },
        args.grants.clone(),
    )
    .with_http_timeout(args.net.timeout)
    .with_insecure_localhost(args.net.insecure_localhost);
    if args.revocation_fail_open {
        config = config.with_revocation_policy(
            RevocationPolicy::default().with_fail_mode(RevocationFailMode::FailOpen),
        );
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
    Ok(session)
}

/// Register `key` with an interop peer's `/enroll` endpoint (see
/// [`crate::enrol`]) and print the enrolment.
pub(crate) fn enroll(peer: url::Url, key: &AitpSigningKey, net: NetOpts) -> CliResult {
    runtime()?.block_on(enroll_async(peer, key, net))
}

async fn enroll_async(peer: url::Url, key: &AitpSigningKey, net: NetOpts) -> CliResult {
    let client = interop_client(&peer, &net)?;
    let challenge: Challenge = post(
        &client,
        &peer,
        enrol::CHALLENGE_PATH,
        &serde_json::json!({}),
    )
    .await?;
    let request = enrol::sign_enroll(key, &challenge)?;
    let enrolled: Enrolled = post(&client, &peer, enrol::ENROLL_PATH, &request).await?;
    eprintln!(
        "aitp: enrolled {} with {} until {} (unix); granted: {}",
        enrolled.aid,
        challenge.peer_aid,
        enrolled.expires_at,
        enrolled.capabilities.join(", ")
    );
    println!("{}", serde_json::to_string_pretty(&enrolled)?);
    Ok(())
}

/// A client for the interop peer's own endpoints: HTTPS only (or
/// loopback HTTP with `--insecure-localhost`), no redirects.
fn interop_client(
    peer: &url::Url,
    net: &NetOpts,
) -> Result<reqwest::Client, Box<dyn std::error::Error>> {
    let local_http = peer.scheme() == "http"
        && matches!(peer.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if peer.scheme() != "https" && !(local_http && net.insecure_localhost) {
        return Err(format!(
            "refusing {peer}: the interop endpoints require https (or http://localhost \
             with --insecure-localhost)"
        )
        .into());
    }
    Ok(reqwest::Client::builder()
        .timeout(net.timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()?)
}

/// POST `body` as JSON to `path` under `peer` and decode a 2xx reply;
/// a non-2xx reply becomes an error naming the endpoint's code.
async fn post<B: serde::Serialize, T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    peer: &url::Url,
    path: &str,
    body: &B,
) -> Result<T, Box<dyn std::error::Error>> {
    let url = peer.join(path)?;
    let resp = client
        .post(url.clone())
        .json(body)
        .send()
        .await
        .map_err(|e| format!("request to {url} failed: {e}"))?;
    let status = resp.status();
    let bytes = resp.bytes().await?;
    if status.is_success() {
        return serde_json::from_slice(&bytes)
            .map_err(|e| format!("unexpected reply from {url}: {e}").into());
    }
    Err(match serde_json::from_slice::<ErrorBody>(&bytes) {
        Ok(e) => format!("{path} refused ({status}): {}: {}", e.error, e.message),
        Err(_) => format!("{path} refused: {url} returned {status}"),
    }
    .into())
}

pub(crate) fn manifest_fetch(peer: url::Url, net: NetOpts) -> CliResult {
    let manifest = runtime()?
        .block_on(net.fetcher().fetch(&peer))
        .map_err(FacadeError::from)?;
    // Same envelope shape `aitp manifest verify` reads, so the two pipe.
    let envelope = ManifestEnvelope::new(manifest);
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
        // The key in AID-identifier form (RFC-AITP-0002 §3.3).
        .identity_hint(
            IdentityHint::new(IdentityHintKind::PinnedKey, CLI_SUBJECT)
                .with_public_key(base64url::encode(&key.verifying_key().to_compressed())),
        )
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
    Some(code.as_str().to_owned())
}

fn runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}
