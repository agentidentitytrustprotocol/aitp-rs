//! End-to-end tests for the networked commands (`aitp handshake`,
//! `aitp manifest fetch`): run the built binary against a real
//! `HandshakeServer` on loopback and assert on its output / exit status.

#![cfg(feature = "http-client")]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use aitp::crypto::AitpSigningKey;
use aitp::handshake::{JwkPublicKey, JwksResolver, ResolveError, StaticPinnedKeyStore};
use aitp::manifest::{IdentityHint, IdentityHintKind, ManifestBuilder};
use aitp::transport::{
    HandshakeServer, ManifestServer, RevocationFailMode, RevocationPolicy, REVOCATION_LIST_PATH,
};
use assert_cmd::Command;
use predicates::prelude::*;
use tokio::net::TcpListener;

/// Seed of the CLI's persistent key (written to a `--key` file).
const CLI_SEED: u8 = 0x70;

struct NoOpResolver;
impl JwksResolver for NoOpResolver {
    fn resolve(&self, _issuer: &url::Url) -> Result<Vec<JwkPublicKey>, ResolveError> {
        Ok(vec![])
    }
}

/// Spawn a responder serving its Manifest, handshake routes and
/// revocation list on loopback. It trusts the CLI's persistent key
/// unless `reject_cli` is set, in which case its pinned-key store is
/// empty and every pinned-key initiator is refused. Returns the
/// responder's key and origin.
async fn spawn_peer(seed: u8, reject_cli: bool) -> (AitpSigningKey, String) {
    let key = AitpSigningKey::from_seed(&[seed; 32]);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let origin = format!("http://localhost:{port}");
    let manifest = ManifestBuilder::new(&key)
        .display_name("peer")
        .handshake_endpoint(format!("{origin}/aitp/handshake/").parse().unwrap())
        .revocation_list_uri(format!("{origin}{REVOCATION_LIST_PATH}").parse().unwrap())
        .identity_hint(
            IdentityHint::new(IdentityHintKind::PinnedKey, "peer").with_public_key(
                aitp::core::base64url::encode(&key.verifying_key().to_compressed()),
            ),
        )
        .accept_identity_type("pinned_key")
        .offer("demo.echo")
        .build()
        .unwrap();

    let trusted = if reject_cli {
        StaticPinnedKeyStore::default()
    } else {
        StaticPinnedKeyStore::new([AitpSigningKey::from_seed(&[CLI_SEED; 32]).verifying_key()])
    };
    let handshake = HandshakeServer::new(
        AitpSigningKey::from_seed(&[seed; 32]),
        manifest.clone(),
        vec![],
        NoOpResolver,
        vec!["demo.echo".into()],
    )
    // The CLI publishes no revocation list of its own.
    .with_revocation_policy(
        RevocationPolicy::default().with_fail_mode(RevocationFailMode::FailOpen),
    )
    .with_pinned_key_store(Arc::new(trusted));
    let app = ManifestServer::new(manifest)
        .router()
        .merge(handshake.router());
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service()).await.ok();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    (key, origin)
}

fn aitp() -> Command {
    Command::cargo_bin("aitp").unwrap()
}

/// Write `aitp keygen`-style output for the CLI's persistent key to a
/// unique temp file.
fn key_file(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("aitp-cli-{}-{name}.key", std::process::id()));
    let seed = hex_seed(CLI_SEED);
    std::fs::write(
        &path,
        format!("suite: ed25519\nseed:  {seed}\naid:   ignored\n"),
    )
    .unwrap();
    path
}

fn hex_seed(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

// The binary is run synchronously from the test thread while the
// multi-threaded runtime keeps the server's tasks running.

#[tokio::test(flavor = "multi_thread")]
async fn handshake_prints_tct_claims() {
    let (peer, origin) = spawn_peer(0x71, false).await;
    let key = key_file("ok");

    let out = aitp()
        .args(["handshake", &origin, "--insecure-localhost"])
        .args(["--grant", "demo.echo", "--offer", "demo.echo"])
        .arg("--key")
        .arg(&key)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let claims: serde_json::Value = serde_json::from_slice(&out.stdout).expect("claims JSON");
    assert_eq!(claims["iss"], peer.aid().to_string());
    assert_eq!(
        claims["aud"],
        AitpSigningKey::from_seed(&[CLI_SEED; 32]).aid().to_string()
    );
    assert!(claims["grants"]
        .as_array()
        .unwrap()
        .iter()
        .any(|g| g == "demo.echo"));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("trust on first use"), "stderr: {stderr}");
}

#[tokio::test(flavor = "multi_thread")]
async fn handshake_with_pinned_peer_aid() {
    let (peer, origin) = spawn_peer(0x72, false).await;
    let key = key_file("pinned");

    aitp()
        .args(["handshake", &origin, "--insecure-localhost"])
        .args(["--peer-aid", &peer.aid().to_string()])
        .args(["--grant", "demo.echo", "--offer", "demo.echo"])
        .arg("--key")
        .arg(&key)
        .assert()
        .success()
        .stderr(predicate::str::contains("trust on first use").not());
}

#[tokio::test(flavor = "multi_thread")]
async fn offers_default_to_the_requested_grants() {
    let (_peer, origin) = spawn_peer(0x7a, false).await;
    let key = key_file("default-offer");

    aitp()
        .args(["handshake", &origin, "--insecure-localhost"])
        .args(["--grant", "demo.echo"])
        .arg("--key")
        .arg(&key)
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "offering the requested capabilities: demo.echo",
        ));
}

#[tokio::test(flavor = "multi_thread")]
async fn handshake_refuses_peer_that_is_not_the_pinned_aid() {
    let (_peer, origin) = spawn_peer(0x73, false).await;
    let someone_else = AitpSigningKey::from_seed(&[0x99; 32]).aid().to_string();
    let key = key_file("mismatch");

    aitp()
        .args(["handshake", &origin, "--insecure-localhost"])
        .args(["--peer-aid", &someone_else])
        .arg("--key")
        .arg(&key)
        .assert()
        .failure()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::starts_with(
            "aitp: error: IDENTITY_FAILED: ",
        ));
}

#[tokio::test(flavor = "multi_thread")]
async fn rejected_ephemeral_key_prints_code_and_enrolment_hint() {
    let (_peer, origin) = spawn_peer(0x74, true).await;

    aitp()
        .args(["handshake", &origin, "--insecure-localhost", "--ephemeral"])
        .assert()
        .failure()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("aitp: error: IDENTITY_FAILED: "))
        .stderr(predicate::str::contains("hint:"))
        .stderr(predicate::str::contains("/enroll"));
}

#[tokio::test(flavor = "multi_thread")]
async fn rejected_persistent_key_prints_code_without_enrolment_hint() {
    let (_peer, origin) = spawn_peer(0x75, true).await;
    let key = key_file("rejected");

    aitp()
        .args(["handshake", &origin, "--insecure-localhost"])
        .arg("--key")
        .arg(&key)
        .assert()
        .failure()
        .stderr(predicate::str::contains("aitp: error: IDENTITY_FAILED: "))
        .stderr(predicate::str::contains("hint:").not());
}

#[tokio::test(flavor = "multi_thread")]
async fn offering_nothing_the_peer_requests_prints_offer_hint() {
    let (_peer, origin) = spawn_peer(0x78, false).await;
    let key = key_file("no-offer");

    aitp()
        .args(["handshake", &origin, "--insecure-localhost"])
        .arg("--key")
        .arg(&key)
        .assert()
        .failure()
        .stderr(predicate::str::contains("aitp: error: POLICY_VIOLATION: "))
        .stderr(predicate::str::contains("--offer <cap>"));
}

#[tokio::test(flavor = "multi_thread")]
async fn requesting_nothing_the_peer_offers_prints_grant_hint() {
    let (_peer, origin) = spawn_peer(0x79, false).await;
    let key = key_file("no-grant");

    aitp()
        .args(["handshake", &origin, "--insecure-localhost"])
        .args(["--grant", "not.offered", "--offer", "demo.echo"])
        .arg("--key")
        .arg(&key)
        .assert()
        .failure()
        .stderr(predicate::str::contains("aitp: error: POLICY_VIOLATION: "))
        .stderr(predicate::str::contains("--grant <cap>"));
}

#[tokio::test(flavor = "multi_thread")]
async fn handshake_against_unreachable_host_fails() {
    // Bind then drop: nothing listens on the port any more.
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };

    aitp()
        .args(["handshake", &format!("http://localhost:{port}")])
        .args(["--insecure-localhost", "--ephemeral", "--timeout", "5"])
        .assert()
        .failure()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::starts_with(
            "aitp: error: manifest fetch failed",
        ));
}

#[tokio::test(flavor = "multi_thread")]
async fn handshake_refuses_plain_http_without_opt_in() {
    let (_peer, origin) = spawn_peer(0x76, false).await;

    aitp()
        .args(["handshake", &origin, "--ephemeral"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("manifest fetch failed"));
}

#[test]
fn handshake_without_a_key_or_default_key_fails() {
    let missing = std::env::temp_dir().join(format!("aitp-cli-{}-none.key", std::process::id()));
    aitp()
        .args(["handshake", "https://peer.example"])
        .env("AITP_KEY", &missing)
        .assert()
        .failure()
        .stderr(predicate::str::contains("no key: pass --key"))
        .stderr(predicate::str::contains("aitp enroll"));
}

#[tokio::test(flavor = "multi_thread")]
async fn manifest_fetch_output_pipes_into_manifest_verify() {
    let (peer, origin) = spawn_peer(0x77, false).await;

    let out = aitp()
        .args(["manifest", "fetch", &origin, "--insecure-localhost"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    aitp()
        .args(["manifest", "verify", "--file", "-"])
        .write_stdin(out.stdout)
        .assert()
        .success()
        .stdout(predicate::str::contains(peer.aid().to_string()));
}
