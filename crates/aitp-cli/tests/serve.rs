//! End-to-end tests for `aitp serve --interop`: run the built binary as
//! the peer and drive it with `aitp enroll` / `aitp handshake` and raw
//! HTTP.

#![cfg(feature = "serve")]

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command as StdCommand, Stdio};

use aitp::core::base64url;
use aitp::crypto::{AitpSigningKey, Digest32};
use assert_cmd::cargo::CommandCargoExt;
use assert_cmd::Command;
use serde_json::{json, Value};

/// A running `aitp serve --interop`, killed on drop.
struct Peer {
    child: Child,
    origin: String,
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
    }
}

/// Start the peer on an ephemeral loopback port and wait for its
/// `listening on` line.
fn spawn_peer(seed: u8) -> Peer {
    let mut child = StdCommand::cargo_bin("aitp")
        .unwrap()
        .args(["serve", "--interop", "--listen", "127.0.0.1:0"])
        .env("AITP_PEER_KEY", format!("{seed:02x}").repeat(32))
        .env("RUST_LOG", "warn")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stderr.take().unwrap()).lines();
    let addr = loop {
        let line = lines.next().expect("peer exited early").unwrap();
        if let Some((_, addr)) = line.split_once(" listening on ") {
            break addr.trim().to_owned();
        }
    };
    // Keep draining so the peer never blocks on a full pipe.
    std::thread::spawn(move || lines.for_each(drop));
    let port = addr.rsplit(':').next().unwrap();
    Peer {
        child,
        origin: format!("http://localhost:{port}"),
    }
}

fn aitp() -> Command {
    Command::cargo_bin("aitp").unwrap()
}

/// A path for a key file that does not exist yet.
fn fresh_key_path(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("aitp-serve-{}-{name}.key", std::process::id()));
    std::fs::remove_file(&path).ok();
    path
}

fn client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::new()
}

fn post_json(peer: &Peer, path: &str, body: &Value) -> (u16, Value) {
    let resp = client()
        .post(format!("{}{path}", peer.origin))
        .json(body)
        .send()
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().unwrap_or(Value::Null))
}

/// A signed `POST /enroll` body for `key`, as `aitp enroll` builds it
/// (crate::enrol).
fn enrol_body(peer: &Peer, key: &AitpSigningKey) -> Value {
    let (status, challenge) = post_json(peer, "/enroll/challenge", &json!({}));
    assert_eq!(status, 200, "{challenge}");
    let nonce_b64 = challenge["nonce"].as_str().unwrap();
    let nonce = base64url::decode_strict(nonce_b64).unwrap();
    let peer_aid = challenge["peer_aid"].as_str().unwrap();
    let aid = key.aid().to_string();
    let mut input = b"aitp-interop-enrol-v1".to_vec();
    for part in [aid.as_bytes(), peer_aid.as_bytes(), &nonce] {
        input.push(0);
        input.extend_from_slice(part);
    }
    let signature = key.sign_jcs(&Digest32::sha256(&input));
    json!({ "aid": aid, "nonce": nonce_b64, "signature": signature.as_str() })
}

#[test]
fn enroll_then_handshake_then_echo() {
    let peer = spawn_peer(0x51);
    let key = fresh_key_path("e2e");

    // Unenrolled: the handshake is refused.
    aitp()
        .args(["handshake", &peer.origin, "--insecure-localhost"])
        .args(["--grant", "aitp.interop.echo", "--ephemeral"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("IDENTITY_FAILED"));

    let out = aitp()
        .args(["enroll", &peer.origin, "--insecure-localhost"])
        .env("AITP_KEY", &key)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let enrolled: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(enrolled["capabilities"], json!(["aitp.interop.echo"]));
    assert!(key.exists(), "enroll creates the default key");

    let out = aitp()
        .args(["echo", &peer.origin, "--insecure-localhost"])
        .env("AITP_KEY", &key)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("offering the requested capabilities"),
        "{stderr}"
    );
    assert!(stderr.contains("proof of possession"), "{stderr}");
    let echo: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(echo["echo"]["sub"], enrolled["aid"]);
    assert_eq!(echo["echo"]["grants"], json!(["aitp.interop.echo"]));

    // A token that fails the issuer's own checks gets no challenge.
    let (status, err) = post_json(&peer, "/echo/challenge", &json!({"tct": "a.b.c"}));
    assert_eq!(status, 401, "{err}");
    assert_eq!(err["error"], "TCT_SIGNATURE_INVALID");
    // No bearer path: a TCT without a pop_response is not an echo request.
    let (status, err) = post_json(&peer, "/echo", &json!({"tct": "a.b.c"}));
    assert_eq!(status, 400, "{err}");

    let status: Value = client()
        .get(format!("{}/status", peer.origin))
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(status["status"], "ok");
    assert_eq!(status["enrolled"], 1);
    std::fs::remove_file(&key).ok();
}

#[test]
fn oversized_bodies_get_413() {
    let peer = spawn_peer(0x52);
    let big = vec![b'a'; 65 * 1024];
    for path in [
        "/enroll",
        "/aitp/handshake/hello",
        "/echo/challenge",
        "/echo",
    ] {
        let resp = client()
            .post(format!("{}{path}", peer.origin))
            .header("content-type", "application/json")
            .body(big.clone())
            .send()
            .unwrap();
        assert_eq!(resp.status().as_u16(), 413, "{path}");
    }
    // Without a Content-Length (a reader body goes chunked) as well.
    let resp = client()
        .post(format!("{}/enroll", peer.origin))
        .body(reqwest::blocking::Body::new(std::io::Cursor::new(vec![
            b'a';
            80 * 1024
        ])))
        .send()
        .unwrap();
    assert_eq!(resp.status().as_u16(), 413);
}

#[test]
fn sixth_enrolment_from_one_address_gets_429() {
    let peer = spawn_peer(0x53);
    for i in 0..5u8 {
        let key = AitpSigningKey::from_seed(&[0x60 + i; 32]);
        let (status, body) = post_json(&peer, "/enroll", &enrol_body(&peer, &key));
        assert_eq!(status, 200, "attempt {}: {body}", i + 1);
    }
    let key = AitpSigningKey::from_seed(&[0x6f; 32]);
    let (status, body) = post_json(&peer, "/enroll", &enrol_body(&peer, &key));
    assert_eq!(status, 429, "{body}");
    assert_eq!(body["error"], "rate_limited");
}

#[test]
fn replayed_nonce_is_rejected() {
    let peer = spawn_peer(0x54);
    let key = AitpSigningKey::from_seed(&[0x70; 32]);
    let body = enrol_body(&peer, &key);
    assert_eq!(post_json(&peer, "/enroll", &body).0, 200);
    let (status, err) = post_json(&peer, "/enroll", &body);
    assert_eq!(status, 401, "{err}");
    assert_eq!(err["error"], "bad_nonce");
}

#[test]
fn bad_signature_is_rejected_without_burning_the_nonce() {
    let peer = spawn_peer(0x55);
    let key = AitpSigningKey::from_seed(&[0x71; 32]);
    let mut body = enrol_body(&peer, &key);
    let good = body["signature"].as_str().unwrap().to_owned();
    // Another key's signature over the same input.
    let other = enrol_body(&peer, &AitpSigningKey::from_seed(&[0x72; 32]));
    body["signature"] = other["signature"].clone();
    let (status, err) = post_json(&peer, "/enroll", &body);
    assert_eq!(status, 401, "{err}");
    assert_eq!(err["error"], "bad_signature");
    // The honest request still goes through on the same nonce.
    body["signature"] = json!(good);
    assert_eq!(post_json(&peer, "/enroll", &body).0, 200);
}

#[test]
fn malformed_enrolment_is_a_400() {
    let peer = spawn_peer(0x56);
    let (status, err) = post_json(&peer, "/enroll", &json!({"aid": "nope"}));
    assert_eq!(status, 400);
    assert_eq!(err["error"], "bad_request");
}
