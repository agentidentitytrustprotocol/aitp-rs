//! TCT renewal core (RFC-AITP-0013): the issuer's §4 checks, the
//! holder's §6.1 checks and the §3.1 PoP-input KATs.

use aitp::core::nonce_store::{InMemoryNonceStore, NonceStoreError};
use aitp::core::{base64url, Aid, ErrorCode, Timestamp};
use aitp::crypto::{AitpSigningKey, AitpVerifyingKey, Digest32, Signature};
use aitp::tct::{IssuedTct, TctBuilder, TctError};
use aitp_experimental::renewal::{
    build_renewal_request, parse_renewal_request, process_renewal_request, renewal_error_envelope,
    renewal_pop_input, renewal_response_envelope, verify_renewal_response, RenewalContext,
    RenewalError, RenewalResponseContext, RenewalResponseError, TctRenewalPayload,
};
use uuid::Uuid;

const GRANTS: &[&str] = &["demo.echo", "demo.write"];

fn offered() -> Vec<String> {
    GRANTS.iter().map(|s| s.to_string()).collect()
}

fn not_revoked(_: &Uuid) -> Result<bool, TctError> {
    Ok(false)
}

fn issue(issuer: &AitpSigningKey, holder: &AitpSigningKey, now: Timestamp, ttl: i64) -> IssuedTct {
    TctBuilder::new(issuer)
        .subject(holder.aid().clone())
        .audience(holder.aid().clone())
        .grants(GRANTS.iter().copied())
        .ttl_secs(ttl)
        .subject_pubkey(holder.verifying_key())
        .issued_at(now)
        .build()
        .unwrap()
}

/// Run `process_renewal_request` with a fresh store and the given
/// Manifest expiry, no revocation, every grant still offered.
async fn renew(
    request: &TctRenewalPayload,
    issuer: &AitpSigningKey,
    manifest_exp: Timestamp,
    now: Timestamp,
    ttl: i64,
) -> Result<IssuedTct, RenewalError> {
    let store = InMemoryNonceStore::new(16);
    let offered = offered();
    let ctx = RenewalContext::new(manifest_exp, &offered, &not_revoked, &store, now).ttl_secs(ttl);
    process_renewal_request(request, issuer, &ctx).await
}

#[tokio::test]
async fn round_trip_renewal_succeeds() {
    let issuer = AitpSigningKey::from_seed(&[0x01; 32]);
    let holder = AitpSigningKey::from_seed(&[0x02; 32]);
    let now = Timestamp(1_700_000_000);
    let manifest_exp = Timestamp(now.0 + 86_400);

    let original = issue(&issuer, &holder, now, 60);
    let request = build_renewal_request(
        &holder,
        original.token.clone(),
        base64url::encode(&[0x33; 16]),
    )
    .unwrap();

    let renewed = renew(&request, &issuer, manifest_exp, now, 3600)
        .await
        .unwrap();
    assert_ne!(renewed.claims.jti, original.claims.jti);
    assert_eq!(renewed.claims.sub, original.claims.sub);
    assert_eq!(renewed.claims.grants, original.claims.grants);
    assert_eq!(renewed.claims.exp.0, now.0 + 3600);
    assert!(renewed.voucher.is_some(), "renewal mints a fresh voucher");
}

#[tokio::test]
async fn renewal_with_wrong_holder_key_rejected() {
    let issuer = AitpSigningKey::from_seed(&[0x10; 32]);
    let holder = AitpSigningKey::from_seed(&[0x11; 32]);
    let attacker = AitpSigningKey::from_seed(&[0x12; 32]);
    let now = Timestamp(1_700_000_000);
    let original = issue(&issuer, &holder, now, 60);
    let request = build_renewal_request(
        &attacker, // attacker signs with its own key
        original.token,
        base64url::encode(&[0x44; 16]),
    )
    .unwrap();
    let err = renew(&request, &issuer, Timestamp(now.0 + 86_400), now, 3600)
        .await
        .unwrap_err();
    assert!(
        matches!(err, RenewalError::Tct(TctError::PopFailed)),
        "got {err:?}"
    );
}

#[tokio::test]
async fn renewal_bounded_by_manifest_expiry() {
    let issuer = AitpSigningKey::from_seed(&[0x20; 32]);
    let holder = AitpSigningKey::from_seed(&[0x21; 32]);
    let now = Timestamp(1_700_000_000);
    let manifest_exp = Timestamp(now.0 + 600); // 10 min left
    let original = issue(&issuer, &holder, now, 60);
    let request =
        build_renewal_request(&holder, original.token, base64url::encode(&[0x55; 16])).unwrap();
    // Caller asks for 1 hour TTL, manifest only allows 10 min.
    let renewed = renew(&request, &issuer, manifest_exp, now, 3600)
        .await
        .unwrap();
    assert_eq!(
        renewed.claims.exp.0, manifest_exp.0,
        "TTL must be capped by manifest expiry"
    );
}

#[tokio::test]
async fn renewal_after_manifest_expired_rejected() {
    let issuer = AitpSigningKey::from_seed(&[0x30; 32]);
    let holder = AitpSigningKey::from_seed(&[0x31; 32]);
    let now = Timestamp(1_700_000_000);
    let original = issue(&issuer, &holder, now, 60);
    let request =
        build_renewal_request(&holder, original.token, base64url::encode(&[0x66; 16])).unwrap();
    // Manifest already expired: the presented TCT now outlives it.
    let err = renew(&request, &issuer, Timestamp(now.0 - 1), now, 3600)
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            RenewalError::Tct(TctError::ExpiresAfterManifest | TctError::Expired)
        ),
        "got {err:?}"
    );
}

/// RFC-AITP-0013: renewal is not a bypass for Manifest rotation.
/// A TCT whose `exp` exceeds the issuer's current Manifest is refused,
/// where the old `skip_manifest_expiry_cap_dangerous` waiver let it in.
#[tokio::test]
async fn renewal_of_tct_outliving_rotated_manifest_rejected() {
    let issuer = AitpSigningKey::from_seed(&[0x32; 32]);
    let holder = AitpSigningKey::from_seed(&[0x33; 32]);
    let now = Timestamp(1_700_000_000);
    let original = issue(&issuer, &holder, now, 3600);
    let request =
        build_renewal_request(&holder, original.token, base64url::encode(&[0x67; 16])).unwrap();
    let err = renew(&request, &issuer, Timestamp(now.0 + 600), now, 3600)
        .await
        .unwrap_err();
    assert!(
        matches!(err, RenewalError::Tct(TctError::ExpiresAfterManifest)),
        "got {err:?}"
    );
}

#[tokio::test]
async fn renewal_of_expired_tct_rejected() {
    let issuer = AitpSigningKey::from_seed(&[0x34; 32]);
    let holder = AitpSigningKey::from_seed(&[0x35; 32]);
    let now = Timestamp(1_700_000_000);
    let original = issue(&issuer, &holder, now, 60);
    let request =
        build_renewal_request(&holder, original.token, base64url::encode(&[0x68; 16])).unwrap();
    let later = Timestamp(now.0 + 3600);
    let err = renew(&request, &issuer, Timestamp(now.0 + 86_400), later, 3600)
        .await
        .unwrap_err();
    assert!(
        matches!(err, RenewalError::Tct(TctError::Expired)),
        "got {err:?}"
    );
}

#[tokio::test]
async fn renewal_of_foreign_issuer_token_rejected() {
    let issuer = AitpSigningKey::from_seed(&[0x40; 32]);
    let other_issuer = AitpSigningKey::from_seed(&[0x41; 32]);
    let holder = AitpSigningKey::from_seed(&[0x42; 32]);
    let now = Timestamp(1_700_000_000);
    let foreign = issue(&other_issuer, &holder, now, 60);
    let request =
        build_renewal_request(&holder, foreign.token, base64url::encode(&[0x77; 16])).unwrap();
    // `issuer` cannot renew a TCT signed by `other_issuer`.
    assert!(
        renew(&request, &issuer, Timestamp(now.0 + 86_400), now, 3600)
            .await
            .is_err()
    );
}

/// RFC-AITP-0001 §5.4.5 / issue #140: a `current_tct` whose (unverified)
/// payload carries a duplicate top-level key must be rejected with
/// `ClaimsMalformed`, not silently accepted with the key's last
/// occurrence winning. Deliberately raw-text tampering of an
/// otherwise-validly-signed token's payload segment — a defect no
/// `serde_json::Value` can even represent.
#[tokio::test]
async fn renewal_of_token_with_duplicate_claim_is_rejected() {
    let issuer = AitpSigningKey::from_seed(&[0x50; 32]);
    let holder = AitpSigningKey::from_seed(&[0x51; 32]);
    let now = Timestamp(1_700_000_000);
    let original = issue(&issuer, &holder, now, 60);

    let parts: Vec<&str> = original.token.split('.').collect();
    assert_eq!(parts.len(), 3);
    let payload_bytes = base64url::decode_strict(parts[1]).unwrap();
    let payload_str = std::str::from_utf8(&payload_bytes).unwrap();
    assert!(payload_str.starts_with('{'));
    let dup_payload = format!("{{\"ver\":\"aitp/0.3\",{}", &payload_str[1..]);
    let dup_token = format!(
        "{}.{}.{}",
        parts[0],
        base64url::encode(dup_payload.as_bytes()),
        parts[2]
    );

    // The holder's builder refuses it too; present it directly.
    assert!(matches!(
        build_renewal_request(&holder, dup_token.clone(), base64url::encode(&[0x88; 16])),
        Err(RenewalError::Tct(TctError::ClaimsMalformed(_)))
    ));
    let request = TctRenewalPayload::new(dup_token, base64url::encode(&[0x88; 16]), "AA".into());
    let err = renew(&request, &issuer, Timestamp(now.0 + 86_400), now, 3600)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, RenewalError::Tct(TctError::ClaimsMalformed(m)) if m.contains("duplicate field `ver`")),
        "got {err:?}"
    );
}

/// #196: the same signed request presented twice mints only once.
#[tokio::test]
async fn replayed_pop_nonce_rejected() {
    let issuer = AitpSigningKey::from_seed(&[0x60; 32]);
    let holder = AitpSigningKey::from_seed(&[0x61; 32]);
    let now = Timestamp(1_700_000_000);
    let original = issue(&issuer, &holder, now, 600);
    let request =
        build_renewal_request(&holder, original.token, base64url::encode(&[0x99; 16])).unwrap();
    let store = InMemoryNonceStore::new(16);
    let offered = offered();
    let ctx = RenewalContext::new(
        Timestamp(now.0 + 86_400),
        &offered,
        &not_revoked,
        &store,
        now,
    );
    process_renewal_request(&request, &issuer, &ctx)
        .await
        .expect("first presentation renews");
    let err = process_renewal_request(&request, &issuer, &ctx)
        .await
        .unwrap_err();
    assert!(matches!(err, RenewalError::Replayed), "got {err:?}");
    assert_eq!(store.len(), 1);
}

/// A request whose PoP fails never reaches the store, so it cannot
/// burn the holder's nonce.
#[tokio::test]
async fn failed_pop_does_not_record_nonce() {
    let issuer = AitpSigningKey::from_seed(&[0x62; 32]);
    let holder = AitpSigningKey::from_seed(&[0x63; 32]);
    let attacker = AitpSigningKey::from_seed(&[0x64; 32]);
    let now = Timestamp(1_700_000_000);
    let original = issue(&issuer, &holder, now, 600);
    let nonce = base64url::encode(&[0x9a; 16]);
    let forged = build_renewal_request(&attacker, original.token.clone(), nonce.clone()).unwrap();
    let store = InMemoryNonceStore::new(16);
    let offered = offered();
    let ctx = RenewalContext::new(
        Timestamp(now.0 + 86_400),
        &offered,
        &not_revoked,
        &store,
        now,
    );
    let err = process_renewal_request(&forged, &issuer, &ctx)
        .await
        .unwrap_err();
    assert!(
        matches!(err, RenewalError::Tct(TctError::PopFailed)),
        "got {err:?}"
    );
    assert!(store.is_empty());
    let genuine = build_renewal_request(&holder, original.token, nonce).unwrap();
    process_renewal_request(&genuine, &issuer, &ctx)
        .await
        .expect("holder's nonce is still usable");
}

#[tokio::test]
async fn pop_nonce_of_wrong_length_rejected() {
    let issuer = AitpSigningKey::from_seed(&[0x65; 32]);
    let holder = AitpSigningKey::from_seed(&[0x66; 32]);
    let now = Timestamp(1_700_000_000);
    let original = issue(&issuer, &holder, now, 600);
    for len in [0usize, 8, 15, 17, 32] {
        let request = build_renewal_request(
            &holder,
            original.token.clone(),
            base64url::encode(&vec![1; len]),
        )
        .unwrap();
        let err = renew(&request, &issuer, Timestamp(now.0 + 86_400), now, 3600)
            .await
            .unwrap_err();
        assert!(
            matches!(err, RenewalError::NonceMalformed(_)),
            "len {len}: got {err:?}"
        );
    }
    // Not base64url at all.
    let mut request =
        build_renewal_request(&holder, original.token, base64url::encode(&[1; 16])).unwrap();
    request.pop_nonce = "not base64url!".into();
    let err = renew(&request, &issuer, Timestamp(now.0 + 86_400), now, 3600)
        .await
        .unwrap_err();
    assert!(
        matches!(err, RenewalError::NonceMalformed(_)),
        "got {err:?}"
    );
}

/// #196: the old `accept_unchecked_revocation_dangerous` waiver let a
/// revoked-but-unexpired TCT renew. It must not.
#[tokio::test]
async fn renewal_of_revoked_tct_rejected() {
    let issuer = AitpSigningKey::from_seed(&[0x70; 32]);
    let holder = AitpSigningKey::from_seed(&[0x71; 32]);
    let now = Timestamp(1_700_000_000);
    let original = issue(&issuer, &holder, now, 600);
    let revoked_jti = original.claims.jti;
    let revoked = move |j: &Uuid| Ok(*j == revoked_jti);
    let request =
        build_renewal_request(&holder, original.token, base64url::encode(&[0xaa; 16])).unwrap();
    let store = InMemoryNonceStore::new(16);
    let offered = offered();
    let ctx = RenewalContext::new(Timestamp(now.0 + 86_400), &offered, &revoked, &store, now);
    let err = process_renewal_request(&request, &issuer, &ctx)
        .await
        .unwrap_err();
    assert!(
        matches!(err, RenewalError::Tct(TctError::Revoked)),
        "got {err:?}"
    );
    assert!(store.is_empty(), "a refused request records no nonce");
}

/// A grant the issuer's Manifest no longer offers is dropped.
#[tokio::test]
async fn withdrawn_grant_is_dropped() {
    let issuer = AitpSigningKey::from_seed(&[0x72; 32]);
    let holder = AitpSigningKey::from_seed(&[0x73; 32]);
    let now = Timestamp(1_700_000_000);
    let original = issue(&issuer, &holder, now, 600);
    let request =
        build_renewal_request(&holder, original.token, base64url::encode(&[0xab; 16])).unwrap();
    let store = InMemoryNonceStore::new(16);
    let offered = vec!["demo.echo".to_string()];
    let ctx = RenewalContext::new(
        Timestamp(now.0 + 86_400),
        &offered,
        &not_revoked,
        &store,
        now,
    );
    let renewed = process_renewal_request(&request, &issuer, &ctx)
        .await
        .unwrap();
    assert_eq!(renewed.claims.grants, vec!["demo.echo".to_string()]);
}

/// Every grant withdrawn (by the Manifest or by policy): refused.
#[tokio::test]
async fn all_grants_withdrawn_refused() {
    let issuer = AitpSigningKey::from_seed(&[0x74; 32]);
    let holder = AitpSigningKey::from_seed(&[0x75; 32]);
    let now = Timestamp(1_700_000_000);
    let original = issue(&issuer, &holder, now, 600);
    let store = InMemoryNonceStore::new(16);
    let manifest_exp = Timestamp(now.0 + 86_400);

    let request = build_renewal_request(
        &holder,
        original.token.clone(),
        base64url::encode(&[0xac; 16]),
    )
    .unwrap();
    let none_offered: Vec<String> = vec!["other.cap".into()];
    let ctx = RenewalContext::new(manifest_exp, &none_offered, &not_revoked, &store, now);
    let err = process_renewal_request(&request, &issuer, &ctx)
        .await
        .unwrap_err();
    assert!(matches!(err, RenewalError::GrantsWithdrawn), "got {err:?}");

    let request =
        build_renewal_request(&holder, original.token, base64url::encode(&[0xad; 16])).unwrap();
    let offered = offered();
    let deny_all = |_: &Aid, _: &[String]| Vec::new();
    let ctx = RenewalContext::new(manifest_exp, &offered, &not_revoked, &store, now)
        .grant_policy(&deny_all);
    let err = process_renewal_request(&request, &issuer, &ctx)
        .await
        .unwrap_err();
    assert!(matches!(err, RenewalError::GrantsWithdrawn), "got {err:?}");
}

#[tokio::test]
async fn grant_policy_narrows_and_voucher_is_optional() {
    let issuer = AitpSigningKey::from_seed(&[0x76; 32]);
    let holder = AitpSigningKey::from_seed(&[0x77; 32]);
    let now = Timestamp(1_700_000_000);
    let original = issue(&issuer, &holder, now, 600);
    let request =
        build_renewal_request(&holder, original.token, base64url::encode(&[0xae; 16])).unwrap();
    let store = InMemoryNonceStore::new(16);
    let offered = offered();
    let policy = |_: &Aid, g: &[String]| {
        g.iter()
            .filter(|c| c.as_str() == "demo.write")
            .cloned()
            .collect()
    };
    let ctx = RenewalContext::new(
        Timestamp(now.0 + 86_400),
        &offered,
        &not_revoked,
        &store,
        now,
    )
    .grant_policy(&policy)
    .without_voucher();
    let renewed = process_renewal_request(&request, &issuer, &ctx)
        .await
        .unwrap();
    assert_eq!(renewed.claims.grants, vec!["demo.write".to_string()]);
    assert!(renewed.voucher.is_none());
}

#[tokio::test]
async fn nonce_store_at_capacity_is_a_local_error() {
    let issuer = AitpSigningKey::from_seed(&[0x78; 32]);
    let holder = AitpSigningKey::from_seed(&[0x79; 32]);
    let now = Timestamp(1_700_000_000);
    let original = issue(&issuer, &holder, now, 600);
    let store = InMemoryNonceStore::new(1);
    let offered = offered();
    let ctx = RenewalContext::new(
        Timestamp(now.0 + 86_400),
        &offered,
        &not_revoked,
        &store,
        now,
    );
    let first = build_renewal_request(
        &holder,
        original.token.clone(),
        base64url::encode(&[0xb0; 16]),
    )
    .unwrap();
    process_renewal_request(&first, &issuer, &ctx)
        .await
        .unwrap();
    let second =
        build_renewal_request(&holder, original.token, base64url::encode(&[0xb1; 16])).unwrap();
    let err = process_renewal_request(&second, &issuer, &ctx)
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            RenewalError::NonceStore(NonceStoreError::AtCapacity { .. })
        ),
        "got {err:?}"
    );
}

/// The renewal future is `Send`, so a multi-threaded server can await it.
#[test]
fn renewal_future_is_send() {
    fn assert_send<T: Send>(_: &T) {}
    let issuer = AitpSigningKey::from_seed(&[0x7a; 32]);
    let store = InMemoryNonceStore::new(1);
    let offered = offered();
    let ctx = RenewalContext::new(Timestamp(1), &offered, &not_revoked, &store, Timestamp(0));
    let req = TctRenewalPayload::new(String::new(), String::new(), String::new());
    let fut = process_renewal_request(&req, &issuer, &ctx);
    assert_send(&fut);
}

fn kat_vector(id: &str) -> serde_json::Value {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/schemas/known-answer/jcs-sha256.json");
    let kat: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    kat["vectors"]
        .as_array()
        .expect("vectors array")
        .iter()
        .find(|v| v["id"].as_str() == Some(id))
        .unwrap_or_else(|| panic!("vector {id} missing from jcs-sha256.json"))
        .clone()
}

/// kat-renewal-pop-001 and kat-renewal-pop-002-p256, read from the
/// vendored spec file: the input bytes, its digest, and the
/// signature verifying over it under the signer AID.
#[test]
fn renewal_pop_input_matches_kats() {
    for id in ["kat-renewal-pop-001", "kat-renewal-pop-002-p256"] {
        let v = kat_vector(id);
        let nonce = base64url::decode_strict(v["pop_nonce"].as_str().unwrap()).unwrap();
        let input = renewal_pop_input(
            v["issuer_aid"].as_str().unwrap(),
            v["current_tct_jti"].as_str().unwrap(),
            &nonce,
        );
        assert_eq!(
            hex::encode(&input),
            v["input_hex"].as_str().unwrap(),
            "{id}"
        );
        assert_eq!(input.len() as u64, v["input_len_bytes"].as_u64().unwrap());
        let digest = Digest32::sha256(&input);
        assert_eq!(
            hex::encode(digest.as_bytes()),
            v["sha256_hex"].as_str().unwrap()
        );
        let signer = Aid::parse(v["signer_aid"].as_str().unwrap()).unwrap();
        let pk = AitpVerifyingKey::from_aid(&signer).unwrap();
        let sig = v["signature"]
            .as_str()
            .or(v["signature_b64url"].as_str())
            .unwrap();
        pk.verify_jcs(&digest, &Signature::parse(sig).unwrap())
            .unwrap_or_else(|e| panic!("{id}: {e}"));
        // The nonce enters as its decoded bytes, not its string.
        let wrong = renewal_pop_input(
            v["issuer_aid"].as_str().unwrap(),
            v["current_tct_jti"].as_str().unwrap(),
            v["pop_nonce"].as_str().unwrap().as_bytes(),
        );
        assert!(pk
            .verify_jcs(&Digest32::sha256(&wrong), &Signature::parse(sig).unwrap())
            .is_err());
        if let Some(double) = v["double_hash_signature_MUST_NOT_verify"].as_str() {
            assert!(pk
                .verify_jcs(&digest, &Signature::parse(double).unwrap())
                .is_err());
        }
    }
}

/// §4: the PoP is checked before revocation, so a revoked TCT with a
/// bad PoP is refused for the PoP.
#[tokio::test]
async fn pop_is_checked_before_revocation() {
    let issuer = AitpSigningKey::from_seed(&[0x7b; 32]);
    let holder = AitpSigningKey::from_seed(&[0x7c; 32]);
    let other = AitpSigningKey::from_seed(&[0x7d; 32]);
    let now = Timestamp(1_700_000_000);
    let original = issue(&issuer, &holder, now, 600);
    let revoked = |_: &Uuid| Ok(true);
    let request =
        build_renewal_request(&other, original.token, base64url::encode(&[0xab; 16])).unwrap();
    let store = InMemoryNonceStore::new(16);
    let offered = offered();
    let ctx = RenewalContext::new(Timestamp(now.0 + 86_400), &offered, &revoked, &store, now);
    let err = process_renewal_request(&request, &issuer, &ctx)
        .await
        .unwrap_err();
    assert!(
        matches!(err, RenewalError::Tct(TctError::PopFailed)),
        "got {err:?}"
    );
    assert_eq!(err.error_code(), ErrorCode::PopResponseInvalid);
}

/// §4 step 6: a grant the policy returns outside its input is dropped.
#[tokio::test]
async fn grant_policy_cannot_widen() {
    let issuer = AitpSigningKey::from_seed(&[0x7e; 32]);
    let holder = AitpSigningKey::from_seed(&[0x7f; 32]);
    let now = Timestamp(1_700_000_000);
    let original = issue(&issuer, &holder, now, 600);
    let request =
        build_renewal_request(&holder, original.token, base64url::encode(&[0xac; 16])).unwrap();
    let store = InMemoryNonceStore::new(16);
    let offered = offered();
    let widen = |_: &Aid, _: &[String]| vec!["demo.echo".to_string(), "demo.admin".into()];
    let ctx = RenewalContext::new(
        Timestamp(now.0 + 86_400),
        &offered,
        &not_revoked,
        &store,
        now,
    )
    .grant_policy(&widen);
    let renewed = process_renewal_request(&request, &issuer, &ctx)
        .await
        .unwrap();
    assert_eq!(renewed.claims.grants, vec!["demo.echo".to_string()]);
}

/// §4 step 2: a TCT whose `aud` is not its `sub` is not one this
/// issuer issued for renewal. (`TctBuilder` refuses to mint one.)
#[test]
fn audience_other_than_subject_is_tct_signature_invalid() {
    assert_eq!(
        RenewalError::Tct(TctError::AudienceMismatch).error_code(),
        ErrorCode::TctSignatureInvalid
    );
}

#[test]
fn malformed_request_body_is_pop_response_invalid() {
    for body in [
        &b"not json"[..],
        br#"{"current_tct":"a","pop_nonce":"b"}"#,
        br#"{"current_tct":"a","pop_nonce":"b","pop_signature":"c","x":1}"#,
        br#"{"current_tct":"a","pop_nonce":"b","pop_signature":"c","pop_nonce":"d"}"#,
    ] {
        let err = parse_renewal_request(body).unwrap_err();
        assert_eq!(err.error_code(), ErrorCode::PopResponseInvalid);
    }
}

struct Exchange {
    issuer: AitpSigningKey,
    holder: AitpSigningKey,
    current: String,
    nonce: String,
    renewed: IssuedTct,
    now: Timestamp,
}

async fn exchange() -> Exchange {
    let issuer = AitpSigningKey::from_seed(&[0x83; 32]);
    let holder = AitpSigningKey::from_seed(&[0x84; 32]);
    let now = Timestamp(1_700_000_000);
    let current = issue(&issuer, &holder, now, 600).token;
    let nonce = base64url::encode(&[0xae; 16]);
    let request = build_renewal_request(&holder, current.clone(), nonce.clone()).unwrap();
    let renewed = renew(&request, &issuer, Timestamp(now.0 + 86_400), now, 600)
        .await
        .unwrap();
    Exchange {
        issuer,
        holder,
        current,
        nonce,
        renewed,
        now,
    }
}

#[tokio::test]
async fn holder_accepts_the_issuer_response() {
    let x = exchange().await;
    let env =
        renewal_response_envelope(&x.issuer, &x.renewed, &x.nonce, Uuid::new_v4(), x.now).unwrap();
    let ctx = RenewalResponseContext::new(x.holder.aid(), &x.current, &x.nonce, x.now);
    let out = verify_renewal_response(&env, &ctx).unwrap();
    assert_eq!(out.tct.claims.jti, x.renewed.claims.jti);
    assert_eq!(out.grant_voucher, x.renewed.voucher);
}

#[tokio::test]
async fn holder_rejects_a_bad_response() {
    let x = exchange().await;
    let ctx = RenewalResponseContext::new(x.holder.aid(), &x.current, &x.nonce, x.now);

    // Step 3: another nonce echoed.
    let other_nonce = base64url::encode(&[0xaf; 16]);
    let env = renewal_response_envelope(&x.issuer, &x.renewed, &other_nonce, Uuid::new_v4(), x.now)
        .unwrap();
    let err = verify_renewal_response(&env, &ctx).unwrap_err();
    assert_eq!(err.error_code(), ErrorCode::NonceMismatch);

    // Step 2: signed by someone other than the issuer.
    let env =
        renewal_response_envelope(&x.holder, &x.renewed, &x.nonce, Uuid::new_v4(), x.now).unwrap();
    let err = verify_renewal_response(&env, &ctx).unwrap_err();
    assert_eq!(err.error_code(), ErrorCode::PeerMismatch);

    // Step 1: outside the timestamp window.
    let env = renewal_response_envelope(
        &x.issuer,
        &x.renewed,
        &x.nonce,
        Uuid::new_v4(),
        Timestamp(x.now.0 - 3600),
    )
    .unwrap();
    let err = verify_renewal_response(&env, &ctx).unwrap_err();
    assert_eq!(err.error_code(), ErrorCode::TimestampExpired);

    // Step 6: a grant the current TCT does not carry.
    let wider = TctBuilder::new(&x.issuer)
        .subject(x.holder.aid().clone())
        .audience(x.holder.aid().clone())
        .grants(["demo.echo", "demo.admin"])
        .ttl_secs(600)
        .subject_pubkey(x.holder.verifying_key())
        .issued_at(x.now)
        .build()
        .unwrap();
    let env =
        renewal_response_envelope(&x.issuer, &wider, &x.nonce, Uuid::new_v4(), x.now).unwrap();
    let err = verify_renewal_response(&env, &ctx).unwrap_err();
    assert_eq!(err.error_code(), ErrorCode::GrantOverflow);
}

#[tokio::test]
async fn holder_surfaces_an_issuer_refusal() {
    let x = exchange().await;
    let ctx = RenewalResponseContext::new(x.holder.aid(), &x.current, &x.nonce, x.now);
    let env = renewal_error_envelope(
        &x.issuer,
        ErrorCode::TctRevoked,
        "revoked",
        false,
        Uuid::new_v4(),
        x.now,
    )
    .unwrap();
    let err = verify_renewal_response(&env, &ctx).unwrap_err();
    assert!(
        matches!(
            &err,
            RenewalResponseError::Refused {
                code: ErrorCode::TctRevoked,
                ..
            }
        ),
        "got {err:?}"
    );
    assert_eq!(err.error_code(), ErrorCode::TctRevoked);
}
