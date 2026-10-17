# Upgrading from 0.13 to 0.14

0.14.0 implements spec proposal
[agentidentitytrustprotocol#72](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/pull/72)
(P-256 signing input, algorithm-agile pinned keys, strict UUID v4 ids,
self-attestation TCTs, pinned-key admission) and pluggable signing
backends (KMS, HSM). Tracking issue: [#205](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/205).

It is a breaking release. The changes below are ordered by how likely
they are to affect you. The per-crate `crates/*/CHANGELOG.md` files are
the authoritative record of what shipped (#201).

## 1. P-256 signatures changed on the wire

0.13 signed P-256 JCS artifacts (envelopes, Manifests, revocation
snapshots, session bundles, pinned-key proofs) with ECDSA-SHA-256 over
the digest `d = SHA-256(signing_input)`. That is a double hash, which
RFC-AITP-0001 §5.4.6 does not allow. 0.14 signs `d` itself as the ECDSA
message hash, which is what other implementations do.

- A P-256 signature made by 0.13 **does not verify** under 0.14, and the
  reverse. Ed25519 is unaffected. JWS (ES256) TCTs were already correct.
- Re-sign every stored P-256 JCS artifact, such as a published Manifest
  or a cached revocation snapshot, after upgrading. Upgrade P-256 peers
  together.
- Verification is strict (§5.4.7). It rejects `r` or `s` equal to 0 or
  ≥ n, and high-S (`s > n/2`). Signing always emits low-S. The same rule
  applies to AITP-minted ES256 JWS (TCTs, vouchers, delegations).
  Third-party JOSE, meaning an IdP's OIDC ID token or a DPoP proof, is
  verified per RFC 7515/7518 and accepts high-S
  (`AitpVerifyingKey::verify_raw_jose`). Its bytes are therefore
  malleable, so key any replay cache on the nonce or `jti`, never on
  the raw token.

`AitpSigningKey::sign(&[u8])` and `AitpVerifyingKey::verify(&[u8], …)`
are gone. Each had a hash step that depended on the algorithm. Use:

| 0.13 | 0.14 |
|---|---|
| `key.sign(&d)` on a JCS digest | `key.sign_jcs(&Digest32::from_bytes(d))` |
| `vk.verify(&d, &sig)` | `vk.verify_jcs(&Digest32::from_bytes(d), &sig)` |
| raw-message signing | `key.sign_raw(msg)` (Ed25519, or ES256 JWS input) |

`Digest32::sha256(signing_input)` computes `d` for you.

## 2. Pinned keys: a trust store is required, and P-256 works

`verify_pinned_key` takes a store and returns the verified key:

```rust
// 0.13
pub fn verify_pinned_key(d: &IdentityDescriptor, ctx: &PinnedKeyVerifyContext<'_>)
    -> Result<(), HandshakeError>;
// 0.14
pub fn verify_pinned_key(
    descriptor: &IdentityDescriptor,
    ctx: &PinnedKeyVerifyContext<'_>,
    store: &dyn PinnedKeyStore,
) -> Result<VerifiedPinnedKey, HandshakeError>;   // { algorithm, key, aid }
```

- `PeerConfig::pinned_key_store` is now `&dyn PinnedKeyStore`, not
  `Option<…>`. There is no possession-only mode. An OIDC-only deployment
  passes `&NoPinnedKeys`.
- `PinnedKeyStore::is_trusted` takes `&AitpVerifyingKey`, keyed by
  `(algorithm, key)`, not `&[u8; 32]`. `StaticPinnedKeyStore::new` takes
  verifying keys. Use `StaticPinnedKeyStore::from_aids(&[aid, …])` to
  build one from AIDs.
- Load a trust-anchors `pinned_keys` array with
  `StaticPinnedKeyStore::from_entries(&entries)`, where each entry is a
  `PinnedKeyEntry { subject, public_key, algorithm?, allowed_capabilities? }`.
  An `algorithm` that disagrees with the key length (43 characters for
  Ed25519, 44 for P-256) is an error at load time, and so is a P-256
  key that is not a curve point.
- `PinnedKeyVerifyContext` gains `subject: SubjectBinding`. The default
  `Unchecked` keeps 0.13 behaviour. `SenderAid` requires
  `subject == sender AID`.
- A `pinned_key` descriptor that carries `issuer` is rejected with
  `IDENTITY_FAILED`.
- The proof must carry the algorithm tag of the sender AID (`p256.` for
  P-256), and `public_key` must equal the sender AID's key.

The Python and Node bindings fail closed the same way. Pass
`pinned_keys=[peer_aid]` (Python) or `{ pinnedKeys: [peerAid] }` (Node)
to `new_session` / `new_responder`. Without it every `pinned_key` peer is
rejected.

## 3. Builders take a signer, not a key

Every builder that signs takes `&dyn AitpSigner`. `&AitpSigningKey`
coerces, so most call sites compile unchanged:

```rust
TctBuilder::new(&key)            // still works: AitpSigningKey: AitpSigner
TctBuilder::new(&kms_signer)     // any backend
TctBuilder::new_async(&signer).….build_async().await   // async backends
```

This applies to `TctBuilder`, `ManifestBuilder`, `DelegationBuilder`
(`new`, `extending`, plus `_async` forms), `SessionBundleBuilder`,
`sign_envelope` / `sign_envelope_with` (plus `_async`),
`jws::sign_compact` (plus `_async`), and in `aitp-transport-http`,
`HandshakeServer::new` and `EmptyRevocationProvider::new`. Both accept
any `S: AitpSigner + 'static`.

To plug in a backend, implement `AitpSigner` (sync) or `AsyncAitpSigner`
(async; `DynAsyncAitpSigner` is the object-safe form, and every
`AsyncAitpSigner` implements it):

```rust
pub trait AitpSigner: Send + Sync {
    fn aid(&self) -> &Aid;
    fn max_message_len(&self) -> Option<usize> { None }
    fn public_key(&self) -> Result<AitpVerifyingKey, SignerError>;
    fn sign(&self, request: SignRequest<'_>) -> Result<BackendSignature, SignerError>;
    fn as_signing_key(&self) -> Option<&AitpSigningKey> { None }
}
```

- `SignRequest::Ed25519Message(&[u8])` is the whole message.
  `SignRequest::P256Digest(&Digest32)` is the 32-byte digest, for a KMS
  "sign digest" call.
- A backend may return `BackendSignature::Der(..)` (AWS KMS, GCP KMS)
  or `Raw([u8; 64])`. The library converts DER to `r||s`, normalises to
  low-S, and verifies against the AID key before emitting. A signature
  that fails this check is never put on the wire
  (`SignerError::VerificationFailed`).
- `SignerError::Transient` / `Permanent` tell retryable backend failures
  apart. `transient_retry_after` carries a `Retry-After`.
- Call `check_public_key(&signer)` at startup to confirm the backend key
  matches the configured AID (`SignerError::KeyMismatch`).
- The `test-util` feature provides `aitp_crypto::testing::MockKmsSigner`,
  a DER-emitting, size-limited, fault-injecting backend for tests. No
  cloud SDK is a dependency.

## 4. Ids are strict UUID v4

TCT `jti`, voucher `src_jti`, envelope `message_id`, every delegation
hop `jti` and every revocation-list `entries[].jti` must be lowercase,
hyphenated UUID v4 (proposal Item 6b, spec PR C at 35aeb84). The check runs on the
unverified token, before signature work. The rejection codes are:

| Field | Code |
|---|---|
| TCT `jti` | `TCT_SIGNATURE_INVALID` |
| voucher `src_jti` | `DELEGATION_INVALID_VOUCHER` |
| envelope `message_id` | `INVALID_ENVELOPE` |
| delegation hop `jti` (outer or `chain[]`) | `DELEGATION_INVALID_SIGNATURE` |
| revocation `entries[].jti` | `REVOCATION_SNAPSHOT_INVALID` |

If you mint ids yourself, use `aitp_core::ids::random_v4()` or, for a
deterministic id, `aitp_core::ids::derived_v4(tag, input)`. That is
SHA-256 of `tag || 0x00 || input`, with the version and variant bits
set. `TctBuilder::jti(uuid)` and `TctBuilder::derived_jti(tag, input)`
set a TCT's `jti`. `build()` fails with `TctError::JtiNotV4` on a non-v4
id. `DelegationBuilder::jti(uuid)` fails the same way, with
`DelegationError::JtiNotV4`, a new variant. Domain tags are registered
in the spec's `registries/jti-domain-tags.md`. Register a production tag
there before you ship it.

## 5. TCT additions and deprecations

- `TctBuilder::ext(map)` sets the `ext` claim.
- Self-attestations: `TctBuilder::self_attestation()` mints
  `iss == sub == aud`, `grants == ["aitp.attestation"]`
  (`ATTESTATION_GRANT`), with the statement in `ext`.
  `verify_attestation(token, &AttestationVerifyContext::builder(issuer,
  statement_key, now)…build()?)` checks one and rejects an attestation
  whose `ext` lacks `statement_key`. In a grant context, a self-issued TCT and the marker grant
  are both rejected (`TCT_SIGNATURE_INVALID`).
- `TctVerifyContext::now` and `TctVerifyContext::permissive_at` are
  deprecated. They silently skip revocation and the Manifest expiry cap.
  Use `TctVerifyContext::builder(..)` and make both decisions explicitly.

## 6. Pinned-key admission (new, feature `pinned-admission`)

`aitp_handshake::admission` (also exposed as `aitp/pinned-admission`)
admits a pinned-key subject without a full Mutual Handshake:

```rust
let admission = PinnedAdmission::builder(verifier_aid, nonce_store, pinned_keys).build();
let challenge = admission.challenge(&ChallengeSource::ip(peer_ip)).await?;   // out of band
let env = present_pinned(&subject_signer, "label", &challenge, Timestamp::now())?; // subject
let admitted = admission.admit(&env, &ChallengeSource::ip(peer_ip)).await?;
// or, straight from the request body:
let admitted = admission.admit_wire(&body_json, &ChallengeSource::ip(peer_ip)).await?;
```

`admit` and `admit_wire` run the RFC-AITP-0002 §3.4 check order (spec
PR D, a2a24da; unchanged at the current pin db7d860):

1. `message_id` deny list ⇒ `REPLAY_DETECTED`. A replay costs no
   rate-limit slot.
2. Per-source presentation rate limit ⇒ HTTP 429, no AITP code.
3. Timestamp window ⇒ `TIMESTAMP_EXPIRED`.
4. Structure ⇒ `INVALID_ENVELOPE` / `UNKNOWN_FIELD`. The payload is
   exactly `{identity, pop_nonce}`.
5. Nonce length, 6. §3.2 steps 1–3 (type, key, trust store),
   8. the proof, 9. the atomic nonce consume ⇒ `IDENTITY_FAILED`;
   7. the envelope signature ⇒ `INVALID_SIGNATURE`.

An admitted `message_id` is then kept until its timestamp leaves the
tolerance window. `admit_wire` runs steps 1–3 on the raw JSON members
before parsing, so a replayed or over-limit request costs no schema
work. Prefer it at an HTTP edge.

- Challenges are 16-byte, single-use nonces, bound to the verifier,
  valid for at most 300 s. They are consumed atomically, and only after
  the presentation verifies.
- `NonceStore` is the persistence trait. `InMemoryNonceStore` is the
  bounded single-replica reference. It refuses at capacity and never
  evicts live nonces. Back the trait with Redis or DynamoDB for more
  than one replica. Expiry is amortised O(log n) per nonce, through a
  per-shard expiry heap, and a full sweep at capacity runs at most once
  per second. `NonceStoreError::AtCapacity` carries
  `retry_after: Option<Duration>` (the earliest outstanding expiry), and
  `ChallengeRefused::retry_after` passes it through. A third-party store
  sets it, or `None`.
- Rate limiting is always on. `ChallengeSource` must carry a transport
  identity (`ip` or `tls_client_cert`). An optional `with_label(aid)`
  adds a second limit and never replaces the transport key. The default
  `RecommendedLimiter` allows 30 per minute per source and 10 per minute
  per label (RFC-AITP-0009 §3.1). Replace it with `rate_limiter(..)`.
  `TokenBucketLimiter::check_key_at(key, Instant)` and
  `RecommendedLimiter::check_at(source, Instant)` take an injected
  clock.
- Feature `metrics` on `aitp-handshake` (enabled by
  `aitp-transport-http/metrics`) emits
  `aitp_admission_challenge_total{result}` (`issued`, `rate_limited`,
  `at_capacity`, `error`), `aitp_admission_admit_total{result}`
  (`admitted`, a lowercased wire code, or `local_error`) and the gauge
  `aitp_admission_nonces_outstanding`. The names are constants in
  `admission::metrics_names`.
- Either limit refuses with `CHALLENGE_REFUSED` (retryable; see
  `ErrorCode::is_retryable`) and never says which one fired.
  `RefusalCause` is for local metrics only.
- Presentations have their own limiter, separate from challenge
  issuance: `presentation_rate_limiter(..)`, default
  `RecommendedLimiter`. Over the limit, `admit` returns
  `AdmissionError::RateLimited { retry_after }`. Its `code()` is `None`,
  and `AdmissionError::http_status()` returns `Some(429)`. Answer with
  HTTP 429 and `Retry-After`, not with an AITP error body
  (RFC-AITP-0009 §3.1).
- The deny list is the `MessageIdDenyList` trait (`contains`, and an
  atomic `insert` that returns `Ok(false)` when the id is already live),
  set with `message_id_deny_list(..)`. `InMemoryMessageIdDenyList` is the
  bounded single-replica reference (100 000 live records by default). It
  refuses at capacity with `DenyListError::AtCapacity` and never
  evicts. Behind a load balancer, back the deny list and the nonce store
  with one shared service (Redis `SET NX EXAT`, for example).
- New `AdmissionError` variants: `Replay` (`REPLAY_DETECTED`),
  `RateLimited { retry_after }` and `DenyList(DenyListError)` (local,
  no code). The enum is `#[non_exhaustive]`.
- `IdentityPresentationPayload` has no `extensions` member, and an
  `extensions` key in the payload is `UNKNOWN_FIELD`. Envelope-level
  `extensions` are unchanged.
- The admit metric gains `result="rate_limited"` and
  `result="replay_detected"`.
- New `MessageType::IdentityPresentation` (`"identity_presentation"`).

## 7. `HandshakeServer` rate limiting is on and keyed on the transport

RFC-AITP-0009 §3.1 (spec #73) makes handshake rate limiting a single
MUST. The pre-auth source key must include a transport identifier, and
forwarding headers count only from a configured trusted proxy.

- Rate limiting is on by default at 30 per source and 10 per sender AID
  per 60 s. 0.13 had it off, and its `RateLimitConfig::default()` was
  120/60.
- `RateLimitConfig` changes shape:

  ```rust
  // 0.13
  RateLimitConfig { requests_per_ip_per_60s: Option<u32>, requests_per_aid_per_60s: Option<u32> }
  // 0.14
  RateLimitConfig {
      requests_per_source_per_60s: u32,        // always applies
      requests_per_aid_per_60s: Option<u32>,   // extra, never the only key
      trusted_proxies: Vec<TrustedProxy>,      // "10.0.0.0/8", "127.0.0.1", …
  }
  ```

- `X-Forwarded-For` and `X-Real-IP` are ignored unless the socket peer
  is in `trusted_proxies`. Behind a trusted proxy, the client is the
  rightmost untrusted `X-Forwarded-For` hop. **If you run behind a load
  balancer, add it to `trusted_proxies`.** Otherwise every client shares
  the balancer's bucket.
- The same rule is public as
  `aitp_transport_http::resolve_source_ip(peer, &headers, &trusted_proxies)`,
  for keying limits in another HTTP stack, such as
  `PinnedAdmission::challenge(&ChallengeSource::ip(..))`. It takes an
  `http` 1.x `HeaderMap`, and with `TrustedProxy` it sits behind
  feature `source-ip`, which depends only on `http`. `server` enables it,
  but you don't need `server` (or axum 0.8) to use it.
- A forwarding hop may carry a port (`1.2.3.4:5678`, as Azure
  Application Gateway writes) or brackets (`[2001:db8::1]:443`); the
  address is used. Any other unparsable hop, such as an RFC 7239
  obfuscated identifier, stops the walk at the last trusted hop, which
  throttles harder.
- Serve the router with
  `into_make_service_with_connect_info::<SocketAddr>()`. Without connect
  info there is no transport identifier, and all requests share one
  bucket.
- IPv6 sources are keyed by /64, and IPv4-mapped addresses are keyed
  as IPv4.
- `enforce_rate_limit` takes `Option<IpAddr>` instead of `Option<&str>`.
- `without_rate_limit()` turns the built-in limiter off. Use it only if
  a layer in front of the server enforces §3.1 by transport source.

## 8. Smaller changes

- New `ErrorCode::ChallengeRefused` and `ErrorCode::is_retryable()`.
- `AitpVerifyingKey::to_aid()` was added.
- The `aitp` CLI moves off the deprecated `permissive_at`, with the same
  behaviour.
- The conformance adapter accepts P-256 pinned keys and `pinned_keys`
  entry objects in a fixture `trust_store`.
- The conformance runner mints every negative placeholder (JWT, PoP,
  pinned-key proof) as a real artifact. A fixture that uses a placeholder
  the runner cannot mint now FAILs, naming the placeholder, instead of
  passing on the sentinel (spec #77).
- The conformance adapter adds `verify_identity_presentation`,
  `issue_presentation_challenge` and `verify_attestation` (extensions
  `aitp-pinned-admission` and `aitp-self-attestation`) and the test-only
  `begin_fixture`. A failed op may report `http_status` in place of
  `error_code`, and a fixture can expect it (`expected.http_status`). See
  [`conformance.md`](conformance.md).
