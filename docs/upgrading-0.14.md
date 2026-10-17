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

TCT `jti`, voucher `src_jti` and envelope `message_id` must be
lowercase, hyphenated UUID v4 (proposal Item 6b). The check runs on the
unverified token, before signature work. The rejection codes are:

| Field | Code |
|---|---|
| TCT `jti` | `TCT_SIGNATURE_INVALID` |
| voucher `src_jti` | `DELEGATION_INVALID_VOUCHER` |
| envelope `message_id` | `INVALID_ENVELOPE` |

If you mint ids yourself, use `aitp_core::ids::random_v4()` or, for a
deterministic id, `aitp_core::ids::derived_v4(tag, input)`. That is
SHA-256 of `tag || 0x00 || input`, with the version and variant bits
set. `TctBuilder::jti(uuid)` and `TctBuilder::derived_jti(tag, input)`
set a TCT's `jti`. `build()` fails with `TctError::JtiNotV4` on a non-v4
id.

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
let admitted = admission.admit(&env).await?;
```

- Challenges are 16-byte, single-use nonces, bound to the verifier,
  valid for at most 300 s. They are consumed atomically, and only after
  the presentation verifies.
- `NonceStore` is the persistence trait. `InMemoryNonceStore` is the
  bounded single-replica reference. It refuses at capacity and never
  evicts live nonces. Back the trait with Redis or DynamoDB for more
  than one replica.
- Rate limiting is always on. `ChallengeSource` must carry a transport
  identity (`ip` or `tls_client_cert`). An optional `with_label(aid)`
  adds a second limit and never replaces the transport key. The default
  `RecommendedLimiter` allows 30 per minute per source and 10 per minute
  per label (RFC-AITP-0009 §3.1). Replace it with `rate_limiter(..)`.
- Either limit refuses with `CHALLENGE_REFUSED` (retryable; see
  `ErrorCode::is_retryable`) and never says which one fired.
  `RefusalCause` is for local metrics only.
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
