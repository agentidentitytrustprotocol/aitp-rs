# Key management

**Audience:** operators and framework authors handling AITP signing keys.
**Scope:** what the secret actually is, how `aitp-rs` treats it in memory,
where to store it, and what rotation means. Pairs with
[`deployment.md`](deployment.md).

## What the secret is

An agent's identity is a signing keypair. `aitp-rs` supports two suites
(RFC-AITP-0001 §5.4.3): **Ed25519** and **ECDSA P-256**. Construct a key
either freshly or from a stored seed:

```rust
use aitp::crypto::AitpSigningKey;

// Fresh, from the OS CSPRNG:
let key = AitpSigningKey::generate_ed25519();          // Ed25519 (default suite)
let key = AitpSigningKey::generate_p256();     // P-256

// Restored from a stored 32-byte seed:
let key = AitpSigningKey::from_ed25519_seed(&seed);              // Ed25519
let key = AitpSigningKey::from_p256_seed(&seed)?;        // P-256 (validates the scalar)
```

**The 32-byte seed is the whole secret.** Anyone with it can impersonate
the agent. Treat it exactly like a raw private key: never log it, never
commit it, never send it over the wire. The public key — and therefore
the agent's AID — is derived from it.

> **The AID is the public key.** `aid:pubkey:<...>` encodes the public
> key directly. This is what makes rotation a first-class concern
> (below): change the key and you change the identity.

## In-memory hygiene (what the library does for you)

- **Zeroize on drop.** `AitpSigningKey` wraps `ed25519-dalek` /
  `p256` signing keys, both of which zero their secret scalar when
  dropped, so the material is wiped when the key value goes out of scope.
- **Redacted `Debug`.** Formatting an `AitpSigningKey` prints only its
  algorithm and AID (both public) — never the secret — so an accidental
  `{:?}` in a log line can't leak it.
- RFC-AITP-0009 §3 also requires you never log **raw tokens or PoP
  nonces**; those are bearer-ish material during their window.

What the library does **not** do: it does not encrypt the seed at rest,
manage a keystore, or hold keys outside your process. Those are your
call — see below.

## Where to keep the seed

The signing key lives **in your process's memory** while the agent runs
(there is no external-signer indirection — see the next section). So the
lifecycle is: keep the seed somewhere protected at rest, load it at
startup, construct the `AitpSigningKey`, and let it drop (zeroizing) at
shutdown.

[RFC-AITP-0009 §3](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0009-security.md#3-implementation-security-requirements)
says implementations **MUST** store private keys in secure storage (HSM,
OS keychain, or equivalent). `aitp-rs` leaves storage to you, so meeting
that requirement is your job. Reasonable homes for the seed, roughly in
order of preference:

1. **A secrets manager / KMS** (AWS Secrets Manager, GCP Secret Manager,
   Vault, k8s Secrets with encryption-at-rest). Fetch at startup,
   construct the key, drop the fetched bytes.
2. **KMS envelope encryption**: store the seed encrypted under a KMS key,
   decrypt at startup. The KMS key never leaves the HSM; the *seed* still
   ends up in your process memory to sign with.
3. **An injected file / mounted secret** with tight file permissions
   (e.g. a `tmpfs`-mounted k8s secret), read once at startup.
4. **An environment variable** — local/dev only. It leaks via `/proc`,
   crash dumps and child processes, and is not "secure storage" in the
   RFC-AITP-0009 §3 sense.

Never bake a seed into a container image or a source file. The demo's
seeds are hard-coded precisely because they are throwaway demo identities.

## HSM / KMS-resident keys (0.14+)

Since 0.14 the private key does not have to exist in application memory.
Every signing API (`ManifestBuilder`, `TctBuilder`, the handshake's
`PeerConfig`, envelopes, revocation snapshots, delegation, session
bundles, `jws::sign_compact`) takes `&dyn AitpSigner`. `AitpSigningKey`
is one implementation. A cloud KMS, an HSM or a remote signing service
is another, written in a few lines on top of the SDK you already use.
`aitp-rs` depends on no cloud SDK.

### What the backend does, and what the library does

A backend implements `AitpSigner` (blocking) or `AsyncAitpSigner` (async;
every cloud SDK). It signs exactly the bytes in the `SignRequest` and
returns what the service produced. Everything protocol-critical stays in
the library, so a backend cannot get it wrong:

| Step | Who | Detail |
|---|---|---|
| What to sign | library | Ed25519 gets the message (`SignRequest::Ed25519Message`). P-256 gets the 32-byte digest (`SignRequest::P256Digest`), already hashed: RFC-AITP-0001 §5.4.6 single hash. |
| Size limit | library | A request over `max_message_len()` fails with `SignerError::MessageTooLarge` **before** the backend is called. |
| DER → `R‖S` | library | Return `BackendSignature::Der(bytes)` as the KMS gave it. |
| Low-S | library | P-256 is normalised to low-S (§5.4.7) whatever the backend returned. |
| Verify before emit | library | The result is verified, strictly, against the key in the signer's AID. A wrong key, truncation or corruption is `SignerError::VerificationFailed`, never a bad token on the wire. |
| Randomized nonces | either | Accepted. §5.4.7 constrains the encoding, not the nonce. |
| Retries | **caller** | `SignerError::is_transient()` / `retry_after()`. The library never retries. |

### Mapping to common backends

| Backend | Ed25519 | P-256 | Limit |
|---|---|---|---|
| AWS KMS `Sign` | `ED25519_SHA_512`, `MessageType=RAW` | `ECDSA_SHA_256`, `MessageType=DIGEST` | `RAW` ≤ 4096 bytes |
| GCP Cloud KMS `asymmetricSign` | `EC_SIGN_ED25519`, `data` | `EC_SIGN_P256_SHA256`, `digest.sha256` | 64 KiB `data` |
| Azure Key Vault `sign` | (no Ed25519) | `ES256` over the digest; returns raw `R‖S` | n/a |
| PKCS#11 | `CKM_EDDSA` | `CKM_ECDSA` (**not** `CKM_ECDSA_SHA256`) | token-specific |

Ed25519 must be **pure** EdDSA over the exact message bytes. Never use
AWS `ED25519_PH_SHA_512` (HashEdDSA): AWS pre-hashes again even with
`MessageType=DIGEST`, and the output does not verify as Ed25519. The
library catches this as `VerificationFailed`.

Ed25519 output is deterministic. P-256 output from a KMS is not: AWS
draws a fresh nonce per call. If you need byte-identical re-signing on a
retry, for example an idempotent TCT seal, keep that key on Ed25519.

The P-256 digest must go to the backend's *digest* mode. A "hash this
message for me" mode reintroduces the 0.13.x double hash. The library's
verify-before-emit catches that as `VerificationFailed`, at the first
signature.

### AWS KMS sketch (P-256)

```rust
use aitp::crypto::{AitpVerifyingKey, AsyncAitpSigner, BackendSignature, SignRequest, SignerError};
use aitp::core::Aid;

struct KmsSigner { client: aws_sdk_kms::Client, key_id: String, aid: Aid }

impl AsyncAitpSigner for KmsSigner {
    fn aid(&self) -> &Aid { &self.aid }
    fn max_message_len(&self) -> Option<usize> { Some(4096) }

    async fn public_key(&self) -> Result<AitpVerifyingKey, SignerError> {
        let out = self.client.get_public_key().key_id(&self.key_id).send().await
            .map_err(classify)?;
        // `out.public_key` is a DER SubjectPublicKeyInfo; take the
        // 65-byte SEC1 point from its tail and parse it.
        let spki = out.public_key().unwrap().as_ref();
        let point = &spki[spki.len() - 65..];
        AitpVerifyingKey::from_p256_affine(
            point[1..33].try_into().unwrap(),
            point[33..].try_into().unwrap(),
        )
        .map_err(|e| SignerError::permanent(e.to_string()))
    }

    async fn sign(&self, req: SignRequest<'_>) -> Result<BackendSignature, SignerError> {
        let SignRequest::P256Digest(d) = req else {
            return Err(SignerError::UnsupportedAlgorithm("P-256 key".into()));
        };
        let out = self.client.sign()
            .key_id(&self.key_id)
            .message(aws_sdk_kms::primitives::Blob::new(d.as_bytes().to_vec()))
            .message_type(aws_sdk_kms::types::MessageType::Digest)
            .signing_algorithm(aws_sdk_kms::types::SigningAlgorithmSpec::EcdsaSha256)
            .send().await
            .map_err(classify)?;
        Ok(BackendSignature::Der(out.signature().unwrap().as_ref().to_vec()))
    }
}

/// ThrottlingException, KMSInternalException, timeouts → transient;
/// AccessDenied, DisabledException, KMSInvalidStateException → permanent.
fn classify<E: std::error::Error + Send + Sync + 'static>(e: E) -> SignerError { /* ... */ }
```

Wire it up once at startup, and fail the boot if the key ID points at
the wrong key:

```rust
let kms: Arc<dyn DynAsyncAitpSigner> = Arc::new(KmsSigner { /* ... */ });
aitp::crypto::check_public_key_async(kms.as_ref()).await?; // SignerError::KeyMismatch
let tct = TctBuilder::new_async(&*kms) /* ... */ .build_async().await?;
```

For a blocking HSM client implement `AitpSigner` instead. To use a
blocking signer where an async one is expected, wrap it in
`BlockingSigner(signer)`.

### Testing a backend

The `aitp` `test-util` feature exposes `aitp::crypto::testing::MockKmsSigner`. It
returns DER, high-S or randomized-nonce output, signs with the wrong key,
reports the wrong public key, or fails transiently with `retry_after`. Its
`calls()` counter lets a test prove that a request was refused before the
backend saw it. Use it to test your error handling without a cloud
account.

### Still in memory

The handshake's session secrets and the TCT cache stay in process memory.
Only the long-term identity key moves to the backend.

## Rotation

The normative rules — the Manifest rotation schedule
([RFC-AITP-0003 §8](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0003-manifest.md#8-manifest-rotation)),
the emergency steps on key compromise (§8.1), and the 90-day key-rotation
SHOULD (RFC-AITP-0009 §3) — are summarised in the spec's
[Manifest and key rotation](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/docs/operational-guidance.md#manifest-and-key-rotation)
guide. What follows is the `aitp-rs` runbook.

Because the AID is derived from the public key, **rotating the signing
key produces a new AID** (RFC-AITP-0003 §8.1). There is no in-band
cryptographic link from the old AID to the new one in v0.3 — peers learn
the new AID out of band, and every pinned reference, trust-anchor entry,
and outstanding TCT `iss` that named the old AID must be updated. Plan
rotation as an identity change, not a transparent key swap:

- **Routine rotation.** Generate a new key (`AitpSigningKey::generate` /
  `generate_p256`), build and publish a Manifest under the new AID,
  distribute the new AID to peers / your registry, then retire the old
  one once no outstanding TCTs reference it (TCT lifetimes are short by
  design, so the drain window is small).
- **Emergency rotation (suspected compromise).** RFC-AITP-0003 §8.1 makes
  these steps MUST:
  1. Generate a new key and publish a Manifest under the new AID.
  2. Revoke every TCT issued **by** the old AID, by publishing a signed
     revocation snapshot covering all known `jti`s
     ([RFC-AITP-0008 §1.5](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0008-revocation.md#15-signed-revocation-response)).
     With `aitp::transport`, that is what a `RevocationListProducer`
     attached via `HandshakeServer::with_revocation_producer` serves.
     Without one, the server serves an empty signed snapshot, which
     revokes nothing.
  3. Notify known peers of the new AID out of band.

  If the compromised host can still publish, first set a short
  `expires_at` on the old Manifest (e.g. `now + 300`) so cached copies
  expire quickly. There is no AID-level revocation in v0.3 (RFC-AITP-0003
  §8.1, last paragraph): trust in the old AID ends when its Manifest
  expires and its TCTs are revoked.

> **Not in v0.3:** key-rotation *continuity* — a signed statement by which
> the old key vouches for its successor, or a dual-key overlap window. No
> AITP RFC specifies it yet. Until one does, treat every rotation as a
> fresh trust bootstrap.

## Checklist

- [ ] Seed stored in a secrets manager / KMS, not in the image or source
      (RFC-AITP-0009 §3 secure-storage MUST), or the key is KMS/HSM-resident
      behind an `AitpSigner` (0.14+).
- [ ] KMS/HSM signers: `check_public_key` / `check_public_key_async` runs at
      startup, and transient `SignerError`s are retried with backoff.
- [ ] Seed loaded at startup and the fetched bytes dropped promptly.
- [ ] No key material, raw TCTs, or PoP nonces in logs.
- [ ] A rotation runbook that treats a new key as a new AID (update
      pinned refs / trust anchors / registry entries).
- [ ] Keys rotated on a schedule (RFC-AITP-0009 §3 recommends 90 days).
- [ ] For suspected compromise: shorten the old Manifest's expiry, publish
      under a new AID, revoke every TCT the old AID issued via a signed
      revocation snapshot, and notify peers out of band.
