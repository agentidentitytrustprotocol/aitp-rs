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
use aitp_crypto::AitpSigningKey;

// Fresh, from the OS CSPRNG:
let key = AitpSigningKey::generate();          // Ed25519 (default suite)
let key = AitpSigningKey::generate_p256();     // P-256

// Restored from a stored 32-byte seed:
let key = AitpSigningKey::from_seed(&seed);              // Ed25519
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

Reasonable homes for the seed, roughly in order of preference:

1. **A secrets manager / KMS** (AWS Secrets Manager, GCP Secret Manager,
   Vault, k8s Secrets with encryption-at-rest). Fetch at startup,
   construct the key, drop the fetched bytes.
2. **KMS envelope encryption**: store the seed encrypted under a KMS key,
   decrypt at startup. The KMS key never leaves the HSM; the *seed* still
   ends up in your process memory to sign with.
3. **An injected file / mounted secret** with tight file permissions
   (e.g. a `tmpfs`-mounted k8s secret), read once at startup.
4. **An environment variable** — acceptable for local/dev, weakest for
   production (leaks via `/proc`, crash dumps, child processes).

Never bake a seed into a container image or a source file. The demo's
seeds are hard-coded precisely because they are throwaway demo identities.

## HSM / KMS: the honest limitation

`aitp-rs` signs **in-process**: `AitpSigningKey::sign` operates on the raw
key held in memory. There is **no external-signer / PKCS#11 / cloud-KMS
signing seam today** — you cannot keep the private key resident in an HSM
and have the library call out to it per signature.

The practical consequence: a KMS/HSM can protect the seed *at rest* (store
it encrypted, decrypt at startup — options 1–2 above), but the signing key
is still materialized in application memory to produce signatures. If your
threat model requires the private key to never exist in application memory
(true HSM-resident signing), `aitp-rs` does not support that yet; it would
require an external-signer abstraction over `AitpSigningKey`. That is
noted as possible future work in the runtime review
([`../plans/protocol-runtime-review-2026-07.md`](../plans/protocol-runtime-review-2026-07.md)).

## Rotation

Because the AID is derived from the public key, **rotating the signing
key produces a new AID** (RFC-AITP-0003 §8.1). There is no in-band
cryptographic link from the old AID to the new one in the current
protocol — peers learn the new AID out of band, and every pinned
reference, trust-anchor entry, and outstanding TCT `iss` that named the
old AID must be updated. Plan rotation as an identity change, not a
transparent key swap:

- **Routine rotation.** Publish a fresh Manifest under the new AID,
  distribute the new AID to peers / your registry, then retire the old
  one once no outstanding TCTs reference it (TCT lifetimes are short by
  design, so the drain window is small).
- **Emergency rotation (suspected compromise).** Per RFC-AITP-0003 §8.1:
  set the compromised agent's Manifest `expires_at` to a near-future
  time so cached copies stop being honored, revoke outstanding TCTs
  issued to/for the affected subject (RFC-AITP-0008), and stand up the
  new AID. Note the current limitation: there is no AID-level revocation
  in v0.2 (§8.2) — a fully compromised host that can still publish is
  bounded only by Manifest expiry.

> **Coming:** key-rotation *continuity* — a signed rotation statement so
> the old key can vouch for its successor, plus a dual-key overlap
> window — is the single largest protocol gap the runtime review calls
> out (§4.1) and is planned as a new RFC. Until it lands, treat every
> rotation as a fresh trust bootstrap.

## Checklist

- [ ] Seed stored in a secrets manager / KMS, not in the image or source.
- [ ] Seed loaded at startup and the fetched bytes dropped promptly.
- [ ] No key material, raw TCTs, or PoP nonces in logs.
- [ ] A rotation runbook that treats a new key as a new AID (update
      pinned refs / trust anchors / registry entries).
- [ ] For suspected compromise: shorten Manifest expiry + revoke
      outstanding TCTs + provision a new AID.
