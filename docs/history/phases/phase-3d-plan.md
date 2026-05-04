# Phase 3d — `aitp-handshake`

You are working on the `aitp-rs` Rust reference implementation. This is
Phase 3d of 6 — the most complex single phase.

**Your goal:** working Mutual Handshake state machines for both
Initiator and Responder, with both OIDC and pinned-key identity paths.
At the end of this phase, two in-process state machines should complete
a full 4-message handshake and each end up holding a TCT issued by the
other peer.

This phase is bigger than the others. Take your time. The bootstrap
verification order is a frequent source of subtle bugs in identity
protocols.

---

## Required reading

1. `phase-3c-report.md`
2. `crates/aitp-handshake/src/*.rs` — current scaffold
3. AITP spec RFCs:
   - RFC-AITP-0002 (identity)
   - RFC-AITP-0003 §5 (Manifest verification)
   - RFC-AITP-0004 (mutual handshake) — read in full, especially §3
     (message payloads), §4 (audience and grant rules), and §5
     (verification orders for each message)
4. The full text of RFC-AITP-0004 §5.1 (bootstrap verification order on
   receiving MUTUAL_HELLO). This is the most subtle part.

---

## The bootstrap verification order

When an agent receives a MUTUAL_HELLO from a peer it has never met
before, it does NOT yet have the peer's public key. The peer's public
key is encoded in their AID, which is in the envelope's `sender.agent_id`
AND in the inline Manifest. The order of operations to safely bootstrap
trust is:

```
1. Parse envelope unauthenticated. Don't trust anything yet.
2. Extract payload.manifest from the parsed envelope.
3. Confirm payload.manifest.aid == envelope.sender.agent_id.
   If they differ, reject — sender is lying about who issued the manifest.
4. Verify the manifest's PoP signature using the public key embedded in
   manifest.aid.
5. Verify the manifest's outer signature using the same key.
   At this point, we have proven the holder of manifest.aid's private
   key signed the manifest. The key is now trusted.
6. Verify payload.identity (the fresh identity proof) using the
   already-trusted manifest.aid's public key for cnf.jkt binding,
   and using OIDC issuer keys for OIDC JWT signature verification.
7. Verify the envelope's outer signature using manifest.aid's public key.
   The envelope's sender claim is now bound to a verified identity.
8. Process requested grants per RFC-AITP-0004 §4.
```

If any step fails, abort with the corresponding error code (see
`ErrorCode` in `aitp-core`).

The same pattern repeats for MUTUAL_HELLO_ACK on the initiator side.
After the first round, both peers have each other's manifest and key,
so MUTUAL_COMMIT and MUTUAL_COMMIT_ACK only need PoP signature
verification and TCT verification — no manifest re-verification.

---

## Decisions baked in

- `INSUFFICIENT_GRANTS` enforcement: after receiving a peer-issued TCT,
  the receiver MUST check that `tct.grants` includes every capability
  in its own `required_peer_capabilities`. If any required capability is
  missing, abort with `INSUFFICIENT_GRANTS`. (Per RFC-AITP-0004 — IMPL-031)
- Pinned-key identity proof transcript: per RFC-AITP-0002 §3.1. The
  spec may pin exact byte encoding; if not, use:
  ```
  b"aitp-pinned-key-v1\0" || sender_aid_bytes || b"\0" || receiver_aid_bytes
  || b"\0" || message_id_bytes || b"\0" || timestamp_be_8_bytes
  || b"\0" || pop_nonce_decoded_bytes
  ```
  Document your choice.

---

## Global rules

[All 12 apply.]

- **Stop at the phase boundary.** Do not begin Phase 4.

---

## Tasks

### 3d.1 — Verify payload types round-trip (IMPL-024)

The four payload types (`MutualHelloPayload`, `MutualHelloAckPayload`,
`MutualCommitPayload`, `MutualCommitAckPayload`) are scaffolded. Add
round-trip tests in `mod tests` of `payloads.rs`:

- Round-trip each of the four payload types
- Verify `extensions` is omitted from output when empty
- Reject unknown top-level fields

### 3d.2 — Implement `IdentityProof` parsing (IMPL-025)

`IdentityProof` is scaffolded as a tagged enum with `Oidc` and
`PinnedKey` variants. Verify both round-trip JSON correctly. Tests:

- Round-trip an OIDC proof
- Round-trip a pinned-key proof
- Reject `{"type": "x509", ...}` (unknown variant)

### 3d.3 — Implement OIDC verification (IMPL-029)

Create `crates/aitp-handshake/src/identity_oidc.rs`:

```rust
pub struct OidcVerifyContext<'a> {
    pub expected_audience: &'a Aid,        // the verifier's AID
    pub expected_nonce: &'a str,           // the pop_nonce sent
    pub trust_anchors: &'a [url::Url],     // accepted OIDC issuers
    pub jwks_resolver: &'a dyn JwksResolver,
    pub subject_aid: &'a Aid,              // for cnf.jkt check
}

pub trait JwksResolver {
    fn resolve(&self, issuer: &url::Url) -> Result<Vec<JwkPublicKey>, ResolveError>;
}

pub fn verify_oidc(
    proof: &OidcProof,
    ctx: &OidcVerifyContext<'_>,
) -> Result<(), HandshakeError> { ... }
```

Implementation:

1. Parse the JWT (`proof.proof` is the compact JWT string) using
   `jsonwebtoken::decode_header`.
2. Check the `iss` (issuer) claim is in `ctx.trust_anchors`. Else
   `IncompatibleTrustAnchors`.
3. Resolve JWKS for the issuer via `ctx.jwks_resolver`.
4. Verify the JWT signature with the matching JWK (matched by `kid`).
5. Validate claims:
   - `aud` equals `ctx.expected_audience.as_str()` (or contains it if
     audience is an array — pin the spec's exact form)
   - `nonce` equals `ctx.expected_nonce`
   - `cnf.jkt` equals `AitpVerifyingKey::from_aid(ctx.subject_aid)
     .to_jwk_thumbprint()`
   - `exp` is in the future
   - `iat` is recent (within the freshness window — say 5 minutes)
6. Map any failure to `HandshakeError::Identity(...)` with a meaningful
   message.

Use `jsonwebtoken` crate (already in workspace deps).

### 3d.4 — Implement pinned-key verification (IMPL-030)

In `identity.rs` or a new `identity_pinned.rs`:

```rust
pub struct PinnedKeyVerifyContext<'a> {
    pub sender_aid: &'a Aid,
    pub receiver_aid: &'a Aid,
    pub message_id: &'a Uuid,
    pub timestamp: &'a Timestamp,
    pub pop_nonce: &'a str,
}

pub fn verify_pinned_key(
    proof: &PinnedKeyProof,
    ctx: &PinnedKeyVerifyContext<'_>,
) -> Result<(), HandshakeError> { ... }
```

1. Decode `proof.public_key` (base64url) → 32 bytes
2. Confirm those 32 bytes match the public key encoded in
   `ctx.sender_aid` (else `Identity("public_key_aid_mismatch")`)
3. Construct the transcript bytes per the pinned format above
4. Verify `proof.proof` (base64url signature) over the transcript using
   the public key
5. Else `Identity("pinned_key_signature_invalid")`

### 3d.5 — Implement Initiator state machine (IMPL-026)

File: `crates/aitp-handshake/src/state_machine.rs`

Replace the placeholder `()` types with the real payload types. Define a
real state enum:

```rust
pub struct Initiator {
    state: InitiatorState,
}

enum InitiatorState {
    AwaitingHelloAck {
        session_id: Uuid,
        my_signing_key: AitpSigningKey,
        my_manifest: Manifest,
        my_pop_nonce: String,
        requested_grants: Vec<String>,
    },
    AwaitingCommitAck {
        session_id: Uuid,
        peer_aid: Aid,
        peer_pop_nonce: String,
        my_pop_nonce: String,
        peer_required_capabilities: Vec<String>,
        // ... whatever's needed
    },
    Done,
    Failed,
}
```

Implement:

- `Initiator::start(my_key, my_manifest, peer_manifest, requested_grants)
  -> (SessionId, MutualHelloPayload)`
- `on_hello_ack(ack: MutualHelloAckPayload, peer_envelope: &AitpEnvelope)
  -> Result<MutualCommitPayload, HandshakeError>` — runs the bootstrap
  verification order on the responder's manifest+identity, then issues
  a TCT for the responder, then signs the responder's pop_nonce
- `on_commit_ack(ack: MutualCommitAckPayload, peer_envelope:
  &AitpEnvelope) -> Result<Tct, HandshakeError>` — verifies the
  responder's PoP signature over our nonce, verifies the peer-issued
  TCT, runs INSUFFICIENT_GRANTS check, returns the TCT we now hold

### 3d.6 — Implement Responder state machine (IMPL-027)

Mirror image. States:

```rust
enum ResponderState {
    AwaitingCommit {
        session_id: Uuid,
        peer_aid: Aid,
        peer_pop_nonce: String,
        my_pop_nonce: String,
        // ...
    },
    Done,
    Failed,
}
```

- `Responder::on_hello(hello: MutualHelloPayload, hello_envelope:
  &AitpEnvelope, my_key, my_manifest) -> Result<(SessionId, Self,
  MutualHelloAckPayload), HandshakeError>` — bootstrap-verifies
  initiator, issues hello_ack
- `on_commit(commit: MutualCommitPayload, commit_envelope:
  &AitpEnvelope) -> Result<(MutualCommitAckPayload, Tct),
  HandshakeError>` — verifies initiator's PoP, verifies peer-issued TCT,
  INSUFFICIENT_GRANTS check, issues OUR TCT for the initiator, returns
  both the commit_ack to send AND the TCT we now hold

### 3d.7 — Bootstrap verification helper (IMPL-028)

The 8-step bootstrap verification appears in both Initiator and
Responder code. Factor it into a helper:

```rust
pub(crate) fn bootstrap_verify_peer(
    envelope: &AitpEnvelope,
    payload_manifest: &Manifest,
    payload_identity: &IdentityProof,
    my_aid: &Aid,
    my_pop_nonce: &str,
    trust_anchors: &[url::Url],
    jwks_resolver: &dyn JwksResolver,
) -> Result<AitpVerifyingKey, HandshakeError> { ... }
```

Returns the peer's verified verifying key for use in subsequent
operations. This helper is called once on receipt of HELLO (responder
side) or HELLO_ACK (initiator side).

### 3d.8 — INSUFFICIENT_GRANTS enforcement (IMPL-031)

After verifying a peer-issued TCT (in both `on_commit_ack` and
`on_commit`):

```rust
for required in &my_manifest.required_peer_capabilities {
    if !peer_issued_tct.grants.contains(required) {
        return Err(HandshakeError::InsufficientGrants);
    }
}
```

### 3d.9 — Test fixtures: mock OIDC issuer (Q-017)

Create `crates/aitp-handshake/tests/fixtures/mock_oidc.rs`:

A small in-process OIDC issuer that:
- Has a fixed Ed25519 keypair (or RS256 — pick one; ed25519-dalek for
  consistency, but standard OIDC providers usually use RS256, so
  `jsonwebtoken` with RS256 is more realistic)
- Mints JWTs with arbitrary claims, signed by its key
- Exposes its JWK Set as a `JwksResolver` impl

About 100-150 lines. Used by handshake integration tests.

### 3d.10 — Full handshake integration test

`crates/aitp-handshake/tests/full_handshake.rs`:

A test that:
1. Generates two keypairs (Alice and Bob)
2. Builds Manifests for each (using pinned_key identity for simplicity
   in this test)
3. Wraps both in envelopes
4. Runs Alice's `Initiator::start` to produce HELLO
5. Runs Bob's `Responder::on_hello` to produce HELLO_ACK
6. Runs Alice's `on_hello_ack` to produce COMMIT
7. Runs Bob's `on_commit` to produce COMMIT_ACK and Bob's held TCT
8. Runs Alice's `on_commit_ack` to produce Alice's held TCT
9. Asserts Alice holds a valid TCT issued by Bob (subject=Alice,
   audience=Alice, issuer=Bob)
10. Asserts Bob holds a valid TCT issued by Alice (subject=Bob,
    audience=Bob, issuer=Alice)

A second test using the OIDC mock issuer for OIDC identity path.

Failure-path tests:
- Tampered envelope signature → fails at appropriate step
- Tampered manifest signature → fails
- Wrong pop_nonce_echo → `NonceMismatch`
- Insufficient grants → `InsufficientGrants`

### 3d.11 — Document the wire transcripts

Write `docs/design/03-handshake-transcripts.md` showing:
- The exact JCS-canonical bytes of one happy-path 4-message exchange
- The bytes that get signed at each step

This becomes useful documentation for other-language implementations.

---

## Format, lint, tests

```sh
cargo fmt --all
cargo clippy -p aitp-handshake --all-targets -- -D warnings
cargo test -p aitp-handshake
cargo test -p aitp-handshake --test full_handshake
```

---

## Update PENDING.md

Check off IMPL-024 through IMPL-031.

---

## Phase report

`phase-3d-report.md`. Specifically note:
- The exact pinned-key transcript byte format you used
- Whether OIDC `aud` is verified as a string or array (the spec is
  ambiguous; pin your choice)
- Lines of code in the state machines (this phase's volume)
- Any subtle ordering issues you ran into in bootstrap verification

---

## Success gate

- Full handshake test runs end-to-end with both peers ending up holding
  valid TCTs
- All failure-path tests pass
- Clippy clean
- Report and PENDING updated

## Stop here.
