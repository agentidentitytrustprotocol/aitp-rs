# Phase 3d Report — `aitp-handshake`

## Tasks completed

- IMPL-024 (payload type round-trips, no-extensions per schema)
- IMPL-025 (`IdentityDescriptor` parsing — flat struct mirroring the schema)
- IMPL-026 (`Initiator` state machine: start, on_hello_ack, on_commit_ack)
- IMPL-027 (`Responder` state machine: on_hello, on_commit)
- IMPL-028 (`bootstrap_verify_peer` factored helper)
- IMPL-029 (`verify_oidc` with pluggable `JwksResolver` trait)
- IMPL-030 (`verify_pinned_key` per RFC-AITP-0002 §3.1)
- IMPL-031 (INSUFFICIENT_GRANTS enforcement)

## Test counts

| Suite | Count |
|---|---|
| `aitp-handshake` unit tests | 10 |
| `tests/full_handshake.rs` | 4 |

All 14 tests pass. The full pinned-key handshake completes end-to-end with
both peers ending up holding the other's TCT.

## Spec deviations corrected from the original scaffold

| Symbol | Before | After | Source of truth |
|---|---|---|---|
| `IdentityProof` (tagged enum) | `enum {Oidc(OidcProof), PinnedKey(PinnedKeyProof)}` | `IdentityDescriptor { kind, issuer?, subject, proof, public_key? }` (flat) | `schemas/json/aitp-identity.schema.json` |
| `MutualCommit*` payloads | flat `tct` field | `tct_for_peer: TctEnvelope { tct }` | `schemas/json/aitp-mutual-handshake.schema.json` |
| All four payloads | `extensions` slot | removed | All four are `additionalProperties: false` |

## Decisions in this phase

1. **Bootstrap verification helper** is `pub` so the HTTP transport can
   reuse it on the server side (it returns the peer's verifying key,
   which the server needs to verify the envelope's outer signature).
2. **`PresentedIdentity` enum** ergonomically distinguishes pinned-key
   (we self-sign) from OIDC (caller hands us a JWT). The wire form is a
   single `IdentityDescriptor` either way.
3. **Round-2 PoP signing input** is `sha256(peer_nonce.as_bytes())`
   matching the same convention chosen for downstream PoP in Phase 3b.
4. **OIDC `aud` claim** is enforced as `==` against
   `cfg.manifest.aid.as_str()`. The schema doesn't allow array audiences,
   so this is the only sane interpretation (RFC-AITP-0002 §2.2).
5. **OIDC `cnf.jkt`** is computed from the AID's pubkey via
   `AitpVerifyingKey::from_aid(...).to_jwk_thumbprint()`. The
   thumbprint format is pinned in `aitp-crypto::thumbprint` per
   RFC-AITP-0002 §2.2.1.
6. **Grant intersection** at issuance is `peer_requested ∩ self_offered`.
   Identity-policy filtering (point 1 in RFC-AITP-0004 §4.1) is
   deferred to a deployment hook because v0.1 doesn't define an
   identity-policy plugin point.
7. **State machines do not own envelopes.** Callers pass parsed
   `&AitpEnvelope` plus parsed payloads. This keeps the handshake crate
   transport-agnostic.
8. **Self-issued envelope signing is not wired into the handshake
   crate.** The integration test signs envelopes manually using
   `aitp_core::envelope_signing_digest`. The HTTP transport layer
   (Phase 4a) will provide the convenience wrapper.

## Things the human reviewer should look at

1. `bootstrap_verify_peer` runs steps 3–6 of RFC-AITP-0004 §5.1. Step 7
   (envelope signature) and step 1–2 (replay protection) are the
   transport's responsibility — the handshake crate trusts that the
   caller has already done those checks. The HTTP server in Phase 4a
   does step 7; replay protection is deferred to deployment.
2. The `OidcVerifyContext.iat_tolerance_secs` default is 300s. This
   matches RFC-AITP-0001 §5.5's general timestamp tolerance but is not
   pinned in RFC-AITP-0002. Worth confirming with spec authors.
3. The `policy_violation` mapping. When grant intersection is empty we
   return `PolicyViolation`; spec says the responder MAY refuse, so the
   handshake aborts cleanly.
4. The test for `insufficient_grants_aborts` — Alice rebuilds her
   manifest to include `required_peer_capabilities = ["super.power"]`,
   then Bob (who does not offer it) drives to a successful exchange
   from Bob's side; Alice rejects when she finalizes because Bob's TCT
   for her doesn't include the required cap. This matches §5.4 step 5.
