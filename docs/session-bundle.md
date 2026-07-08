# Session Trust Bundle (RFC-AITP-0010)

> **Status: draft / opt-in.** Implemented in `aitp-session-bundle`, re-exported
> as `aitp::session_bundle` under the `experimental-session-bundle` feature
> (`session-bundle` in the language bindings, enabled by default). No
> wire-stability promise until the RFC is ratified.

## Motivation

AITP's core trust is **bilateral**: two agents exchange peer-issued TCTs during
a Mutual Handshake (see [handshake transcripts](handshake-transcripts.md)). A multi-agent
*session* (e.g. an orchestrator coordinating several workers) would otherwise
require every pair to handshake — O(n²) exchanges.

The Session Trust Bundle lets a **coordinator** that has already handshaken
with each participant attest the session membership in a single signed
artifact. A participant verifies one bundle to learn the full roster and each
member's coordinator-issued TCT, instead of handshaking with everyone. The
coordinator is **not** a central trust authority: it only vouches for TCTs it
itself issued, and a participant still verifies every embedded TCT.

## Wire format (RFC-AITP-0010 §3)

Transport-wrapped as `{"session_bundle": { … }}` (`SessionBundleEnvelope`). The
inner `SessionTrustBundle` (`additionalProperties: false`, no `extensions` slot
yet). The bundle itself is a **JCS-profile** object (its outer `signature` is
computed over the JCS canonicalization minus `signature`), but each embedded
participant TCT is now an **opaque compact JWS string** (RFC-AITP-0001 §5.4.5)
— carried verbatim and covered by the outer signature as a plain string:

```json
{
  "session_bundle": {
    "version": "aitp/0.2",
    "session_id": "550e8400-e29b-41d4-a716-446655440000",
    "coordinator": "aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik",
    "issued_at": 1700000000,
    "expires_at": 1700010000,
    "participants": [
      { "aid": "aid:pubkey:…A", "tct": "<compact JWS string — coordinator→A TCT>" },
      { "aid": "aid:pubkey:…B", "tct": "<compact JWS string — coordinator→B TCT>" }
    ],
    "signature": "<coordinator sig over JCS(bundle minus signature)>"
  }
}
```

| Field | Meaning |
|---|---|
| `version` | MUST be `"aitp/0.2"`. |
| `session_id` | UUIDv4, unique per session; a replay-binding scope. |
| `coordinator` | Coordinator AID. MUST equal the `issuer` of **every** embedded TCT. |
| `issued_at` | Bundle signing time. |
| `expires_at` | MUST equal `min(participants[*].tct.exp)` (§6, decoded TCT claim) — the bundle is no more trustworthy than its shortest-lived member TCT. |
| `participants[]` | One `{aid, tct}` per member; the embedded TCT's decoded `aud` MUST equal `aid`. |
| `signature` | Coordinator's signature over the JCS canonicalization of the bundle minus `signature` (RFC-AITP-0001 §5.4.1). |

## Verification algorithm (`verify_session_bundle`)

The verifier supplies its own AID; checks run in this order, each mapping to a
`BUNDLE_*` / `SessionBundleError` variant:

1. `version == "aitp/0.2"` → else `VersionMismatch`.
2. `expires_at` in the future → else `Expired`.
3. `participants` non-empty → else `EmptyParticipants`.
4. `expires_at == min(participants[*].tct.exp)` (decoded claim) → else `ExpiryWindowInvariant`.
5. The verifier's AID appears as some `participants[i].aid` → else `NotMember`.
6. Coordinator `signature` verifies over the canonical bundle → else `InvalidSignature`.
7. For every entry, the embedded TCT compact JWS decodes and:
   `tct.iss == coordinator` (`CoordinatorIssuerMismatch`) and
   `tct.aud == entry.aid` (`AudienceMismatch`).
8. Each embedded TCT verifies via `verify_tct` — `typ == aitp-tct+jwt`,
   AID-pinned `alg`, signature over its transmitted bytes (`TctVerification`).

On success the verifier knows the roster and holds a verified TCT for every
peer — without any additional handshake.

## Known limitations

- **Coordinator is a single signer.** A compromised coordinator can attest a
  bogus roster, but cannot forge TCTs for agents it never issued to (each TCT
  is still independently verified). Participants who require mutual trust with a
  *specific* peer should still handshake directly.
- **No `extensions` slot** — the bundle schema is closed.
- Draft: gated behind a feature, excluded from the v0.2 conformance gate
  (fixtures `bundle-*` pass only under the opt-in feature).

## SDK example (Python coordinator → Node verifier)

```python
# Coordinator (Python): each participant already handshook with the
# coordinator, which issued them a TCT (aud == participant AID).
# a_tct / c_tct are the coordinator-issued TCT compact JWS strings.
b = aitp.SessionBundleBuilder(coordinator_agent)   # `session-bundle` feature
b.participant(a_aid, a_tct)
b.participant(c_aid, c_tct)
bundle_json = b.build()        # expires_at auto-set to min(member expiries)
```

```js
// Participant (Node) verifies the bundle naming its own AID:
const outcome = verifySessionBundle(bundleJson, myAid);   // `session-bundle` feature
// throws on NotMember / ExpiryWindowInvariant / bad coordinator signature /
// any embedded TCT failing verification.
```

The cross-language `test_session_bundle_python_coordinator_node_verifier`
interop test exercises exactly this path.
