# 04 — Session Trust Bundle (RFC-AITP-0010)

> **Status: draft / opt-in.** Implemented in `aitp-session-bundle`, re-exported
> as `aitp::session_bundle` under the `experimental-session-bundle` feature
> (`experimental-bundle` in the language bindings). No wire-stability promise
> until the RFC is ratified.

## Motivation

AITP's core trust is **bilateral**: two agents exchange peer-issued TCTs during
a Mutual Handshake (see [03](03-handshake-transcripts.md)). A multi-agent
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
in v0.1):

```json
{
  "session_bundle": {
    "version": "aitp/0.1",
    "session_id": "550e8400-e29b-41d4-a716-446655440000",
    "coordinator": "aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik",
    "issued_at": 1700000000,
    "expires_at": 1700010000,
    "participants": [
      { "aid": "aid:pubkey:…A", "tct": { "tct": { /* coordinator→A TCT */ } } },
      { "aid": "aid:pubkey:…B", "tct": { "tct": { /* coordinator→B TCT */ } } }
    ],
    "signature": "<coordinator sig over JCS(bundle minus signature)>"
  }
}
```

| Field | Meaning |
|---|---|
| `version` | MUST be `"aitp/0.1"`. |
| `session_id` | UUIDv4, unique per session; a replay-binding scope. |
| `coordinator` | Coordinator AID. MUST equal the `issuer` of **every** embedded TCT. |
| `issued_at` | Bundle signing time. |
| `expires_at` | MUST equal `min(participants[*].tct.expires_at)` (§6) — the bundle is no more trustworthy than its shortest-lived member TCT. |
| `participants[]` | One `{aid, tct}` per member; `tct.audience` MUST equal `aid`. |
| `signature` | Coordinator's signature over the JCS canonicalization of the bundle minus `signature` (RFC-AITP-0001 §5.4.1). |

## Verification algorithm (`verify_session_bundle`)

The verifier supplies its own AID; checks run in this order, each mapping to a
`BUNDLE_*` / `SessionBundleError` variant:

1. `version == "aitp/0.1"` → else `VersionMismatch`.
2. `expires_at` in the future → else `Expired`.
3. `participants` non-empty → else `EmptyParticipants`.
4. `expires_at == min(participants[*].tct.expires_at)` → else `ExpiryWindowInvariant`.
5. The verifier's AID appears as some `participants[i].aid` → else `NotMember`.
6. Coordinator `signature` verifies over the canonical bundle → else `InvalidSignature`.
7. For every entry: `tct.issuer == coordinator` (`CoordinatorIssuerMismatch`) and
   `tct.audience == entry.aid` (`AudienceMismatch`).
8. Each embedded TCT verifies via `verify_tct` (`TctVerification`).

On success the verifier knows the roster and holds a verified TCT for every
peer — without any additional handshake.

## Known limitations

- **Coordinator is a single signer.** A compromised coordinator can attest a
  bogus roster, but cannot forge TCTs for agents it never issued to (each TCT
  is still independently verified). Participants who require mutual trust with a
  *specific* peer should still handshake directly.
- **No `extensions` slot in v0.1** — the schema is closed.
- Draft: gated behind a feature, excluded from the v0.1 conformance gate
  (fixtures `bundle-*` pass only under the opt-in feature).

## SDK example (Python coordinator → Node verifier)

```python
# Coordinator (Python): each participant already handshook with the
# coordinator, which issued them a TCT (audience = participant AID).
b = aitp.SessionBundleBuilder(coordinator_agent)   # experimental-bundle
b.participant(a_aid, a_tct_json)
b.participant(c_aid, c_tct_json)
bundle_json = b.build()        # expires_at auto-set to min(member expiries)
```

```js
// Participant (Node) verifies the bundle naming its own AID:
const outcome = verifySessionBundle(bundleJson, myAid);   // experimental-bundle
// throws on NotMember / ExpiryWindowInvariant / bad coordinator signature /
// any embedded TCT failing verification.
```

The cross-language `test_session_bundle_python_coordinator_node_verifier`
interop test exercises exactly this path.
