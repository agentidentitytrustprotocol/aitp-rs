# Session Trust Bundle (RFC-AITP-0010)

> **Status: Draft, opt-in.**
> [RFC-AITP-0010](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0010-session-trust-bundle.md)
> is a Community Standards Track (Draft) RFC outside v0.2 core conformance.
> Implemented in `aitp-session-bundle`, re-exported as `aitp::session_bundle`
> under the facade's `experimental-session-bundle` feature (the language
> bindings use their own `session-bundle` feature, on by default). No
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

## Wire format

The schema, field table and signing input are defined in
[RFC-AITP-0010 §3](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0010-session-trust-bundle.md#3-schema)
and §4.2. In short: a JCS-profile object whose `signature` member sits
**inside** the signed body, carried on the wire inside a
`{"session_bundle": …}` transport wrapper; each participant `tct` is an
opaque compact JWS string covered verbatim by the coordinator's signature.

How `aitp-rs` maps it:

| Spec concept | `aitp-rs` |
|---|---|
| Inner signed body | `SessionTrustBundle` (`crates/aitp-session-bundle/src/types.rs`). `extensions` is `Option<ExtensionsMap>`, so absent and `{}` stay distinct in the signing input. |
| Transport wrapper | `SessionBundleEnvelope` |
| Wire parsing | `parse_session_bundle_wire` (`src/wire.rs`): a sibling member beside the wrapper (the pre-erratum `signature` placement) → `WireFormInvalid` (`SESSION_BUNDLE_INVALID`); an unknown body member outside `extensions` → `UnknownField` (`UNKNOWN_FIELD`). Both run before any crypto. |
| Issuance (§4.2) | `SessionBundleBuilder` (`src/builder.rs`) — sets `expires_at = min(participants[*].tct.exp)` and signs `sha256(JCS(body minus signature))`. |
| Coordinator advertisement (§4.3.1) | the `RFC_AITP_0010_BUNDLE_URI` constant (`"rfc-aitp-0010.bundle_uri"`, `src/lib.rs`) — see *Known limitations*. |
| HTTP binding (§4.3.1) | `SessionBundleServer` (`crates/aitp-transport-http/src/session_bundle_server.rs`), behind `aitp-transport-http/experimental-session-bundle`. Stores and serves bundles verbatim; it does **no** trust verification. |

## Verification (`verify_session_bundle`)

The normative order is
[RFC-AITP-0010 §5](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0010-session-trust-bundle.md#5-verification):
member-set check first, then (1) version, (2) expiry, (3) expiry-window
invariant, (4) participants non-empty, (5) fetch and verify the coordinator's
Manifest, (6) bundle signature, (7) per-participant TCT verification,
(8) self-membership.

What `aitp-rs` actually runs (`crates/aitp-session-bundle/src/verifier.rs:63-178`),
with the adapter's error code for each (`bundle_error_code` in
`crates/aitp-rs-adapter/src/lib.rs`):

0. Member-set and wrapper-shape checks, in `parse_session_bundle_wire`
   (before the verifier is called) → `UNKNOWN_FIELD` / `SESSION_BUNDLE_INVALID`.
1. `version == "aitp/0.2"` → `VersionMismatch` (`BUNDLE_VERSION_MISMATCH`).
2. `expires_at` not in the past → `Expired` (`BUNDLE_EXPIRED`).
3. `participants` non-empty → `EmptyParticipants` (`BUNDLE_EMPTY_PARTICIPANTS`).
4. `expires_at == min(participants[*].tct.exp)`, read from the still-unverified
   payloads → `ExpiryWindowInvariant` (`BUNDLE_EXPIRY_WINDOW_INVARIANT`).
5. The verifier's AID appears in `participants[*].aid` → `NotMember` (`BUNDLE_NOT_MEMBER`).
6. Coordinator signature, with the key **derived from the coordinator AID**
   (no Manifest fetch) → `InvalidSignature` (`BUNDLE_INVALID_SIGNATURE`).
7. For each entry, `verify_tct` with issuer pinned to `coordinator` and
   audience pinned to `entry.aid`: `CoordinatorIssuerMismatch`,
   `AudienceMismatch`, or any other TCT failure → `TctVerification`
   (`BUNDLE_PARTICIPANT_TCT_INVALID`).
8. Per-pair revocation (§7): if `revocation_check` reports an entry's `jti`
   revoked, that participant is **dropped**, not failed.

The order differs from §5 — see *Known limitations*.

On success the result is a `BundleOutcome`: `Clear { active_aids }` when no
participant was revoked, or `DegradedSubset { active_aids, dropped_aids }`
when some were. A revoked participant (including the verifier itself) appears
in `dropped_aids` rather than failing the call; the caller decides policy.
Every AID in `active_aids` had its TCT signature, claims and expiry
verified; revocation is applied separately afterwards, and the Manifest
grant cap is not applied to participant TCTs (`verifier.rs:138,143`).

## Known limitations

- **Coordinator is a single signer.** A compromised coordinator can attest a
  bogus roster, but cannot forge TCTs for agents it never issued to (each TCT
  is still independently verified). Pairs that need direct peer binding must
  still handshake (RFC-AITP-0010 §2).
- **The HTTP endpoint accepts a bare body**
  ([#195](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/195)).
  `POST /aitp/session/bundle` passes the request to `parse_session_bundle_wire`
  (`session_bundle_server.rs:141`), whose no-wrapper branch accepts a bare
  inner body (`crates/aitp-session-bundle/src/wire.rs:77-88`); the server then
  stores it wrapped. RFC-AITP-0010 §4.3.1 at spec `main` says the request
  body MUST be the wrapped envelope and a bare body MUST be rejected. That
  sentence came in an erratum after the spec revision `aitp-rs` pins, and
  §4.3.1 is titled "non-normative for Draft", so this is a divergence from
  the spec's stated requirement rather than a conformance failure.
- **`bundle_uri` is not advertised for you** (#195). §4.3.1 says a coordinator
  serving bundles over HTTPS MUST advertise the concrete URL in its Manifest
  under `extensions["rfc-aitp-0010.bundle_uri"]`. Nothing in the crates adds
  it; set it yourself with the Manifest builder's `extension(...)` using the
  `RFC_AITP_0010_BUNDLE_URI` constant. No client in `aitp-rs` reads it either.
- **Check order differs from RFC-AITP-0010 §5**
  ([#197](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/197),
  `verifier.rs:67-123`): non-empty runs before the expiry-window invariant;
  self-membership runs before the signature instead of last; and there is no
  step 5 — the coordinator key is taken from its `aid:pubkey` AID with no
  Manifest fetch or verification, so the coordinator's Manifest expiry and
  rotation state are not consulted. A forged bundle that omits the verifier
  therefore reports `BUNDLE_NOT_MEMBER` rather than `BUNDLE_INVALID_SIGNATURE`.
- **No `session_id` replay tracking.** RFC-AITP-0010 §10 says consumers MUST
  reject a bundle whose `session_id` they already accepted with a different
  signature. `verify_session_bundle` is stateless
  (`crates/aitp-session-bundle/src/verifier.rs:63-178`); track accepted
  `session_id`s in your code.
- **The bundle server is an in-memory reference.** `SessionBundleServer` is
  process-local, unbounded, overwrites on a repeated `session_id`, and
  performs no verification
  (`crates/aitp-transport-http/src/session_bundle_server.rs:42,162`).
- **Draft, opt-in.** Outside the v0.2 conformance gate; the `bundle-*`
  fixtures run only with `--feature experimental-session-bundle`. Pass/skip
  status: [conformance.md](conformance.md#v02-conformance-matrix).

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
// outcome = { kind: "clear" | "degraded", activeAids, droppedAids }
// Throws on NotMember / ExpiryWindowInvariant / bad coordinator signature /
// any embedded TCT failing verification.
```

The cross-language `test_session_bundle_python_coordinator_node_verifier`
interop test (`bindings/interop/test_interop.py`) exercises exactly this path.
