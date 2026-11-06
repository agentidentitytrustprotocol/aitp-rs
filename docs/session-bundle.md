# Session Trust Bundle (RFC-AITP-0010)

> **Status: Draft, opt-in.**
> [RFC-AITP-0010](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0010-session-trust-bundle.md)
> is a Community Standards Track (Draft) RFC outside v0.3 core conformance.
> Implemented in the `aitp-experimental` crate as
> `aitp_experimental::session_bundle` (the language bindings: their
> `experimental-session-bundle` feature, off by default and absent from the
> published packages). Neither the API nor the wire
> form carries a stability promise until the RFC is ratified.

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
| Inner signed body | `SessionTrustBundle` (`crates/aitp-experimental/src/session_bundle/types.rs`). `extensions` is `Option<ExtensionsMap>`, so absent and `{}` stay distinct in the signing input. |
| Transport wrapper | `SessionBundleEnvelope` |
| Wire parsing | `parse_session_bundle_wire` (`src/wire.rs`) accepts the wrapped envelope or, for library callers, a bare inner body; `parse_session_bundle_envelope` requires the wrapper. A sibling member beside the wrapper (the pre-erratum `signature` placement) → `WireFormInvalid` (`SESSION_BUNDLE_INVALID`); an unknown body member outside `extensions` → `UnknownField` (`UNKNOWN_FIELD`). Both run before any crypto. |
| Issuance (§4.2) | `SessionBundleBuilder` (`src/builder.rs`) — sets `expires_at = min(participants[*].tct.exp)` and signs `sha256(JCS(body minus signature))`. |
| Coordinator advertisement (§4.3.1) | `advertise_bundle_uri(manifest_builder, &url)` sets `extensions["rfc-aitp-0010.bundle_uri"]` (`RFC_AITP_0010_BUNDLE_URI`) inside the coordinator's signed Manifest; `bundle_uri_from_manifest` reads it back (HTTPS only, or `http://localhost` / `http://127.0.0.1`), returning `None` when the coordinator advertises nothing. `SessionBundleServer::bundle_uri(&origin)` gives the URL of the server's route. |
| HTTP binding (§4.3.1) | `SessionBundleServer` (`crates/aitp-experimental/src/session_bundle/server.rs`), behind the `aitp-experimental/http-server` feature. `POST` accepts only the wrapped `{"session_bundle": …}` body (`parse_session_bundle_envelope`); a bare body is `SESSION_BUNDLE_INVALID`. Stores and serves bundles verbatim; it does **no** trust verification. |

## Verification (`verify_session_bundle`)

The normative order is
[RFC-AITP-0010 §5](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0010-session-trust-bundle.md#5-verification):
member-set check first, then (1) version, (2) expiry, (3) expiry-window
invariant, (4) participants non-empty, (5) fetch and verify the coordinator's
Manifest, (6) bundle signature, (7) per-participant TCT verification,
(8) self-membership.

`aitp-rs` runs exactly that order
(`crates/aitp-experimental/src/session_bundle/verifier.rs`), with the adapter's error code for each (`bundle_error_code` in
`crates/aitp-conformance/src/rs_adapter/mod.rs`):

0. Member-set and wrapper-shape checks, in `parse_session_bundle_wire`
   (before the verifier is called) → `UNKNOWN_FIELD` / `SESSION_BUNDLE_INVALID`.
1. `version == PROTOCOL_VERSION` (`"aitp/0.3"`) → `VersionMismatch` (`BUNDLE_VERSION_MISMATCH`).
2. `expires_at` not in the past → `Expired` (`BUNDLE_EXPIRED`).
3. `expires_at == min(participants[*].tct.exp)`, read from the still-unverified
   payloads → `ExpiryWindowInvariant` (`BUNDLE_EXPIRY_WINDOW_INVARIANT`).
   Vacuous for an empty roster, which step 4 reports.
4. `participants` non-empty → `EmptyParticipants` (`BUNDLE_EMPTY_PARTICIPANTS`).
5. Coordinator Manifest, chosen by `SessionBundleVerifyContext::coordinator_key`:
   - `CoordinatorKeySource::Manifest(&m)` — the caller fetched the coordinator's
     Manifest (e.g. `aitp::transport::ManifestFetcher::fetch`); it is
     re-verified with `aitp::manifest::verify_manifest` → `CoordinatorManifest(_)`
     (the Manifest's own error code, e.g. `MANIFEST_EXPIRED`; for local
     development, `insecure_localhost_dangerous` accepts a plain
     `http://localhost` or `http://127.0.0.1` endpoint), must have
     `m.aid == coordinator` → `CoordinatorManifestMismatch`
     (`KEY_RESOLUTION_FAILED`, RFC-AITP-0007 §1), and the signing key is
     resolved from `m.aid`.
     `m.expires_at` also caps every participant TCT in step 7.
   - `CoordinatorKeySource::UnverifiedAidDangerous` — skips step 5 and derives
     the key from the `aid:pubkey` coordinator AID alone; the coordinator's
     Manifest expiry and rotation state are not consulted. Not §5 step 5
     conformant; kept for offline callers that pin the coordinator out of
     band. The conformance adapter and the language bindings never use it.
6. Coordinator signature → `InvalidSignature` (`BUNDLE_INVALID_SIGNATURE`).
7. For each entry, `verify_tct` with issuer pinned to `coordinator` and
   audience pinned to `entry.aid`: `CoordinatorIssuerMismatch`,
   `AudienceMismatch`, or any other TCT failure → `TctVerification`
   (`BUNDLE_PARTICIPANT_TCT_INVALID`). Per-pair revocation (§7): if
   `revocation_check` reports an entry's `jti` revoked, that participant is
   **dropped**, not failed.
8. The verifier's AID appears in `participants[*].aid` → `NotMember`
   (`BUNDLE_NOT_MEMBER`). Last, so a forged bundle that omits the verifier
   reports `BUNDLE_INVALID_SIGNATURE`.

On success the result is a `BundleOutcome`: `Clear { active_aids }` when no
participant was revoked, or `DegradedSubset { active_aids, dropped_aids }`
when some were. A revoked participant (including the verifier itself) appears
in `dropped_aids` rather than failing the call; the caller decides policy.
Every AID in `active_aids` had its TCT signature, claims and expiry
verified; revocation is applied separately afterwards. The Manifest grant
cap is not applied to participant TCTs; the Manifest expiry cap is applied
only when a coordinator Manifest is supplied.

## Known limitations

- **Coordinator is a single signer.** A compromised coordinator can attest a
  bogus roster, but cannot forge TCTs for agents it never issued to (each TCT
  is still independently verified). Pairs that need direct peer binding must
  still handshake (RFC-AITP-0010 §2).
- **The coordinator Manifest is caller-supplied.** The sync verifier does not
  fetch it; fetch it yourself (e.g. `ManifestFetcher::fetch`) and pass
  `CoordinatorKeySource::Manifest`. The conformance adapter and the language
  bindings require it (`coordinator_manifest` in the adapter,
  `coordinator_manifest_json` / `coordinatorManifestJson` in Python / Node)
  and have no AID-only fallback: the adapter reports a missing Manifest as
  `KEY_RESOLUTION_FAILED`.
- **No client reads `bundle_uri` for you.** `bundle_uri_from_manifest` returns
  the advertised URL; posting to it is up to the caller.
- **No `session_id` replay tracking.** RFC-AITP-0010 §10 says consumers MUST
  reject a bundle whose `session_id` they already accepted with a different
  signature. `verify_session_bundle` is stateless
  (`crates/aitp-experimental/src/session_bundle/verifier.rs`); track accepted
  `session_id`s in your code.
- **The bundle server is an in-memory reference.** `SessionBundleServer` is
  process-local, unbounded, overwrites on a repeated `session_id`, and
  performs no verification
  (`crates/aitp-experimental/src/session_bundle/server.rs:56,180`).
- **Draft, opt-in.** Outside the core conformance gate; the `bundle-*`
  fixtures run only with the runner's `--feature experimental-session-bundle`. Pass/skip
  status: [conformance.md](conformance.md#v02-conformance-matrix).

## SDK example (Python coordinator → Node verifier)

```python
# Coordinator (Python): each participant already handshook with the
# coordinator, which issued them a TCT (aud == participant AID).
# a_tct / c_tct are the coordinator-issued TCT compact JWS strings.
b = aitp.SessionBundleBuilder(coordinator_agent)   # `experimental-session-bundle` feature
b.participant(a_aid, a_tct)
b.participant(c_aid, c_tct)
bundle_json = b.build()        # expires_at auto-set to min(member expiries)
```

```js
// Participant (Node) verifies the bundle naming its own AID, under the
// key the coordinator's Manifest designates (`{"manifest": …}` JSON,
// required; RFC-AITP-0010 §5 step 5):
const outcome = verifySessionBundle(bundleJson, myAid, coordinatorManifestJson);   // `experimental-session-bundle` feature
// outcome = { kind: "clear" | "degraded", activeAids, droppedAids }
// Throws on a Manifest for another AID / NotMember / ExpiryWindowInvariant /
// bad coordinator signature / any embedded TCT failing verification.
```

The cross-language `test_session_bundle_python_coordinator_node_verifier`
interop test (`bindings/interop/test_interop.py`) exercises exactly this path.
