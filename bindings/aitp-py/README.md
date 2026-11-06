# aitp — Python SDK

Python bindings for the **Agent Identity & Trust Protocol (AITP)**, built on
the pure-Rust `aitp-rs` protocol crates via [PyO3](https://pyo3.rs).

A thin SDK: an `AitpAgent` plus initiator/responder session objects. Their
methods take and return strings: JSON for the HTTP request/response bodies,
and compact-JWS strings for TCTs, grant vouchers and delegation tokens. Agent
code never handles a Rust type across the FFI boundary.

The feature-by-feature guide, with an example for every capability, is
[`docs/sdk-python.md`](../../docs/sdk-python.md).

## Install

```bash
pip install aitp-sdk      # PyPI distribution name; the import name is `aitp`
```

## Build from source

This crate is **not** part of the `aitp-rs` Cargo workspace. Build it with
[maturin](https://github.com/PyO3/maturin) and a Rust toolchain:

```bash
pip install maturin
maturin develop                          # default wheel, as published
maturin develop --features experimental  # adds the experimental features
maturin develop --no-default-features    # without SPKI pinning
```

### Cargo features

The published wheel is the default build:

- handshake, TCT, delegation, manifest verification and OIDC identity
- revocation-list signing and verification
- envelope signing and verification
- SPKI pinning (feature `spki-pinning`, on by default)

The experimental features are off by default and are not in the published
wheel. A source build enables them one by one, or all with `experimental`.
They carry no stability promise; their stubs are in `aitp_experimental.pyi`.

| Feature                            | Enables                                                       | RFC                  |
|------------------------------------|---------------------------------------------------------------|----------------------|
| `spki-pinning` (default)           | `compute_spki_hash`, `SpkiPinVerifier`                        | HPKP (RFC 7469)      |
| `experimental-renewal`             | `AitpAgent.build_renewal_request` / `process_renewal_request` | RFC-AITP-0013 (Draft) |
| `experimental-session-bundle`      | `SessionBundleBuilder`, `verify_session_bundle`               | RFC-AITP-0010 (Draft) |
| `experimental-multihop-delegation` | `verify_delegation_multihop`                                  | RFC-AITP-0011 (Draft) |
| `experimental-a2a-agent-card`      | `a2a_card_manifest_url`, `verify_a2a_agent_card_binding`      | RFC-AITP-0014 (Draft) |

From the sdist: `MATURIN_PEP517_ARGS="--features experimental" pip install --no-binary aitp-sdk aitp-sdk`.

## Usage

```python
import json

import aitp

initiator = aitp.AitpAgent.generate()
responder = aitp.AitpAgent.generate()

initiator.build_manifest(
    display_name="initiator",
    handshake_endpoint="https://localhost:8100/aitp/handshake/",
    offered_caps=["demo.echo"],
)
resp_manifest = responder.build_manifest(
    display_name="responder",
    handshake_endpoint="https://localhost:8200/aitp/handshake/",
    offered_caps=["demo.write"],
)

# Each side trusts the other's pinned key by AID. Without `pinned_keys`
# every pinned_key peer is rejected (fail closed).
sess  = initiator.new_session(pinned_keys=[responder.aid])
rsess = responder.new_responder(pinned_keys=[initiator.aid])

# Four-message mutual handshake — each call's output is the next peer's input.

hello                 = sess.build_hello(resp_manifest, ["demo.write"])
hello_ack, session_id = rsess.process_hello(hello)
commit                = sess.process_hello_ack(hello_ack, session_id)
commit_ack, responder_held = rsess.process_commit(commit, revoked_jtis=set())  # JSON: TCT the initiator issued the responder
held = json.loads(sess.complete(commit_ack, revoked_jtis=set()))  # JSON string: {"tct": ..., "grant_voucher": ...}

# Each peer now holds a TCT the other issued it.
ident = initiator.verify_tct(held["tct"], "demo.write", revoked_jtis=set())
print(ident.peer_aid, ident.grants)
```

In a real deployment each message moves over HTTP. `build_hello` returns the
body for `POST /aitp/handshake/hello`. `process_hello` returns the response
body plus the value for the `X-Aitp-Session-Id` header, and so on.

## API

[`aitp.pyi`](aitp.pyi) describes the full public surface; the table below
summarizes it. All `*_json` parameters and return values are JSON strings.

| Type / function       | Feature | Notes |
|-----------------------|:-------:|-------|
| `AitpAgent`           | default | `generate(suite=...)`, `from_seed(bytes, suite=...)`, `aid`, `build_manifest(...)`, `new_session(jwks=None, trust_anchors=None, pinned_keys=None, *, insecure_localhost_dangerous=False)`, `new_responder(jwks=None, trust_anchors=None, pinned_keys=None, *, insecure_localhost_dangerous=False)`, `verify_tct(..., pop=None)`, `verify_tct_cached(..., pop=None)` (`pop=(challenge_json, response_json)`, the presented-TCT path), `new_pop_challenge(tct_token, ttl_secs=60)`, `sign_pop_response(challenge_json)`, `build_delegation(voucher_token, delegatee_aid, scope, ttl_secs=None)`, `issue_tct_for_delegatee(...)` (returns `{"tct", "grant_voucher"}` JSON), `sign_envelope(message_type, payload_json, ...)`, `sign_revocation_list(...)` |
| `InitiatorSession`    | default | `build_hello(peer_manifest, grants, oidc_mint_jwt=None)`, `process_hello_ack(...)`, `complete(...)` → JSON `{"tct", "grant_voucher"}` |
| `ResponderSession`    | default | `process_hello(hello, oidc_mint_jwt=None)` → `(ack_json, session_id)`, `process_commit(...)` → `(ack_json, completed_json)` |
| `TctIdentity`         | default | `peer_aid`, `grants`, `expires_at`, `jti` |
| `DelegationVerified`  | default | `delegator`, `delegatee`, `issued_by`, `grants`, `expires_at`, `cnf_jkt` (`cnf` is a deprecated alias that emits `DeprecationWarning`) |
| `JwksProvider`        | default | OIDC JWKS map. `upsert(issuer, keys)`, `remove(issuer)`, `issuers()` |
| `TctStore`            | default | Cache for `AitpAgent.verify_tct_cached()`. A byte-identical, still-valid TCT skips the signature check; the key is the SHA-256 of the token bytes |
| `verify_delegation()` | default | RFC-AITP-0006, strict single-hop; rejects any multi-hop `chain`. `verify_delegation(token, verifier_aid, issuer_manifests, revoked_jtis=None, revocation=None, *, insecure_localhost_dangerous=False)`: verifies under the key the delegator's Manifest designates |
| `verify_manifest_json()` / `ManifestVerificationError` | default | Raises `ManifestVerificationError` with `.code`; non-manifest input raises `ValueError` |
| `verify_envelope()` / `EnvelopeVerificationError` | default | Verifies an `aitp/0.3` envelope's signature against a pinned sender, in the RFC-AITP-0001 §5.4 check order. Raises with `.code` (`UNKNOWN_VERSION`, `UNKNOWN_FIELD`, `INVALID_ENVELOPE`, `INVALID_SIGNATURE`). Replay and timestamp checks stay with the caller; see [Envelope signatures](../../docs/sdk-python.md#envelope-signatures-rfc-aitp-0001-54) |
| `verify_revocation_list()` / `RevocationVerificationError` | default | Verifies a revocation snapshot against a pinned issuer. Raises with `.code` |
| `revocation_signing_bytes()` | default | The exact bytes a revocation snapshot's signature covers |
| `verify_pop_response()` | default | RFC-AITP-0005 §6.2 checks only (not the TCT itself); returns the proven holder AID. Raises with `.code` `POP_CHALLENGE_INVALID` or `POP_RESPONSE_INVALID` |
| `compute_aid_jkt()`   | default | RFC 7638 thumbprint of an AID's key, for an OIDC JWT's `cnf.jkt` |
| `AitpAgent.build_renewal_request()` / `process_renewal_request()` | `experimental-renewal` | RFC-AITP-0013 (Draft). `build_renewal_request(current_tct_token)`; `process_renewal_request` returns `{"tct", "grant_voucher"}` JSON |
| `SessionBundleBuilder`, `verify_session_bundle(json, verifier_aid, coordinator_manifest_json, ...)` | `experimental-session-bundle` | RFC-AITP-0010. Verifies under the key the coordinator's Manifest designates (`coordinator_manifest_json` required) |
| `compute_spki_hash()`, `SpkiPinVerifier` | `spki-pinning` | HPKP-style outbound pinning |
| `verify_delegation_multihop()` | `experimental-multihop-delegation` | RFC-AITP-0011 multi-hop opt-in |
| `a2a_card_manifest_url(card_json)`, `verify_a2a_agent_card_binding(card_json, selected_interface_url, manifest_json=None, now_unix_secs=None)` | `experimental-a2a-agent-card` | RFC-AITP-0014 client verification, no I/O. Raises with `.code`. See [`docs/a2a-agent-card.md`](https://github.com/agentidentitytrustprotocol/aitp-rs/blob/main/docs/a2a-agent-card.md) |

The Python and Node bindings differ in some return shapes and argument
names; see
[Python vs Node differences](../../docs/sdk-python.md#python-vs-node-differences).

### UUID inputs

Identifiers that are signed or sent are **strict**: `sign_envelope`'s
`message_id`, `SessionBundleBuilder.session_id()` and the `jti` of each
`sign_revocation_list` entry must be the lowercase hyphenated UUID v4 wire
form (`xxxxxxxx-xxxx-4xxx-[89ab]xxx-xxxxxxxxxxxx`). Uppercase, braced,
`urn:uuid:`, unhyphenated and non-v4 forms raise `ValueError` naming the
field; they are never normalized, so what you pass is what goes on the wire.

A `revoked_jtis` set (on `verify_tct`, `verify_tct_cached`,
`process_renewal_request`, `verify_delegation` and
`verify_delegation_multihop`) is a **lenient** lookup key: each entry may be
in any RFC 9562 text form and is normalized before matching, so
`"{11111111-2222-4333-8444-555555555555}"` revokes the same TCT as the
lowercase form. An entry that is not a UUID at all raises `ValueError`
(`revoked_jtis entry is not a UUID`) rather than being ignored. The Node SDK
behaves identically.

Revocation is `fail_closed` (RFC-AITP-0008 §3.1): with no `revoked_jtis`,
every check fails with `.code` `TCT_REVOKED`. Pass `set()` when the issuer's
list is empty, or `revocation="fail_open"` only when the deployment has no
revocation source. As an issuer, advertise your list with
`build_manifest(..., revocation_list_uri=...)`, which RFC-AITP-0005 §11 and
RFC-AITP-0008 §1.4 require: an absolute HTTPS URL, conventionally your origin
plus `aitp.REVOCATION_LIST_PATH`.

### OIDC identity and P-256

See [OIDC identity](../../docs/sdk-python.md#oidc-identity-rfc-aitp-0002) and
[P-256 signing suite](../../docs/sdk-python.md#p-256-signing-suite-rfc-aitp-0001-543).

`pinned_key` identities work with Ed25519 and P-256 keys. For P-256 the
manifest's `public_key` is the 33-byte SEC1 compressed point.

### Pinned keys (`pinned_keys=`)

A session accepts a `pinned_key` peer only if the peer's AID is in the
`pinned_keys` list passed to `new_session` / `new_responder`
(RFC-AITP-0002 §3.2: the key must be in the verifier's local trust store,
checked before the proof). `None` or `[]` trusts no pinned key, so every
`pinned_key` peer is rejected. An entry that is not a valid AID raises
`ValueError`.

**Upgrading to 0.14:** possession-only pinned-key verification is gone. Pass
the peer's AID, e.g. `agent.new_session(pinned_keys=[peer.aid])`, or the
handshake fails with `IDENTITY_FAILED`.

## Tests

```bash
pip install maturin pytest httpx 'pyjwt[crypto]' cryptography
maturin develop
pytest tests/
```

`tests/test_docs_samples.py` runs every Python block in
[`docs/sdk-python.md`](../../docs/sdk-python.md) and the Usage block above.

The cross-language interop suite (Python ↔ Node) lives in
[`../interop`](../interop). Run it with `make interop` from the repo root.
