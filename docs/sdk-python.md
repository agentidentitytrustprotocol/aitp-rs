# Python SDK — feature guide

This page is a feature-by-feature pointer into [`bindings/aitp-py`](../bindings/aitp-py).
Each section names the RFC, the Cargo feature flag (if any), and a short
example. The type stubs in [`aitp.pyi`](../bindings/aitp-py/aitp.pyi) have
the full method signatures.

The Node SDK covers the same operations; see [`sdk-node.md`](sdk-node.md) and
[Python vs Node differences](#python-vs-node-differences) below.

The Python blocks on this page run as one connected flow. Names defined in
an earlier block (`alice`, `bob`, `tct_jws`, …) are reused later. CI runs
every block as written, through
[`bindings/aitp-py/tests/test_docs_samples.py`](../bindings/aitp-py/tests/test_docs_samples.py).
That test fails if a block here changes without the test changing too.

## Install

```bash
pip install aitp-sdk      # PyPI distribution name; the import name is `aitp`
```

For the current version, see the
[releases](https://github.com/agentidentitytrustprotocol/aitp-rs/releases) or
`bindings/aitp-py/pyproject.toml`.

## Build

To build from source you need [maturin](https://github.com/PyO3/maturin) and a
Rust toolchain. The binding is not part of the `aitp-rs` Cargo workspace.

```bash
pip install maturin
maturin develop                          # full surface (all features are default)
maturin develop --no-default-features    # minimal surface (core handshake only)
```

## Default surface

### Mutual handshake (RFC-AITP-0004)

```python
import json

import aitp

alice = aitp.AitpAgent.generate()
bob   = aitp.AitpAgent.generate()
bob_manifest = bob.build_manifest(
    display_name="bob",
    handshake_endpoint="https://bob.example/aitp/handshake/",
    offered_caps=["demo.echo"],
)
alice.build_manifest(
    display_name="alice",
    handshake_endpoint="https://alice.example/aitp/handshake/",
    offered_caps=["demo.write"],
)
# 4 messages — each call's output is the next peer's input.
s, r = alice.new_session(), bob.new_responder()
hello = s.build_hello(bob_manifest, ["demo.echo"])
ack, sid = r.process_hello(hello)
commit   = s.process_hello_ack(ack, sid)
cack, bob_side_json = r.process_commit(commit)  # bob_side_json: what alice issued to bob
held = json.loads(s.complete(cack))             # complete() returns a JSON string
tct_jws     = held["tct"]            # compact JWS issued by bob — store / present this
voucher_jws = held["grant_voucher"]  # compact JWS, or None if bob disallowed delegation
```

Both `complete()` and the second element of `process_commit()` are JSON
strings of the form `{"tct": …, "grant_voucher": …}`.
`complete()` gives the initiator the TCT the responder issued to it.
`process_commit()` gives the responder the TCT the initiator issued to it.
The `aitp.pyi` docstring for `process_commit` describes this the other way
round ([#199](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/199)), but the code above is what the binding does.

The Python binding does not return decoded TCT claims; the Node binding
returns them as `held.claims`. The claim set is defined in
[RFC-AITP-0005 §2](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0005-tct.md#2-claims)
and
[`aitp-tct.schema.json`](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/schemas/json/aitp-tct.schema.json).
To read a claim, verify the token first; `verify_tct` returns the claims you
need for authorization.

`new_session` and `new_responder` both take optional `jwks=` and
`trust_anchors=` arguments. `trust_anchors` overrides the agent manifest's
`accepted_trust_anchors` for that one session. The
[OIDC section](#oidc-identity-rfc-aitp-0002) shows when you need it.

<a id="tct-verification-rfc-aitp-0005-9"></a>

### TCT verification (RFC-AITP-0005 §7.2)

A TCT is an opaque compact JWS string. `verify_tct` runs the verification
order in
[RFC-AITP-0005 §7.2](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0005-tct.md#72-verification-order).
It returns a `TctIdentity` with `peer_aid` (the issuer), `grants`,
`expires_at` and `jti`. The spec integration guide,
[Step 2: Verify locally](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/docs/integration-guide.md#step-2-verify-locally),
explains what a verifier checks and why.

```python
# Holder-receipt model — the verifier's AID is the agent's own AID (default).
ident = alice.verify_tct(tct_jws, "demo.echo")
print(ident.peer_aid == bob.aid, ident.grants)   # True ['demo.echo']

# Presented-TCT model — a resource server checking a TCT a peer presented
# (e.g. in `X-AITP-TCT`). The expected audience is the TCT's subject (aud == sub).
ident = bob.verify_tct(tct_jws, "demo.echo", expected_audience=alice.aid)

# Revocation gate: pass the set of revoked TCT `jti`s. Verifiers SHOULD supply
# it — omitting it accepts a revoked-but-unexpired TCT.
try:
    alice.verify_tct(tct_jws, "demo.echo", revoked_jtis={ident.jti})
except RuntimeError as err:
    print(err)   # TCT verification failed: TCT jti is revoked
```

A failed verification raises a plain `RuntimeError` with no `.code`
attribute. Malformed input, such as a token that is not a compact JWS or a bad
`expected_audience` AID, raises `ValueError` instead. The Rust core does have
`ErrorCode::TctRevoked` and the other TCT codes, but the binding exposes them
only in the message text. Do not branch on that text.

#### Cached verification (`TctStore`)

A high-throughput verifier that sees the same TCT on many requests can skip
the signature check on repeat sightings:

```python
store = aitp.TctStore(max_entries=1024)
ident = alice.verify_tct_cached(tct_jws, "demo.echo", store)
ident = alice.verify_tct_cached(tct_jws, "demo.echo", store)  # signature check skipped
print(store.len())   # 1
```

The cache key is the SHA-256 of the exact token bytes, so only a
byte-identical token can hit. Expiry, audience, required grant and
`revoked_jtis` are re-checked on every call, including cache hits.

#### Verifying without this SDK

A TCT verifies under any stock JOSE library (`pyjwt`, etc.) given only the
issuer's public key. See
[architecture.md § Debugging a TCT](architecture.md#debugging-a-tct). For an
independent, dependency-light Python implementation of the full check, see
[`aitp_verifier/tct.py`](https://github.com/agentidentitytrustprotocol/aitp-verifier-py/blob/main/aitp_verifier/tct.py)
and
[`aitp_verifier/jws.py`](https://github.com/agentidentitytrustprotocol/aitp-verifier-py/blob/main/aitp_verifier/jws.py)
in `aitp-verifier-py`.

### Delegation (RFC-AITP-0006)

`build_delegation` takes the grant voucher the delegator received in the
handshake (`held["grant_voucher"]` above). The delegatee's key binding comes
from its AID, so you pass no public key. The voucher model is described in
[RFC-AITP-0006](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0006-delegation.md)
and
[RFC-AITP-0005 §8](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0005-tct.md#8-grant-voucher).

```python
carol = aitp.AitpAgent.generate()
# alice delegates part of what bob granted her to carol.
delegation_jws = alice.build_delegation(voucher_jws, carol.aid, ["demo.echo"])

# bob (the original grantor) verifies and mints carol a TCT of her own.
revoked = set()   # bob's deny list, e.g. jtis from verified revocation snapshots
verified = aitp.verify_delegation(delegation_jws, bob.aid, revoked_jtis=revoked)
issued = json.loads(bob.issue_tct_for_delegatee(verified))  # JSON string
carol_tct = issued["tct"]
print(carol.verify_tct(carol_tct, "demo.echo").peer_aid == bob.aid)   # True
```

The signature is `build_delegation(voucher_token, delegatee_aid, scope, ttl_secs=None)`.
`verify_delegation` is strict single-hop: it rejects any token that carries a
multi-hop `chain`. Pass `revoked_jtis`. If you omit it, a delegation whose
source TCT has been revoked is still redeemed. For multi-hop chains, see
[Multi-hop delegation](#multi-hop-delegation-rfc-aitp-0011-feature-multihop-delegation).

### Manifest verification

```python
aitp.verify_manifest_json(bob_manifest)   # returns None on success

try:
    aitp.verify_manifest_json(bob_manifest, now_unix_secs=4_102_444_800)  # year 2100
except aitp.ManifestVerificationError as err:
    print(err.code)   # expired
```

- **Verification failures** raise `ManifestVerificationError`, a subclass of
  `RuntimeError`. Its `.code` is one of `signature_invalid`, `pop_failed`,
  `aid_mismatch`, `expired`, `version_unknown`, `identity_hint_malformed`,
  `incompatible_identity_type` or `malformed`. Branch on `.code`, not on the
  message.
- **Unknown members** (the `UNKNOWN_FIELD` case) are rejected while the binding
  parses the JSON, so Python raises `ValueError` ("invalid manifest JSON:
  unknown field …") rather than `ManifestVerificationError`; there is no
  `UNKNOWN_FIELD` code
  ([#152](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/152)).
- **Input that is not a manifest at all** raises `ValueError`.
- **`now_unix_secs`** overrides the verification clock.

### Revocation lists (RFC-AITP-0008)

```python
import uuid

snapshot = bob.sign_revocation_list(
    [{"jti": str(uuid.uuid4()), "reason": "compromised"}],   # jti must be a UUID
    expires_in_secs=600,
)
aitp.verify_revocation_list(snapshot, bob.aid)   # pin the expected issuer
try:
    aitp.verify_revocation_list(snapshot, alice.aid)
except aitp.RevocationVerificationError as err:
    print(err.code)   # issuer_mismatch

revoked |= {e["jti"] for e in json.loads(snapshot)["revocation_list"]["entries"]}
signed_bytes = aitp.revocation_signing_bytes(snapshot)   # JCS of the inner body
```

`sign_revocation_list` entries take `jti` (a UUID string), plus optional
`revoked_at` (unix seconds, defaulting to now) and `reason`.

`verify_revocation_list(envelope_json, expected_issuer_aid, now_unix_secs=None)`
returns `None` or raises `RevocationVerificationError`. Its `.code` is one of
`signature_invalid`, `issuer_mismatch`, `version_unknown`, `expired` or
`malformed`. A bad `expected_issuer_aid` raises `ValueError` instead.

The function checks only that the snapshot is authentic and has not expired.
It does not decide whether the snapshot is fresh enough. That policy belongs
to you; see
[RFC-AITP-0008 §3](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0008-revocation.md#3-revocation-policy)
and the spec's
[operational guidance](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/docs/operational-guidance.md#revocation-lookup-revocation_policymode).
`revocation_signing_bytes` returns the exact signed bytes, for use by an
independent verifier or an HSM signing path.

### OIDC identity (RFC-AITP-0002)

```python
# You fetch the IdP's JWKS yourself; the SDK does no HTTP.
jwks = aitp.JwksProvider({"https://idp.example/": [idp_jwk]})
dave = aitp.AitpAgent.generate()
dave.build_manifest(
    display_name="dave",
    handshake_endpoint="https://dave.example/aitp/handshake/",
    offered_caps=["demo.write"],
    identity_type="oidc", oidc_issuer="https://idp.example/", oidc_subject="dave",
)

def mint(pop_nonce: str) -> str:
    # Return a fresh JWT from your IdP, bound to this handshake and to dave's key.
    return my_idp.mint_jwt(sub="dave", aud=bob.aid, nonce=pop_nonce,
                           cnf_jkt=aitp.compute_aid_jkt(dave.aid))

sess = dave.new_session(jwks=jwks)
oidc_hello = sess.build_hello(bob_manifest, ["demo.echo"], oidc_mint_jwt=mint)

# bob's manifest accepts no OIDC issuer by default, so his responder must
# trust the IdP explicitly.
responder = bob.new_responder(jwks=jwks, trust_anchors=["https://idp.example/"])
oidc_ack, oidc_sid = responder.process_hello(oidc_hello)
```

The `oidc_mint_jwt` callback receives the handshake's `pop_nonce` (a `str`)
and returns a compact JWT. The claims that JWT must carry (`nonce`, `aud`,
`cnf.jkt`, …) are defined in
[RFC-AITP-0002 §2.2](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0002-identity.md#22-required-jwt-claims).
`aitp.compute_aid_jkt(aid)` computes the `cnf.jkt` value for an Ed25519 or
P-256 AID.

### P-256 signing suite (RFC-AITP-0001 §5.4.3)

```python
erin = aitp.AitpAgent.generate(suite="p256")                  # aid:pubkey:p256:…
erin_again = aitp.AitpAgent.from_seed(bytes(range(32)), suite="p256")   # deterministic

try:
    erin.build_manifest(display_name="erin",
                        handshake_endpoint="https://erin.example/aitp/handshake/",
                        offered_caps=["demo.echo"])   # pinned_key is the default
except RuntimeError as err:
    print(err)   # pinned_key identity_hint with a P-256 agent key is not supported; …
```

Every other method works the same with a P-256 agent. Signature formats are
defined in
[RFC-AITP-0001 §5.4.3](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0001-core.md#543-algorithm-tagged-signature-wire-format-jcs-profile-only)
for the JCS profile and in
[§5.4.5](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0001-core.md#545-compact-jws-profile-portable-trust-artifacts)
for compact JWS.

**SDK restriction:** this SDK's `build_manifest` can only emit a `pinned_key`
identity hint for an Ed25519 key (`bindings/aitp-py/src/agent.rs`), so P-256
agents must use `identity_type="oidc"`. The protocol itself does not impose
this: the v0.2 manifest schema accepts a P-256 `public_key`.

## Additional capabilities (on by default)

These ship in the default wheel. A `--no-default-features` build drops all of
them; add back by named Cargo feature: `renewal`, `session-bundle`,
`spki-pinning`, `multihop-delegation`.

### TCT renewal (RFC-AITP-0013 / RFC-AITP-0004 §8.1, feature `renewal`)

```python
import time

req = alice.build_renewal_request(tct_jws)   # pass the held TCT positionally
renewed = json.loads(bob.process_renewal_request(
    req, manifest_exp_unix_secs=int(time.time()) + 86_400, new_ttl_secs=3600,
))
fresh_tct, fresh_voucher = renewed["tct"], renewed["grant_voucher"]
```

- **Return value:** `process_renewal_request` returns a JSON string with
  `tct` and `grant_voucher`. The Node binding returns only the TCT.
- **Pass the held TCT positionally.** The stub names the argument
  `current_tct_token`, but the compiled keyword is
  `current_tct_envelope_json`, even though it takes a compact JWS
  ([#199](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/199)).
- **Status:** RFC-AITP-0013 is *Planned* and the RFC-AITP-0004 §8.1 renewal
  extension is non-normative.
- **Before you expose renewal:** read
  [tct-renewal.md § Known limitations](tct-renewal.md#known-limitations).
  That section covers request replay and the lack of revocation
  re-evaluation, tracked in
  [#196](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/196).

### Multi-hop delegation (RFC-AITP-0011, feature `multihop-delegation`)

```python
verified = aitp.verify_delegation_multihop(
    delegation_jws, bob.aid, max_delegation_hops=3, revoked_jtis=revoked,
)
```

This is an opt-in verifier that accepts RFC-AITP-0011 chains up to
`max_delegation_hops` total hops, with a default of 3. A single-hop token
also verifies, and `max_delegation_hops=0` reverts to strict single-hop.
`revoked_jtis` is applied to the root voucher's `src_jti` and to every hop's
`jti`. See [multihop-delegation.md](multihop-delegation.md) for the
verification rules and known limitations.

### Session Trust Bundle (RFC-AITP-0010, feature `session-bundle`)

```python
bundle = (
    aitp.SessionBundleBuilder(bob)              # bob coordinates
        .session_id(str(uuid.uuid4()))          # optional; defaults to a fresh UUID
        .issued_at(int(time.time()))            # optional; defaults to now
        .participant(alice.aid, tct_jws)        # TCTs bob issued to each member
        .participant(carol.aid, carol_tct)
        .build()
)
outcome = aitp.verify_session_bundle(bundle, alice.aid)
print(outcome["kind"])   # clear  (keys: kind, active_aids, dropped_aids)

outcome = aitp.verify_session_bundle(
    bundle, alice.aid, revocation_check=lambda jti: jti in revoked,
)
```

`verify_session_bundle(bundle_envelope_json, verifier_aid, now_unix_secs=None, revocation_check=None)`
returns `{"kind": "clear" | "degraded", "active_aids": [...], "dropped_aids": [...]}`.
`revocation_check` is called with each participant TCT's `jti` and returns
`True` if that TCT is revoked. A revoked participant is dropped, and `kind`
becomes `degraded`. If the callback raises or returns a non-bool, the
participant is treated as **not** revoked (fail-open,
`bindings/aitp-py/src/bundle.rs:146-149`), so keep it total. See [session-bundle.md](session-bundle.md).

### SPKI cert pinning (HPKP-style, feature `spki-pinning`)

```python
pin = aitp.compute_spki_hash(cert_der_bytes)    # 32 bytes
verifier = aitp.SpkiPinVerifier([pin])
print(verifier.is_pinned(cert_der_bytes), verifier.is_pinned(other_cert_der))   # True False
```

Wire `verifier.is_pinned()` into your HTTP client's certificate-verification
hook, for example an `httpx` transport-level verify callback. The SDK does no
HTTP itself.

## Python vs Node differences

The two bindings wrap the same Rust core, but they differ in these places.
[#199](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/199)
tracks the first three rows and
[#152](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/152) the
fourth.

| Operation | Python | Node |
|---|---|---|
| `process_renewal_request` / `processRenewalRequest` | JSON string with `tct` and `grant_voucher` | bare compact-JWS TCT (no voucher) |
| `issue_tct_for_delegatee` / `issueTctForDelegatee` | JSON string with `tct` and `grant_voucher` | bare compact-JWS TCT (no voucher) |
| `build_renewal_request` argument | pass positionally; the compiled keyword is `current_tct_envelope_json`, not the stub's `current_tct_token` | `buildRenewalRequest(currentTctToken)` |
| Unknown manifest members (`UNKNOWN_FIELD`) | `ValueError` (parse-time rejection; no code) | `error.code === 'malformed'` |
| Handshake completion | `complete()` returns a JSON string; no decoded claims | `complete()` returns an object with `tct`, `claims` and an optional `grantVoucher` |
| Non-manifest input to manifest verification | `ValueError` | `Error` with `code === 'malformed'` (also used for unknown members) |
| Revoked-JTI sets | `set` or `frozenset` of `str` (the stub's `AbstractSet` is wider than what the binding accepts, [#199](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/199)) | `Array<string>` |
| TCT verification failure | `RuntimeError`, no `.code` | `Error` with napi's generic `code === 'GenericFailure'`, no AITP code |

## Tests + interop

```bash
maturin develop
pytest -v                      # binding tests in bindings/aitp-py/tests
cd ../interop && pytest -v     # cross-language interop (see bindings/interop/README.md)
```

See [`bindings/interop/README.md`](../bindings/interop/README.md) for what the
interop suite covers.
