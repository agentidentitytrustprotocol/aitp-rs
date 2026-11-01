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
maturin develop                          # default surface, as published
maturin develop --features experimental  # adds the experimental features (see below)
maturin develop --no-default-features    # without SPKI pinning
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
# Each side lists the peer AIDs it trusts as pinned keys (RFC-AITP-0002 §3.2).
s = alice.new_session(pinned_keys=[bob.aid])
r = bob.new_responder(pinned_keys=[alice.aid])
# 4 messages — each call's output is the next peer's input.
hello = s.build_hello(bob_manifest, ["demo.echo"])
ack, sid = r.process_hello(hello)
commit   = s.process_hello_ack(ack, sid)
cack, bob_side_json = r.process_commit(commit, revoked_jtis=set())  # bob_side_json: what alice issued to bob
held = json.loads(s.complete(cack, revoked_jtis=set()))             # complete() returns a JSON string
tct_jws     = held["tct"]            # compact JWS issued by bob — store / present this
voucher_jws = held["grant_voucher"]  # compact JWS, or None if bob disallowed delegation
```

Both `complete()` and the second element of `process_commit()` are JSON
strings of the form `{"tct": …, "grant_voucher": …}`.
`complete()` gives the initiator the TCT the responder issued to it.
`process_commit()` gives the responder the TCT the initiator issued to it.

The Python binding does not return decoded TCT claims; the Node binding
returns them as `held.claims`. The claim set is defined in
[RFC-AITP-0005 §2](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0005-tct.md#2-claims)
and
[`aitp-tct.schema.json`](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/schemas/json/aitp-tct.schema.json).
To read a claim, verify the token first; `verify_tct` returns the claims you
need for authorization.

`new_session` and `new_responder` both take optional `jwks=`,
`trust_anchors=` and `pinned_keys=` arguments. `trust_anchors` overrides the
agent manifest's `accepted_trust_anchors` for that one session. The
[OIDC section](#oidc-identity-rfc-aitp-0002) shows when you need it.

`pinned_keys` is the session's local pinned-key trust store
([RFC-AITP-0002 §3.2](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0002-identity.md)):
a list of peer AID strings, Ed25519 or P-256. A peer that presents a
`pinned_key` identity is accepted only if its AID is in the list, and the
check runs before the proof is verified. Omitting `pinned_keys` (or passing
`[]`) trusts no pinned key, so **every `pinned_key` peer is rejected**: the
handshake fails closed with `IDENTITY_FAILED` in the `RuntimeError` message.
An entry that is not a valid AID raises `ValueError`. Possessing the private
key is not enough; the verifier must already know the key.

> **Upgrading to 0.14.** Before 0.14 a session accepted any `pinned_key` peer
> that proved possession of its key. That mode is gone. Pass the peer's AID
> (its `aid` property, or `manifest.aid` from the manifest you fetched and
> chose to trust) in `pinned_keys` on both `new_session` and `new_responder`,
> or every pinned-key handshake fails.

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
ident = alice.verify_tct(tct_jws, "demo.echo", revoked_jtis=set())
print(ident.peer_aid == bob.aid, ident.grants)   # True ['demo.echo']

# Presented-TCT model — a resource server checking a TCT a peer presented
# (e.g. in `X-AITP-TCT`). It challenges the presenter for proof of possession
# (RFC-AITP-0005 §6); verify_tct then checks the TCT and the PoP response
# together and pins the audience to the proven holder AID (the TCT's `sub`).
challenge = bob.new_pop_challenge(tct_jws)        # send to the presenter
response = alice.sign_pop_response(challenge)     # the presenter's reply
ident = bob.verify_tct(tct_jws, "demo.echo", revoked_jtis=set(), pop=(challenge, response))

# Revocation is fail_closed: pass the issuer's revoked TCT `jti`s (an empty
# set when nothing is revoked). A revoked jti and a missing list both raise
# with `.code == "TCT_REVOKED"`.
try:
    alice.verify_tct(tct_jws, "demo.echo", revoked_jtis={ident.jti})
except RuntimeError as err:
    print(err.code, err)   # TCT_REVOKED TCT verification failed: TCT jti is revoked
try:
    alice.verify_tct(tct_jws, "demo.echo")   # no list: status unavailable
except RuntimeError as err:
    print(err.code)   # TCT_REVOKED

# Explicit opt-out, for a deployment with no revocation source at all.
alice.verify_tct(tct_jws, "demo.echo", revocation="fail_open")
```

Revocation is `fail_closed` (RFC-AITP-0008 §3.1): without `revoked_jtis`
every TCT is rejected, because an unknown revocation status counts as
revoked. Pass `revocation="fail_open"` only when the deployment has no
revocation source; any other `revocation` value raises `ValueError`.

The issuer side of the same rule: every agent that issues TCTs MUST advertise
its `ListRevoked` URL in its signed Manifest (RFC-AITP-0005 §11,
RFC-AITP-0008 §1.4). Pass `revocation_list_uri` to `build_manifest`,
conventionally your origin plus `aitp.REVOCATION_LIST_PATH`
(`/.well-known/aitp-revocation-list`). Without it, a `fail_closed` verifier
that discovers lists through the Manifest rejects your TCTs as `TCT_REVOKED`.

```python
# not executed: fragment
agent.build_manifest(
    display_name="alice",
    handshake_endpoint="https://alice.example/aitp/handshake/",
    offered_caps=["demo.echo"],
    revocation_list_uri="https://alice.example" + aitp.REVOCATION_LIST_PATH,
)
```

A revocation failure (a listed `jti`, or no list under `fail_closed`) raises a
`RuntimeError` whose `.code` is `"TCT_REVOKED"`. A PoP failure raises one
whose `.code` is `"POP_CHALLENGE_INVALID"` (a malformed or stale challenge)
or `"POP_RESPONSE_INVALID"` (any other RFC-AITP-0005 §6.2 step). Every other
failed verification raises a plain `RuntimeError` with no `.code` attribute; the
Rust core's other TCT codes appear only in the message text, so do not branch
on that text. Malformed input, such as a token that is not a compact JWS or a
bad `expected_audience` AID, raises `ValueError` instead.

#### Downstream proof of possession

Verify a TCT a peer presents with `pop=(challenge_json, response_json)`, as in
the presented-TCT example above. That is the only way the SDK checks that the
presenter holds the key the TCT is bound to
([RFC-AITP-0005 §6](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0005-tct.md#6-binding-proof-of-possession)).
`pop` and `expected_audience` are mutually exclusive. If you pass
`expected_audience` instead, the presenter's AID must come from an
authenticated source, such as a verified PoP response or an equivalent
channel binding (mTLS with a bound client certificate). Never take it from
the token's own `aud`: that makes the audience check vacuous.

- `AitpAgent.new_pop_challenge(tct_token, ttl_secs=60)` is the consumer side.
  It returns a `pop_challenge` payload (`tct_jti`, a 128-bit CSPRNG `nonce`,
  `expires_at`).
- `AitpAgent.sign_pop_response(challenge_json)` is the holder side. It signs
  `sha256` of the decoded nonce bytes and returns the `pop_response` payload.
- `aitp.verify_pop_response(challenge_json, response_json, tct_token)` runs
  only the §6.2 checks and returns the proven holder AID. It does not verify
  the TCT itself.

The JSON values are envelope payloads: wrap them with `sign_envelope` for the
wire. Replay protection stays with the caller (RFC-AITP-0001 §5.5): the SDK
keeps no record of issued challenges. Accept a response to each challenge at
most once.

#### Cached verification (`TctStore`)

A high-throughput verifier that sees the same TCT on many requests can skip
the signature check on repeat sightings:

```python
store = aitp.TctStore(max_entries=1024)
ident = alice.verify_tct_cached(tct_jws, "demo.echo", store, revoked_jtis=set())
ident = alice.verify_tct_cached(tct_jws, "demo.echo", store, revoked_jtis=set())  # signature check skipped
print(store.len())   # 1
```

The cache key is the SHA-256 of the exact token bytes, so only a
byte-identical token can hit. Expiry, audience, required grant and
revocation (`revoked_jtis`, `fail_closed`) are re-checked on every call,
including cache hits.

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
# alice's Manifest: bob checks her signature under the key it designates.
alice_manifest = alice.build_manifest(
    display_name="alice",
    handshake_endpoint="https://alice.example/aitp/handshake/",
    offered_caps=["demo.write"],
)
# alice delegates part of what bob granted her to carol.
delegation_jws = alice.build_delegation(voucher_jws, carol.aid, ["demo.echo"])

# bob (the original grantor) verifies and mints carol a TCT of her own.
revoked = set()   # bob's deny list, e.g. jtis from verified revocation snapshots
verified = aitp.verify_delegation(
    delegation_jws, bob.aid, [alice_manifest], revoked_jtis=revoked
)
issued = json.loads(bob.issue_tct_for_delegatee(verified))  # JSON string
carol_tct = issued["tct"]
print(carol.verify_tct(carol_tct, "demo.echo", revoked_jtis=set()).peer_aid == bob.aid)   # True
```

The signature is `build_delegation(voucher_token, delegatee_aid, scope, ttl_secs=None)`.
`verify_delegation(delegation_token, verifier_aid, issuer_manifests,
revoked_jtis=None)` is strict single-hop: it rejects any token that carries a
multi-hop `chain`. `issuer_manifests` holds the delegator's Manifest as
`{"manifest": …}` envelope JSON strings. The token is verified under the key
that Manifest designates (RFC-AITP-0006 §4 step 1); without a valid one it
fails with `KEY_RESOLUTION_FAILED`. Pass `revoked_jtis`. If you omit it, a delegation whose
source TCT has been revoked is still redeemed. The result's `cnf_jkt` is the
delegatee's `cnf.jkt` (Node: `cnfJkt`). The older name `cnf` still works but
emits a `DeprecationWarning`. For multi-hop chains, see
[Multi-hop delegation](#multi-hop-delegation-rfc-aitp-0011-feature-experimental-multihop-delegation).

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
  `incompatible_identity_type`, `unknown_field` or `malformed`. Branch on
  `.code`, not on the message.
- **Unknown members** (the `UNKNOWN_FIELD` case, RFC-AITP-0001 §7) raise
  `ManifestVerificationError` with `.code == "unknown_field"`. The binding
  runs the same hardened wire parser as the HTTP transport
  ([#152](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/152)).
- **Input that is not a manifest at all**, including JSON with a duplicate
  key anywhere (RFC-AITP-0001 §5.4.5), raises `ValueError`.
- **`now_unix_secs`** overrides the verification clock.
- **`build_hello` verifies the peer's Manifest first** (RFC-AITP-0003 §5),
  including that it accepts this agent's identity type. A Manifest that fails
  raises `RuntimeError` with its registry code in `.code`, and nothing is built
  or sent.
- **`handshake_endpoint` must be `https://`** (RFC-AITP-0003 §5 step 2). For
  local development, `insecure_localhost_dangerous=True` also accepts plain
  `http://localhost` and `http://127.0.0.1`, and nothing else. The same keyword
  is on `new_session`, `new_responder` and `verify_delegation`. It is off by
  default.

### Revocation lists (RFC-AITP-0008)

```python
import uuid

snapshot = bob.sign_revocation_list(
    [{"jti": str(uuid.uuid4()), "reason": "compromised"}],   # jti must be a lowercase UUID v4
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

`sign_revocation_list` entries take `jti` (a lowercase hyphenated UUID v4,
as `str(uuid.uuid4())` returns; any other form raises `ValueError`), plus optional
`revoked_at` (unix seconds, defaulting to now) and `reason`.

`verify_revocation_list(envelope_json, expected_issuer_aid, now_unix_secs=None)`
returns `None` or raises `RevocationVerificationError`. Its `.code` is one of
`signature_invalid`, `issuer_mismatch`, `version_unknown`, `expired`,
`unknown_field` (a member outside the schema) or `malformed` (including a
duplicate JSON key). A bad `expected_issuer_aid` raises `ValueError` instead.
These are the binding's own lowercase cause codes, not the spec's registered
codes. `version_unknown` (a `version` other than `aitp/0.3`, checked before
the signature) and `malformed` are separate codes here, but
both are the spec's `REVOCATION_SNAPSHOT_INVALID` (spec `VERSIONING.md`).

The function checks only that the snapshot is authentic and has not expired.
It does not decide whether the snapshot is fresh enough. That policy belongs
to you; see
[RFC-AITP-0008 §3](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0008-revocation.md#3-revocation-policy)
and the spec's
[operational guidance](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/docs/operational-guidance.md#revocation-lookup-revocation_policymode).
`revocation_signing_bytes` returns the exact signed bytes, for use by an
independent verifier or an HSM signing path.

### Envelope signatures (RFC-AITP-0001 §5.4)

```python
envelope = bob.sign_envelope(
    "mutual_hello",
    json.dumps({"hello": True}),
    extensions_json=json.dumps({"com.example.trace": {"id": "t-1"}}),   # optional
)
aitp.verify_envelope(envelope, bob.aid)   # pin the expected sender
tampered = json.loads(envelope) | {"message_type": "mutual_hello_ack"}
try:
    aitp.verify_envelope(json.dumps(tampered), bob.aid)
except aitp.EnvelopeVerificationError as err:
    print(err.code)   # INVALID_SIGNATURE
```

`sign_envelope(message_type, payload_json, extensions_json=None,
message_id=None, timestamp=None)` signs an `aitp/0.3` envelope over signing
input v2. The signature covers every member except `signature`, including
`extensions`. `message_id` defaults to a fresh UUID v4; a supplied one must be
lowercase hyphenated v4, and any other form raises `ValueError`. `timestamp`
defaults to now.

`verify_envelope(envelope_json, expected_sender_aid)` returns `None` or raises
`EnvelopeVerificationError`, a subclass of `RuntimeError`. Its `.code` is the
registered spec code of the first failing step of the RFC-AITP-0001 §5.4
check order:

1. `UNKNOWN_VERSION`: `version` is absent or is not `aitp/0.3`. `aitp/0.2`
   is rejected exactly like `aitp/9.9`.
2. `UNKNOWN_FIELD`: a member outside the schema and outside `extensions`.
   `INVALID_ENVELOPE`: any other structural defect, such as a duplicate JSON
   key (RFC-AITP-0001 §5.4.5), a missing member, an unregistered
   `message_type` or a non-v4 `message_id`.
3. `INVALID_SIGNATURE`: the signature does not verify under the expected
   sender's key, or `sender.agent_id` is not `expected_sender_aid`.

The key comes from `expected_sender_aid`, since every AID encodes its public
key. A bad `expected_sender_aid` raises `ValueError` instead.

The function checks only that the envelope is well formed and authentic. It
does not check the timestamp window or deduplicate `message_id`
(RFC-AITP-0001 §5.5). A receiving endpoint runs those checks itself, in the
order RFC-AITP-0009 §3.1 sets out.

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
    accepted_identity_types=["oidc", "pinned_key"],   # bob presents a pinned key
)

def mint(pop_nonce: str) -> str:
    # Return a fresh JWT from your IdP, bound to this handshake and to dave's key.
    return my_idp.mint_jwt(sub="dave", aud=bob.aid, nonce=pop_nonce,
                           cnf_jkt=aitp.compute_aid_jkt(dave.aid))

# Each side must list the other's identity type (RFC-AITP-0004 §5.1 step 8),
# so bob re-publishes a manifest that accepts OIDC peers too.
bob_manifest = bob.build_manifest(
    display_name="bob",
    handshake_endpoint="https://bob.example/aitp/handshake/",
    offered_caps=["demo.echo"],
    accepted_identity_types=["pinned_key", "oidc"],
)
sess = dave.new_session(jwks=jwks, pinned_keys=[bob.aid])   # bob answers with a pinned key
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

erin_manifest = erin.build_manifest(
    display_name="erin",
    handshake_endpoint="https://erin.example/aitp/handshake/",
    offered_caps=["demo.echo"],
)   # pinned_key is the default; public_key is the 33-byte compressed point
aitp.verify_manifest_json(erin_manifest)

# A P-256 peer is pinned by its AID, exactly like an Ed25519 one.
p_sess = bob.new_session(pinned_keys=[erin.aid])
p_resp = erin.new_responder(pinned_keys=[bob.aid])
p_ack, p_sid = p_resp.process_hello(p_sess.build_hello(erin_manifest, ["demo.echo"]))
```

Every other method works the same with a P-256 agent. Signature formats are
defined in
[RFC-AITP-0001 §5.4.3](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0001-core.md#543-algorithm-tagged-signature-wire-format-jcs-profile-only)
for the JCS profile and in
[§5.4.5](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0001-core.md#545-compact-jws-profile-portable-trust-artifacts)
for compact JWS.

Since 0.14, `build_manifest` emits a `pinned_key` identity hint for a P-256
key too. Its `public_key` is the 33-byte SEC1 compressed point (44 base64url
characters), the same bytes as the AID's identifier. Earlier versions raised
`RuntimeError` here.

### SPKI cert pinning (HPKP-style, feature `spki-pinning`)

```python
pin = aitp.compute_spki_hash(cert_der_bytes)    # 32 bytes
verifier = aitp.SpkiPinVerifier([pin])
print(verifier.is_pinned(cert_der_bytes), verifier.is_pinned(other_cert_der))   # True False
```

Wire `verifier.is_pinned()` into your HTTP client's certificate-verification
hook, for example an `httpx` transport-level verify callback. The SDK does no
HTTP itself.

<a id="additional-capabilities-on-by-default"></a>
## Experimental (build from source)

The published `aitp-sdk` wheel does not include these. They carry no
stability promise. Build from source with every experimental feature, or
name one of `experimental-renewal`, `experimental-session-bundle` and
`experimental-multihop-delegation`:

```bash
maturin develop --features experimental
# From the sdist:
MATURIN_PEP517_ARGS="--features experimental" pip install --no-binary aitp-sdk aitp-sdk
```

Their type stubs are in `bindings/aitp-py/aitp_experimental.pyi`, which the
wheel does not ship.

### TCT renewal (RFC-AITP-0013, feature `experimental-renewal`)

```python
import time

req = alice.build_renewal_request(current_tct_token=tct_jws)
renewed = json.loads(bob.process_renewal_request(
    req, manifest_exp_unix_secs=int(time.time()) + 86_400, new_ttl_secs=3600,
))
fresh_tct, fresh_voucher = renewed["tct"], renewed["grant_voucher"]
```

- **Return value:** `process_renewal_request` returns a JSON string with
  `tct` and `grant_voucher`. The Node binding returns the same fields as an
  object, `{ tct, grantVoucher }`.
- **Argument:** `current_tct_token`, the held TCT as a compact JWS. Before
  0.15 the compiled keyword was `current_tct_envelope_json`, which disagreed
  with the stub
  ([#199](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/199)).
- **Status:** RFC-AITP-0013 is *Draft*.
- **Policy re-evaluation (since 0.15).** The issuer must have called
  `build_manifest()`; grants its Manifest no longer offers are dropped
  (none left raises). Pass the issuer's revoked TCT `jti`s as
  `revoked_jtis=` to refuse a revoked TCT. A replayed request (same
  `pop_nonce`) raises. See [tct-renewal.md](tct-renewal.md).

### Multi-hop delegation (RFC-AITP-0011, feature `experimental-multihop-delegation`)

```python
# Every hop verifies under the key its issuer's Manifest designates
# (RFC-AITP-0011 §3 step 1), so pass each hop issuer's Manifest
# (`alice_manifest` from the delegation example above).
verified = aitp.verify_delegation_multihop(
    delegation_jws, bob.aid, [alice_manifest],
    max_delegation_hops=3, revoked_jtis=revoked,
)
```

For a loopback issuer in local development, it takes the same
`insecure_localhost_dangerous=True` as `verify_delegation`. It is off by default.

This is an opt-in verifier that accepts RFC-AITP-0011 chains up to
`max_delegation_hops` total hops, with a default of 3. Each hop is verified
under the key resolved from its issuer's verified Manifest
(RFC-AITP-0011 §3 step 1), so `issuer_manifests` must hold the
`{"manifest": …}` envelope JSON of every hop issuer; a hop whose issuer has
none fails with `KEY_RESOLUTION_FAILED`. A single-hop token
also verifies, and `max_delegation_hops=0` reverts to strict single-hop.
`revoked_jtis` is applied to the root voucher's `src_jti` and to every hop's
`jti`. See [multihop-delegation.md](multihop-delegation.md) for the
verification rules and known limitations.

### Session Trust Bundle (RFC-AITP-0010, feature `experimental-session-bundle`)

```python
bundle = (
    aitp.SessionBundleBuilder(bob)              # bob coordinates
        .session_id(str(uuid.uuid4()))          # optional; defaults to a fresh UUID
        .issued_at(int(time.time()))            # optional; defaults to now
        .participant(alice.aid, tct_jws)        # TCTs bob issued to each member
        .participant(carol.aid, carol_tct)
        .build()
)
# The coordinator's current Manifest is required: it designates the key
# the bundle verifies under (RFC-AITP-0010 §5 step 5), and its expires_at
# must outlive every participant TCT (RFC-AITP-0005 §10.4).
bob_manifest = bob.build_manifest(
    display_name="bob",
    handshake_endpoint="https://bob.example/aitp/handshake/",
    offered_caps=["demo.echo"],
    ttl_secs=24 * 3600,
)
outcome = aitp.verify_session_bundle(bundle, alice.aid, bob_manifest)
print(outcome["kind"])   # clear  (keys: kind, active_aids, dropped_aids)

outcome = aitp.verify_session_bundle(
    bundle, alice.aid, bob_manifest, revocation_check=lambda jti: jti in revoked,
)
```

`verify_session_bundle(bundle_envelope_json, verifier_aid, coordinator_manifest_json, now_unix_secs=None, revocation_check=None)`
returns `{"kind": "clear" | "degraded", "active_aids": [...], "dropped_aids": [...]}`.
`revocation_check` is called with each participant TCT's `jti` and returns
`True` if that TCT is revoked. A revoked participant is dropped, and `kind`
becomes `degraded`. If the callback raises or returns a non-bool, the
participant is treated as **not** revoked (fail-open,
`bindings/aitp-py/src/bundle.rs:153-156`), so keep it total. `coordinator_manifest_json` is required: the coordinator's `{"manifest": …}`
envelope is verified, must designate the bundle's `coordinator`, and supplies
the coordinator key (RFC-AITP-0010 §5 step 5). There is no AID-only fallback;
a Manifest for another AID raises `RuntimeError`. See
[session-bundle.md](session-bundle.md).

## Python vs Node differences

The two bindings wrap the same Rust core, but they differ in these places.
Python returns structured results as JSON strings where Node returns objects;
the field names match apart from casing (`grant_voucher` / `grantVoucher`).

| Operation | Python | Node |
|---|---|---|
| `process_renewal_request` / `processRenewalRequest` | JSON string with `tct` and `grant_voucher` | object `{ tct, grantVoucher }` |
| `issue_tct_for_delegatee` / `issueTctForDelegatee` | JSON string with `tct` and `grant_voucher` | object `{ tct, grantVoucher }` |
| Handshake completion | `complete()` returns a JSON string; no decoded claims | `complete()` returns an object with `tct`, `claims` and an optional `grantVoucher` |
| Non-manifest input to manifest verification (including a duplicate key) | `ValueError` | `Error` with `code === 'malformed'` |
| Revoked-JTI sets | `set` or `frozenset` of `str` (not a `list` or other iterable) | `Array<string>` |
| `sign_envelope` / `signEnvelope` optional arguments | keyword arguments `extensions_json`, `message_id`, `timestamp` | an `opts` object `{ extensionsJson, messageId, timestamp }` |
| TCT verification failure | `RuntimeError`; `.code == "TCT_REVOKED"` on revocation failures, otherwise no `.code` | `Error`; `code === 'TCT_REVOKED'` on revocation failures, otherwise napi's generic `'GenericFailure'` |

## Tests + interop

```bash
maturin develop
pytest -v                      # binding tests in bindings/aitp-py/tests
cd ../interop && pytest -v     # cross-language interop (see bindings/interop/README.md)
```

See [`bindings/interop/README.md`](../bindings/interop/README.md) for what the
interop suite covers.
