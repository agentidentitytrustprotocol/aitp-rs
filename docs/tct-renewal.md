# TCT renewal (RFC-AITP-0013)

> **Status: opt-in, implementation ahead of the spec.** The shortened renewal
> exchange is sketched non-normatively in
> [RFC-AITP-0004 §8.1](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0004-mutual-handshake.md#81-non-normative-shortened-renewal-extension);
> its standardization is reserved as
> [RFC-AITP-0013](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0013-tct-renewal-extension.md),
> whose status is **Planned** (a non-normative stub). It is not part of v0.2
> conformance. In `aitp-rs` it is off by default:
>
> - `aitp-tct` — `build_renewal_request` / `process_renewal_request` behind
>   `experimental-renewal`.
> - `aitp-transport-http` — the renewal route on `HandshakeServer`, mounted
>   at the path of the Manifest's advertised `rfc-aitp-0005.renew_uri`,
>   behind its own `experimental-renewal`.
> - `aitp` facade — `experimental-renewal` turns on both of the above and
>   the client driver `aitp::facade::renew_tct`.
> - Language bindings — their own `renewal` feature (on by default), which
>   enables `aitp-tct/experimental-renewal` only.
>
> No wire-stability promise until RFC-AITP-0013 is written.

What the spec asks of an implementation that offers renewal (advertise
`rfc-aitp-0005.renew_uri`, no probing, current TCT unexpired, re-evaluate
grant policy and revocation) is summarised in the spec's operational guide,
[Shortened renewal](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/docs/operational-guidance.md#shortened-renewal-opt-in-not-part-of-v02-conformance).
This page describes what `aitp-rs` does; see also
[Known limitations](#known-limitations).

## Motivation

A TCT is short-lived (bounded by the issuer's Manifest validity). Before it
expires, the holder needs a fresh one. Replaying the full Mutual Handshake
repeats identity work already encoded in the existing TCT's `sub` + `cnf`.
Renewal is a **shortened exchange**: the holder presents the existing TCT
plus a proof of possession, and the issuer mints a fresh TCT and grant
voucher for the same subject and grants.

## Wire format

TCTs cross this exchange as opaque compact JWS strings (RFC-AITP-0001 §5.4.5).

Request (`TctRenewalPayload`, `deny_unknown_fields`):

```json
{
  "current_tct":   "<compact JWS string — the TCT being renewed>",
  "pop_nonce":     "<base64url nonce chosen by the holder>",
  "pop_signature": "<sign(holder_key, sha256(base64url_decode(pop_nonce)))>"
}
```

The holder signs `sha256(decoded_nonce_bytes)` with the key encoded in the
TCT's `sub` AID (the key `cnf.jkt` binds). `pop_nonce` MUST decode to
exactly 16 bytes (22 base64url characters, RFC-AITP-0004 §8.1); the SDKs
and `renew_tct` draw a fresh random one per request.

Response from the renewal route:

```json
{
  "tct":           "<compact JWS string — the fresh TCT>",
  "grant_voucher": "<compact JWS string — re-minted voucher>"
}
```

## Endpoint discovery (`renew_uri`)

The issuer advertises its renewal endpoint as the Manifest extension
`rfc-aitp-0005.renew_uri` (`aitp_transport_http::RENEW_URI_EXT`), an
absolute HTTPS URL (`http` is accepted only for `localhost` /
`127.0.0.1`, for development). Because the Manifest is signed, the
extension is set when the Manifest is built:

```rust
let manifest = ManifestBuilder::new(&key)
    // ...
    .extension(RENEW_URI_EXT, "https://issuer.example/aitp/renew".into())
    .build()?;
```

- **Server.** `HandshakeServer::router()` mounts the renewal route at the
  path of that URL, and only then. A Manifest without a usable
  `renew_uri` gets no renewal route.
- **Client.** `aitp::facade::renew_tct(holder, current, &issuer_manifest)`
  reads the extension from the issuer's (verified) Manifest and POSTs
  there. With no usable `renew_uri` it fails with
  `FacadeError::RenewalNotAdvertised` before sending anything: per
  RFC-AITP-0004 §8.1 the holder MUST NOT probe a guessed path and falls
  back to a full handshake.

## Issuer side (`process_renewal_request`)

`process_renewal_request(request, issuer_key, &RenewalContext)` is async
(the replay guard is a pluggable `NonceStore`). `RenewalContext` carries
the issuer's current Manifest expiry, the grants it offers now, a
revocation check, the replay-guard store, an optional grant-policy hook,
the new TTL and whether to mint a voucher. Checks run in this order:

1. **`pop_nonce` shape.** Must decode to 16 bytes → else
   `RenewalNonceMalformed`.
2. **Strict parse of `current_tct`.** Duplicate-key and claim-set checks on
   the still-unverified payload → `ClaimsMalformed` / `UnknownField`.
3. **Verify `current_tct`** with `verify_tct` under the issuer's own AID
   and the token's own `aud`: `typ`, AID-pinned `alg`, signature, claims,
   `exp` (→ `Expired`), the caller's **revocation check** (→ `Revoked`;
   renewal is not a revocation bypass, RFC-AITP-0004 §8.1) and the issuer's
   current Manifest expiry (→ `ExpiresAfterManifest`).
4. **PoP.** `pop_signature` must verify over `sha256(decode(pop_nonce))`
   under the key in `sub` (Ed25519 or P-256) → else `PopFailed`.
5. **Issuer Manifest window.** `manifest_expires_at > now` → else `Expired`;
   effective TTL `min(ttl, manifest_expires_at − now)` must be positive.
6. **Replay guard.** The nonce is recorded in the `NonceStore`
   (`aitp_core::nonce_store`, the same store the handshake admission path
   uses) until the presented TCT's `exp`. A nonce already recorded →
   `RenewalReplayed`. Recording happens only after the checks above pass,
   so an observer cannot burn a holder's nonce or fill the store with
   unauthenticated requests. A store failure → `RenewalNonceStore`.
7. **Grant re-evaluation** (RFC-AITP-0004 §8.1). The old grants are
   intersected with the grants the issuer offers now, then passed through
   the optional policy hook. Withdrawn grants are dropped; if none
   survive → `RenewalGrantsWithdrawn`.
8. **Mint** with `TctBuilder`: same `sub` and `aud`, the surviving grants,
   `cnf` bound to the same key, new random `jti`, `iat = now`,
   `exp = now + effective TTL` (the RFC-AITP-0004 §4.3 bound). A grant
   voucher is re-minted by default (`RenewalContext::without_voucher`
   turns it off), with `src_jti` = the new `jti`; vouchers bound to the
   old `jti` do not transfer.

The fresh TCT verifies under the normal `verify_tct` path. The facade's
`renew_tct` does not verify it for you; verify before storing.

## Server (`HandshakeServer`)

The renewal route applies the server's per-source rate limit and checks
the content type, then runs `process_renewal_request` with:

- revocation from the attached `RevocationListProducer`'s current list
  (none attached means nothing is revoked);
- grants from the server Manifest's `offered_capabilities`, plus the
  optional `with_renewal_grant_policy` hook;
- an in-memory replay guard by default, replaceable with
  `with_renewal_nonce_store` (use a shared store when several replicas
  serve one issuer);
- TTL `aitp_tct::DEFAULT_TCT_TTL_SECS`, capped by the Manifest window.

Each failure maps to its own registry code:

| Failure | Code |
|---|---|
| replayed `pop_nonce` | `REPLAY_DETECTED` |
| malformed nonce, malformed TCT or claims, not a JWS, bad JSON | `INVALID_ENVELOPE` |
| unknown request member or claim | `UNKNOWN_FIELD` |
| unknown `ver` | `UNKNOWN_VERSION` |
| revoked TCT | `TCT_REVOKED` |
| expired TCT | `TCT_EXPIRED` |
| TCT outlives the issuer's current Manifest | `TCT_EXPIRES_AFTER_MANIFEST` |
| PoP signature does not verify | `POP_RESPONSE_INVALID` |
| no grant survives re-evaluation | `POLICY_VIOLATION` |
| `aud` mismatch | `AUDIENCE_MISMATCH` |
| `alg` / `typ` mismatch | `TOKEN_ALG_MISMATCH` / `TOKEN_TYP_MISMATCH` |
| any other verification failure (e.g. another issuer's TCT) | `TCT_SIGNATURE_INVALID` |
| replay guard full (local) | HTTP 503 |

## Known limitations

- **Same subject, narrower-or-equal grants only.** Renewal cannot widen
  scope or rebind to a new key; those need a fresh handshake (or
  delegation).
- **Issuer key-rotation boundary.** If the issuer's Manifest has expired,
  renewal fails closed and the holder must re-handshake.
- **Default replay guard is per process.** It is bounded and in memory; a
  multi-replica deployment needs a shared `NonceStore`.
- **Binding replay guard.** The Python and Node bindings keep one
  process-wide in-memory replay guard shared by every agent.

## SDK example (holder ↔ issuer, Python)

```python
import json

# Holder side: build the renewal request bound to a fresh nonce.
# current_tct is the holder's TCT as a compact JWS string. Pass it
# positionally (the keyword name differs between aitp.pyi and the binding, #199).
req_json = holder_agent.build_renewal_request(current_tct)

# Issuer side: verify PoP + mint a fresh TCT (bounded by the issuer manifest).
# The issuer must have called build_manifest(): grants it no longer offers
# are dropped. A revoked jti or a replayed request raises RuntimeError.
# Returns a JSON string: {"tct": "<jws>", "grant_voucher": "<jws>"}.
result = json.loads(
    issuer_agent.process_renewal_request(
        req_json, manifest_exp_unix_secs, new_ttl_secs, revoked_jtis=revoked
    )
)
fresh_tct = result["tct"]
```

In Node, `processRenewalRequest(...)` returns the fresh TCT as a bare compact
JWS string, with no voucher
([#199](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/199)).

`bindings/aitp-py/tests/test_renewal.py` covers the holder → issuer
round-trip and rejection of a wrong holder key, a replayed request, a
revoked TCT and withdrawn grants; `bindings/aitp-node/tests/test_renewal.mjs`
covers the same in Node.
