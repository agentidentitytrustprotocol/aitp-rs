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
> - `aitp-transport-http` — the `/aitp/handshake/renew` route on
>   `HandshakeServer` behind its own `experimental-renewal`.
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
This page describes what `aitp-rs` does, including where it falls short of
that — see [Known limitations](#known-limitations).

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
TCT's `sub` AID (the key `cnf.jkt` binds). The SDKs and `renew_tct` generate
a fresh random 16-byte nonce (22 base64url characters); the issuer does not
check the length.

Response from the `/aitp/handshake/renew` route:

```json
{
  "tct":           "<compact JWS string — the fresh TCT>",
  "grant_voucher": "<compact JWS string — re-minted voucher>"
}
```

`grant_voucher` is always present in practice: renewal always mints one (see
below). The route path is the RFC's illustrative one; `renew_tct` reaches it
by joining `renew` onto the peer's `handshake_endpoint` URL, so that URL
needs a trailing slash (`…/aitp/handshake/`).

## Issuer side (`process_renewal_request`)

`crates/aitp-tct/src/renewal.rs:70-150`, in order:

1. **Strict parse of `current_tct`.** Duplicate-key and claim-set checks on
   the still-unverified payload → `ClaimsMalformed` / `UnknownField`.
2. **Verify `current_tct`** with `verify_tct` under the issuer's own AID and
   the token's own `aud`, using `TctVerifyContext::permissive_at` —
   `typ`, AID-pinned `alg`, signature, claims, and `exp` (an expired TCT
   fails with `Expired`). **No revocation check and no Manifest-expiry cap**
   (see *Known limitations*).
3. **PoP.** `pop_signature` must verify over `sha256(decode(pop_nonce))`
   under the key in `sub` (Ed25519 or P-256) → else `SignatureInvalid`.
4. **Issuer Manifest window.** `manifest_expires_at > now` → else `Expired`;
   effective TTL `min(ttl, manifest_expires_at − now)` must be positive.
5. **Mint** with `TctBuilder`: same `sub`, `aud` and `grants` (copied
   unchanged), `cnf` bound to the same key, new random `jti`, `iat = now`,
   `exp = now + effective TTL` (the RFC-AITP-0004 §4.3 bound). The builder
   mints a companion grant voucher by default, so a voucher is **always**
   re-minted, with `src_jti` = the new `jti`; vouchers bound to the old
   `jti` do not transfer.

The fresh TCT verifies under the normal `verify_tct` path. The facade's
`renew_tct` does not verify it for you; verify before storing.

## Known limitations

These are tracked in
[#196](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/196).
Treat the renew endpoint as unsuitable for untrusted networks until it is
fixed.

- **Captured requests can be replayed.** `pop_nonce` is chosen by the holder
  and is never recorded: `process_renewal_request` (`renewal.rs:125-131`)
  checks only that the signature over it verifies, and the server's
  `handle_renew` (`crates/aitp-transport-http/src/server.rs:563-613`) does
  not pass the request through the replay guard, rate limiter or timestamp
  check that guard the handshake routes (those run in
  `enforce_envelope_boundary_checks`, called only from hello and commit,
  `server.rs:645, 788`). Anyone who captures one valid request can re-POST
  it until the presented TCT expires and receive a fresh TCT and grant
  voucher each time. Each fresh TCT is bound to the holder's key, so a
  replayer cannot use it without that key, but nothing limits how many are
  minted.
- **No revocation or grant-policy re-evaluation.** The old TCT is checked
  with `TctVerifyContext::permissive_at` (`renewal.rs:118`), which skips the
  revocation check, and grants are copied unchanged (`renewal.rs:141-149`).
  RFC-AITP-0004 §8.1 says the issuer MUST re-evaluate its grant policy and
  that renewal is not a bypass for revocation; a revoked TCT that has not
  expired can therefore still be renewed. §8.1 is titled non-normative, so
  this is a divergence from the spec's stated requirement rather than a
  conformance failure — but it is security-relevant: do not mount the route
  where a revoked-but-unexpired TCT must not be renewable.
- **Voucher always minted.** There is no policy input; the voucher comes
  from `TctBuilder`'s default (`crates/aitp-tct/src/builder.rs:46`). The
  spec re-mints it only "per issuer policy" (RFC-AITP-0004 §8.1).
- **`renew_uri` is neither advertised nor read.** Nothing in the crates puts
  `rfc-aitp-0005.renew_uri` into a Manifest, and `renew_tct` guesses the path
  with `join("renew")` (`crates/aitp/src/facade.rs:800`). RFC-AITP-0004 §8.1
  says peers MUST advertise the concrete endpoint and MUST NOT probe a
  guessed path.
- **Server error mapping and TTL.** `handle_renew` maps every
  `process_renewal_request` failure, including an expired TCT, to
  `TCT_SIGNATURE_INVALID` (`server.rs:602`); an unknown request member is
  `UNKNOWN_FIELD` and malformed JSON is `INVALID_ENVELOPE`. The new TTL is
  fixed at `aitp_tct::DEFAULT_TCT_TTL_SECS`, capped by the Manifest window.
- **Same subject and grants only.** Renewal cannot widen scope or rebind to a
  new key; those need a fresh handshake (or delegation).
- **Issuer key-rotation boundary.** If the issuer's Manifest has expired,
  renewal fails closed and the holder must re-handshake.

## SDK example (holder ↔ issuer, Python)

```python
import json

# Holder side: build the renewal request bound to a fresh nonce.
# current_tct is the holder's TCT as a compact JWS string. Pass it
# positionally (the keyword name differs between aitp.pyi and the binding, #199).
req_json = holder_agent.build_renewal_request(current_tct)

# Issuer side: verify PoP + mint a fresh TCT (bounded by the issuer manifest).
# Returns a JSON string: {"tct": "<jws>", "grant_voucher": "<jws>"}.
result = json.loads(
    issuer_agent.process_renewal_request(req_json, manifest_exp_unix_secs, new_ttl_secs)
)
fresh_tct = result["tct"]
```

In Node, `processRenewalRequest(...)` returns the fresh TCT as a bare compact
JWS string, with no voucher
([#199](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/199)).

`bindings/aitp-py/tests/test_renewal.py` covers the holder → issuer
round-trip and the wrong-holder-key rejection; `bindings/aitp-node/tests/test_renewal.mjs`
covers the same in Node.
