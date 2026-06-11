# TCT renewal (RFC-AITP-0013)

> **Status: draft / opt-in.** The shortened renewal exchange is described
> non-normatively in [RFC-AITP-0004 §8.1](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0004-mutual-handshake.md)
> and will be standardized in
> [RFC-AITP-0013](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0013-tct-renewal-extension.md)
> (Planned). Implemented in `aitp-tct` under the `experimental-renewal`
> feature; the high-level driver `aitp::renew_tct` and the binding methods
> (`build_renewal_request` / `process_renewal_request`) ride the same flag.
> No wire-stability promise until ratified.

## Motivation

A TCT is short-lived (bounded by the issuer's Manifest validity). Before it
expires, the holder needs a fresh one — but replaying the full four-message
Mutual Handshake is wasteful: identity was already established and is encoded in
the existing TCT's `subject` + `binding.cnf`. Renewal is a **shortened
exchange**: the holder presents the existing TCT plus a proof-of-possession,
and the issuer mints a fresh TCT for the same subject/grants.

## Wire format

Renewal request payload (`TctRenewalPayload`):

```json
{
  "current_tct":   { "tct": { /* the TCT being renewed */ } },
  "pop_nonce":     "<22-char base64url, fresh>",
  "pop_signature": "<sign(holder_key, sha256(base64url_decode(pop_nonce)))>"
}
```

The PoP construction is identical to the handshake's pinned-key proof: the
holder signs `sha256(decoded_nonce_bytes)` with its long-term key — the key
bound by the existing TCT's `binding.cnf`. This proves the request comes from
the same holder that originally received the TCT, without re-establishing
identity from scratch.

The high-level `aitp::renew_tct` POSTs this payload to the peer's
`/aitp/handshake/renew` endpoint and returns the fresh `TctEnvelope`.

## Verification algorithm (`process_renewal_request`, issuer side)

1. **Verify `current_tct`** under the issuer's own AID (`verify_tct` with
   `expected_audience = current_tct.audience`). The issuer only renews TCTs it
   itself issued.
2. **PoP check.** Decode `binding.cnf` (algorithm-agile: 32 B Ed25519 raw or
   33 B SEC1-compressed P-256), then verify `pop_signature` over
   `sha256(decode(pop_nonce))` under that key. Failure ⇒ `SignatureInvalid`.
3. **Issuer Manifest still valid.** `manifest_expires_at > now`, else `Expired`
   — a holder cannot renew across an issuer key-rotation boundary.
4. **Mint.** Build a fresh `Tct` with: same `subject` / `audience` / `grants` /
   `cnf`; **new random `jti`**; `issued_at = now`; `expires_at = min(now + ttl,
   manifest_expires_at)` — the same upper bound the original handshake applied
   (RFC-AITP-0004 §4.3). `effective_ttl <= 0` ⇒ `Expired`.

The fresh TCT is otherwise indistinguishable from a handshake-issued one and
verifies under the normal `verify_tct` path.

## Known limitations

- **Same subject/grants only.** Renewal cannot widen scope or rebind to a new
  key — those require a fresh handshake (or delegation).
- **Issuer key-rotation boundary.** If the issuer's Manifest has expired,
  renewal fails closed; the holder must re-handshake.
- Draft / opt-in: gated by `experimental-renewal`, excluded from the v0.1
  conformance gate.

## SDK example (holder Python ↔ issuer)

```python
# Holder side: build the renewal request bound to a fresh nonce.
req_json = holder_agent.build_renewal_request(current_tct_json)  # experimental-renewal

# Issuer side: verify PoP + mint a fresh TCT (bounded by the issuer manifest).
fresh_tct_json = issuer_agent.process_renewal_request(
    req_json, manifest_exp_unix_secs, new_ttl_secs,
)
```

The `bindings/aitp-py/tests/test_renewal.py` (and `.mjs`) suites cover the full
holder → issuer round-trip plus the wrong-holder-key rejection.
