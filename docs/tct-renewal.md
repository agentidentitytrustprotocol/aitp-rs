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
the existing TCT's `sub` + `cnf`. Renewal is a **shortened exchange**: the
holder presents the existing TCT plus a proof-of-possession, and the issuer
mints a fresh TCT (and, if policy permits delegation, a re-minted grant
voucher) for the same subject/grants.

## Wire format

Under the v0.2 Compact JWS profile (RFC-AITP-0001 §5.4.5), TCTs cross this
exchange as **opaque compact JWS strings**, not JSON objects.

Renewal request payload (`TctRenewalPayload`):

```json
{
  "current_tct":   "<compact JWS string — the TCT being renewed>",
  "pop_nonce":     "<22-char base64url, fresh>",
  "pop_signature": "<sign(holder_key, sha256(base64url_decode(pop_nonce)))>"
}
```

The PoP construction is identical to the handshake's pinned-key proof: the
holder signs `sha256(decoded_nonce_bytes)` with its long-term key — the key
identified by the existing TCT's `cnf.jkt` (and encoded in its `sub` AID). This
proves the request comes from the same holder that originally received the TCT,
without re-establishing identity from scratch.

The high-level `aitp::renew_tct` POSTs this payload to the peer's
`/aitp/handshake/renew` endpoint. The renewal **response** carries the
replacement TCT as a compact JWS string, plus the re-minted grant voucher when
the issuer permits the subject to delegate:

```json
{
  "tct":           "<compact JWS string — the fresh TCT>",
  "grant_voucher": "<compact JWS string — re-minted voucher, omitted if delegation disallowed>"
}
```

## Verification algorithm (`process_renewal_request`, issuer side)

1. **Verify `current_tct`** under the issuer's own AID (`verify_tct` with
   `expected_audience = current_tct.aud`). The TCT is parsed as a compact JWS
   over its transmitted bytes — `typ == aitp-tct+jwt`, AID-pinned `alg`. The
   issuer only renews TCTs it itself issued.
2. **PoP check.** Resolve the subject key from the TCT's `sub` AID
   (algorithm-agile: Ed25519 or P-256), confirm it matches `cnf.jkt`, then
   verify `pop_signature` over `sha256(decode(pop_nonce))` under that key.
   Failure ⇒ `SignatureInvalid`.
3. **Issuer Manifest still valid.** `manifest_expires_at > now`, else `Expired`
   — a holder cannot renew across an issuer key-rotation boundary.
4. **Mint.** Build a fresh TCT with: same `sub` / `aud` / `grants` / `cnf`;
   **new random `jti`**; `iat = now`; `exp = min(now + ttl, manifest_expires_at)`
   — the same upper bound the original handshake applied (RFC-AITP-0004 §4.3).
   `effective_ttl <= 0` ⇒ `Expired`. A companion grant voucher is **re-minted**
   with the new `src_jti` (the fresh `jti`); vouchers bound to the old TCT's
   `jti` do not transfer.

The fresh TCT is otherwise indistinguishable from a handshake-issued one and
verifies under the normal `verify_tct` path.

## Known limitations

- **Same subject/grants only.** Renewal cannot widen scope or rebind to a new
  key — those require a fresh handshake (or delegation).
- **Issuer key-rotation boundary.** If the issuer's Manifest has expired,
  renewal fails closed; the holder must re-handshake.
- Draft / opt-in: gated by `experimental-renewal`, excluded from the v0.2
  conformance gate.

## SDK example (holder Python ↔ issuer)

```python
# Holder side: build the renewal request bound to a fresh nonce.
# current_tct is the holder's TCT as a compact JWS string.
req_json = holder_agent.build_renewal_request(current_tct)  # experimental-renewal

# Issuer side: verify PoP + mint a fresh TCT (bounded by the issuer manifest).
# Returns {"tct": "<jws>", "grant_voucher": "<jws>"?}.
result = issuer_agent.process_renewal_request(
    req_json, manifest_exp_unix_secs, new_ttl_secs,
)
fresh_tct = result["tct"]
```

The `bindings/aitp-py/tests/test_renewal.py` (and `.mjs`) suites cover the full
holder → issuer round-trip plus the wrong-holder-key rejection.
