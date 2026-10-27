# TCT renewal (RFC-AITP-0013)

> **Status: opt-in, tracks a Draft RFC.**
> [RFC-AITP-0013](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0013-tct-renewal-extension.md)
> is **Draft**. It is not part of v0.3 core conformance; its fixtures
> (`ren-*`) carry the runner feature `experimental-renewal`. In `aitp-rs`
> it lives in the `aitp-experimental` crate, module
> `aitp_experimental::renewal`:
>
> - The core (request, PoP input, issuer checks, holder checks, envelopes)
>   needs no feature.
> - `RenewalServer`, the issuer's HTTP endpoint, needs feature
>   `http-server`.
> - `renew_tct`, the holder's HTTP client, needs feature `http-client`.
> - Language bindings: their own `renewal` feature (on by default), which
>   depends on `aitp-experimental`.
>
> No stability promise (STABILITY.md).

A holder renews its TCT by presenting it, with a proof of possession of the
subject key, to the issuer that issued it. The issuer mints a TCT for the
same `sub`, `aud` and `cnf` with a new `jti`. This page describes what
`aitp-rs` does; see also [Known limitations](#known-limitations).

## Wire format

TCTs cross this exchange as opaque compact JWS strings (RFC-AITP-0001 §5.4.5).

### Request

The body of a `POST` to `renew_uri` is an unenveloped JSON object with
exactly these members (`TctRenewalPayload`; `parse_renewal_request`):

```json
{
  "current_tct":   "<compact JWS string: the TCT being renewed>",
  "pop_nonce":     "<22 base64url characters: 16 fresh random bytes>",
  "pop_signature": "<sign(holder_key, sha256(renewal_pop_input))>"
}
```

The PoP input (`renewal_pop_input`, RFC-AITP-0013 §3.1) is

```text
"aitp-renewal-pop-v1" || 0x00 || iss || 0x00 || jti || 0x00 || nonce
```

where `iss` and `jti` are the current TCT's claims exactly as written and
`nonce` is the 16 decoded bytes of `pop_nonce`. The holder signs
`sha256` of it once, with the key encoded in the TCT's `sub`, in the
RFC-AITP-0001 §5.4.6 form (`p256.`-tagged for P-256). The SDKs and
`renew_tct` draw a fresh nonce per request.

### Response

Every answer is an RFC-AITP-0001 envelope signed by the issuer, whose
`sender.agent_id` is the current TCT's `iss`:

- success: `message_type` `tct`, status 200, payload
  (`RenewalResponsePayload`, built by `renewal_response_envelope`):

  ```json
  {
    "tct":            "<compact JWS string: the renewed TCT>",
    "grant_voucher":  "<compact JWS string, when minted>",
    "pop_nonce_echo": "<the request's pop_nonce>"
  }
  ```

- refusal: `message_type` `error`, status 4xx (503 when retryable),
  payload `{code, reason, retryable}` (RFC-AITP-0001 §5.6), built by
  `renewal_error_envelope`.

## Endpoint discovery (`renew_uri`)

The issuer advertises its renewal endpoint as the Manifest extension
`rfc-aitp-0005.renew_uri` (`RENEW_URI_EXT`), an
absolute HTTPS URL (`http` is accepted only for `localhost` /
`127.0.0.1`, for development). Because the Manifest is signed, the
extension is set when the Manifest is built:

```rust
let manifest = ManifestBuilder::new(&key)
    // ...
    .extension(RENEW_URI_EXT, "https://issuer.example/aitp/renew".into())
    .build()?;
```

- **Server.** `RenewalServer::router()` mounts the renewal route at the
  path of that URL. A Manifest without a usable `renew_uri` is
  `RenewalServerError::NotAdvertised`; a path another AITP route uses is
  `RenewalServerError::PathCollision`.
- **Client.** `renew_tct(holder, current, &issuer_manifest)`
  reads the extension from the issuer's (verified) Manifest and POSTs
  there. It uses only an `https` `renew_uri`; for a plain-`http`
  loopback one in local development, call
  `renew_tct_with_insecure_localhost` instead (never in production). With no usable `renew_uri` it fails with
  `RenewClientError::NotAdvertised` before sending anything: per
  RFC-AITP-0013 §2 the holder MUST NOT probe a guessed path and falls
  back to a full handshake.

## Issuer side (`process_renewal_request`)

`parse_renewal_request(body)` parses the request (RFC-AITP-0013 §4 step
1). `process_renewal_request(request, issuer_key, &RenewalContext)` is
async (the replay guard is a pluggable `NonceStore`). `RenewalContext`
carries the issuer's current Manifest expiry, the grants it offers now, a
revocation check, the replay-guard store, an optional grant-policy hook,
the new TTL and whether to mint a voucher. The steps run in this order
(RFC-AITP-0013 §4) and stop at the first failure:

1. **Parse.** The body is an object with exactly the three string
   members, no repeated key (`RenewalError::RequestMalformed`), and
   `pop_nonce` decodes to 16 bytes (`RenewalError::NonceMalformed`).
2. **Verify `current_tct` as its issuer** with `verify_tct` (failures are
   `RenewalError::Tct`): `typ`, `alg`,
   signature under the issuer's own key, claims, `exp` (`Expired`) and the
   issuer's current Manifest expiry (`ExpiresAfterManifest`). Its `aud`
   must equal its `sub` (`AudienceMismatch`).
3. **PoP.** `pop_signature` verifies under the `sub` key over
   `renewal_pop_input`, rebuilt from the verified `iss` and `jti`
   (`PopFailed`).
4. **Revocation.** The `jti` is not in the issuer's deny list (`Revoked`).
5. **Replay guard.** The nonce is recorded in the `NonceStore`
   (`aitp::core::nonce_store`) until the presented TCT's `exp`; a nonce
   already recorded is `RenewalError::Replayed`. A store failure is
   `RenewalError::NonceStore`.
6. **Grants.** The current grants intersected with the grants the issuer
   offers now, then narrowed by the optional policy hook. A grant the hook
   returns outside its input is dropped. None left is
   `RenewalError::GrantsWithdrawn`.
7. **Mint** with `TctBuilder`: same `iss`, `sub`, `aud` and `cnf`, the
   surviving grants, a new random `jti`, `iat = now`,
   `exp = min(now + ttl, Manifest expires_at)`.
8. **Voucher.** A grant voucher is minted by default
   (`RenewalContext::without_voucher` turns it off), with `src_jti` = the
   new `jti`.

`RenewalError::error_code` gives each failure's registry code;
`RenewalError::is_local_fault` is true for the issuer's own nonce store
or signer failing.

## Holder side (`verify_renewal_response`)

`verify_renewal_response(&envelope, &RenewalResponseContext)` checks the
issuer's answer (RFC-AITP-0013 §6.1) before the renewed TCT is used:

1. The envelope timestamp is in the window, `message_type` is `tct` or
   `error`, and the signature verifies under `sender.agent_id`.
2. `sender.agent_id` is the current TCT's `iss` (`PEER_MISMATCH`). An
   `error` envelope that passes steps 1 and 2 is
   `RenewalResponseError::Refused` with the issuer's code.
3. `pop_nonce_echo` is the nonce sent (`NONCE_MISMATCH`).
4. The renewed TCT verifies with `verify_tct` as addressed to the holder,
   issued by the current TCT's `iss`, and within the issuer Manifest's
   `expires_at` when the context carries it.
5. Its `sub` is the holder and its `cnf.jkt` the current TCT's
   (`AUDIENCE_MISMATCH`).
6. Its grants are a subset of the current TCT's (`GRANT_OVERFLOW`).

`message_id` deduplication (RFC-AITP-0001 §5.5) is the caller's.
`renew_tct` runs this check, with the issuer Manifest's
`expires_at`, and returns the verified `RenewedTct`.

## Server (`RenewalServer`)

```rust
let renewal = RenewalServer::new(
    Arc::new(issuer_key),          // the Manifest's key
    manifest.clone(),
    revocation_producer.clone(),   // the same producer as the handshake server's
    Arc::new(InMemoryNonceStore::default()),
)?;
let app = handshake_server
    .into_router()                 // aitp feature `experimental-axum`
    .merge(ManifestServer::new(manifest).into_router())
    .merge(renewal.router()?);
axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
```

`RenewalServer::new` refuses a signer whose AID is not the Manifest's
`aid` (`RenewalServerError::KeyMismatch`). Each request is rate limited
per transport source, then the content type and body are checked, then
`process_renewal_request` runs with:

- revocation from the `RevocationListProducer`'s current list;
- grants from the Manifest's `offered_capabilities`, plus the optional
  `with_grant_policy` hook;
- the `NonceStore` passed to `new` as the replay guard (use a shared store
  when several replicas serve one issuer);
- TTL `aitp::tct::DEFAULT_TCT_TTL_SECS`, capped by the Manifest window.

Rate limiting:

- On by default with `RateLimitConfig::default()`; `with_rate_limit`
  replaces it and `without_rate_limit` turns it off. Only
  `requests_per_source_per_60s` and `trusted_proxies` apply.
- Its counters are its own, separate from the handshake server's.
- A rate-limited request gets HTTP 429 with an empty body.
- With the rate limit on, a request without a client address (a router
  served without `into_make_service_with_connect_info`) gets a retryable
  error envelope with HTTP 500.

The body limit is `DEFAULT_MAX_BODY_BYTES` (`with_request_body_limit`
changes it), read within `DEFAULT_BODY_READ_TIMEOUT`.

Each refusal is a signed `error` envelope carrying the failing step's
registry code:

| Failure | Code |
|---|---|
| request not exactly the three string members, repeated key, bad JSON, malformed nonce | `POP_RESPONSE_INVALID` |
| `current_tct` not a JWS, malformed claims | `INVALID_ENVELOPE` |
| unknown claim | `UNKNOWN_FIELD` |
| unknown `ver` | `UNKNOWN_VERSION` |
| another issuer's TCT, `aud` other than `sub`, bad signature, self-issued or attestation TCT | `TCT_SIGNATURE_INVALID` |
| `alg` / `typ` mismatch | `TOKEN_ALG_MISMATCH` / `TOKEN_TYP_MISMATCH` |
| expired TCT | `TCT_EXPIRED` |
| TCT outlives the issuer's current Manifest | `TCT_EXPIRES_AFTER_MANIFEST` |
| PoP signature does not verify under `sub` | `POP_RESPONSE_INVALID` |
| revoked TCT | `TCT_REVOKED` |
| replayed `pop_nonce` | `REPLAY_DETECTED` |
| no grant survives re-evaluation | `POLICY_VIOLATION` |
| wrong content type | `POP_RESPONSE_INVALID` |
| body over the limit, unreadable or too slow | `INVALID_ENVELOPE` |
| replay guard failure or full (local) | retryable error envelope, HTTP 500 / 503 |
| no client address with the rate limit on (local) | retryable error envelope, HTTP 500 |

## Known limitations

- **Same subject, narrower-or-equal grants only.** Renewal cannot widen
  scope or rebind to a new key; those need a fresh handshake (or
  delegation).
- **Issuer key-rotation boundary.** A TCT that outlives the issuer's
  current Manifest is refused (`TCT_EXPIRES_AFTER_MANIFEST`); the holder
  re-handshakes.
- **Default replay guard is per process.** It is bounded and in memory; a
  multi-replica deployment needs a shared `NonceStore`.
- **Binding replay guard.** The Python and Node bindings keep one
  process-wide in-memory replay guard shared by every agent.

## SDK example (holder ↔ issuer, Python)

```python
import json

# Holder side: build the renewal request bound to a fresh nonce.
# current_tct is the holder's TCT as a compact JWS string.
req_json = holder_agent.build_renewal_request(current_tct_token=current_tct)

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

In Node, `processRenewalRequest(...)` returns the same fields as an object,
`{ tct, grantVoucher }`.

`bindings/aitp-py/tests/test_renewal.py` covers the holder → issuer
round-trip and rejection of a wrong holder key, a replayed request, a
revoked TCT and withdrawn grants; `bindings/aitp-node/tests/test_renewal.mjs`
covers the same in Node.
