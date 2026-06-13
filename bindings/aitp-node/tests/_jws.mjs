// Tiny compact-JWS helpers for the Node SDK test suite.
//
// In AITP v0.2 TCTs, grant vouchers, and delegations are opaque compact
// JWS strings (`header.payload.signature`, all base64url). Tests that need
// to read a claim (e.g. `jti`) or tamper with the signature operate on
// these helpers rather than `JSON.parse` (which no longer works — the
// token is not JSON).

/** Decode the (unverified) claims payload of a compact JWS into an object. */
export function decodeJwsPayload(token) {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error(`not a compact JWS: ${parts.length} segments`);
  }
  const json = Buffer.from(parts[1], 'base64url').toString('utf8');
  return JSON.parse(json);
}

/**
 * Return a copy of `token` with its signature segment corrupted (first
 * base64url char flipped). The header/payload are untouched, so the token
 * still parses but fails signature verification.
 */
export function tamperJwsSignature(token) {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error(`not a compact JWS: ${parts.length} segments`);
  }
  const sig = parts[2];
  parts[2] = (sig[0] !== 'A' ? 'A' : 'B') + sig.slice(1);
  return parts.join('.');
}

/**
 * Return a copy of `token` with `claims` merged into its (unverified)
 * payload, re-encoded. The header and (now-stale) signature are kept
 * verbatim — the result is structurally a JWS but its signature no longer
 * covers the mutated payload. Useful for exercising verifier gates that
 * fire on a claim *before* the signature check (e.g. the multi-hop
 * `chain` gate).
 */
export function withClaims(token, claims) {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error(`not a compact JWS: ${parts.length} segments`);
  }
  const payload = { ...decodeJwsPayload(token), ...claims };
  parts[1] = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  return parts.join('.');
}
