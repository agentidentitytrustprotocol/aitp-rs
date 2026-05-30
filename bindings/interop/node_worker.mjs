#!/usr/bin/env node
// AITP interop worker — Node.js side.
//
// A long-lived process speaking line-delimited JSON-RPC over
// stdin/stdout. The Python interop test suite (test_interop.py) spawns
// one of these and drives a real four-message AITP handshake where the
// Python end runs in-process and this worker plays the Node end. The
// worker only computes one side of each step; it never talks to the
// Python side directly — every wire message is relayed by the test.
//
// Protocol (one JSON object per line):
//   request : {"id": int, "method": str, "params": {...}}
//   response: {"id": int, "ok": true,  "result": {...}}
//           | {"id": int, "ok": false, "error": str}
//
// Handles (agents, initiator sessions, responder sessions) are integers
// into a per-process registry; they are opaque to the caller.

import { createInterface } from 'node:readline';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const mod = await import(
  pathToFileURL(join(here, '..', 'aitp-node', 'index.js')).href
);
const AitpAgent = mod.AitpAgent ?? mod.default?.AitpAgent;
const verifyDelegation = mod.verifyDelegation ?? mod.default?.verifyDelegation;
const verifyManifestJson = mod.verifyManifestJson ?? mod.default?.verifyManifestJson;
const JwksProvider = mod.JwksProvider ?? mod.default?.JwksProvider;
const SessionBundleBuilder =
  mod.SessionBundleBuilder ?? mod.default?.SessionBundleBuilder;
const verifySessionBundle =
  mod.verifySessionBundle ?? mod.default?.verifySessionBundle;
if (!AitpAgent) {
  throw new Error('aitp-node binding not built — run `npm run build:debug`');
}

// In-process Ed25519 OIDC JWT signer for cross-language tests. Each
// call to `mintJwtSync` mints a fresh JWT bound to the supplied nonce —
// the worker exposes this to Python so the Python side can issue mint
// calls during a Node-side handshake (and vice versa, via a Node-only
// closure used from process_hello / build_hello).
import {
  generateKeyPairSync,
  sign as cryptoSign,
  createHash,
} from 'node:crypto';
import { Buffer } from 'node:buffer';

function b64url(b) {
  return Buffer.from(b).toString('base64url');
}

const oidcIssuers = new Map(); // kid → { issuer, priv, jwk }

function makeOidcIssuer(issuerUrl, kid) {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const rawPub = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  const jwk = {
    kty: 'OKP',
    crv: 'Ed25519',
    x: b64url(rawPub),
    kid,
    alg: 'EdDSA',
    use: 'sig',
  };
  oidcIssuers.set(kid, { issuer: issuerUrl, priv: privateKey, jwk });
  return jwk;
}

function mintJwt(kid, { sub, aud, nonce, cnfJkt, now }) {
  const iss = oidcIssuers.get(kid);
  if (!iss) throw new Error(`unknown oidc kid: ${kid}`);
  const header = { alg: 'EdDSA', typ: 'JWT', kid };
  const payload = {
    iss: iss.issuer,
    sub,
    aud,
    iat: now,
    exp: now + 3600,
    nonce,
    cnf: { jkt: cnfJkt },
  };
  const h = b64url(JSON.stringify(header));
  const p = b64url(JSON.stringify(payload));
  const signingInput = Buffer.from(`${h}.${p}`);
  const sig = cryptoSign(null, signingInput, iss.priv);
  return `${h}.${p}.${b64url(sig)}`;
}

const registry = new Map();
let nextHandle = 0;
const store = (obj) => {
  const handle = nextHandle++;
  registry.set(handle, obj);
  return handle;
};

const methods = {
  ping: () => ({ sdk: 'aitp-node', version: '0.1.0' }),

  new_agent: (p) => {
    const suite = p.suite ?? 'ed25519';
    const opts = { suite };
    let agent;
    if (p.seed) {
      agent = AitpAgent.fromSeed(Buffer.from(p.seed), opts);
    } else {
      agent = AitpAgent.generate(opts);
    }
    return { handle: store(agent), aid: agent.aid };
  },

  build_manifest: (p) => ({
    manifest: registry.get(p.agent).buildManifest({
      displayName: p.display_name,
      handshakeEndpoint: p.handshake_endpoint,
      offeredCaps: p.offered_caps,
    }),
  }),

  new_session: (p) => ({ handle: store(registry.get(p.agent).newSession()) }),

  new_responder: (p) => ({
    handle: store(registry.get(p.agent).newResponder()),
  }),

  build_hello: (p) => ({
    hello: registry
      .get(p.session)
      .buildHello(p.peer_manifest, p.requested_grants),
  }),

  process_hello: (p) => {
    const { ackJson, sessionId } = registry
      .get(p.responder)
      .processHello(p.hello);
    return { hello_ack: ackJson, session_id: sessionId };
  },

  process_hello_ack: (p) => ({
    commit: registry
      .get(p.session)
      .processHelloAck(p.hello_ack, p.session_id),
  }),

  process_commit: (p) => {
    const { ackJson, tctJson } = registry
      .get(p.responder)
      .processCommit(p.commit);
    return { commit_ack: ackJson, tct: tctJson };
  },

  complete: (p) => ({
    tct: registry.get(p.session).complete(p.commit_ack),
  }),

  verify_tct: (p) => {
    const ident = registry
      .get(p.agent)
      .verifyTct(p.tct, p.required_grant, p.expected_audience ?? undefined);
    return {
      peer_aid: ident.peerAid,
      grants: ident.grants,
      expires_at: ident.expiresAt,
      jti: ident.jti,
    };
  },

  // ── A1 — delegation ───────────────────────────────────────────────
  build_delegation: (p) => ({
    delegation: registry.get(p.agent).buildDelegation(
      p.held_tct,
      p.delegatee_aid,
      p.delegatee_pubkey_b64u,
      p.scope,
      p.ttl_secs ?? null,
    ),
  }),

  verify_delegation: (p) => {
    const v = verifyDelegation(p.envelope, p.verifier_aid, p.max_hops ?? 0);
    return {
      delegator: v.delegator,
      delegatee: v.delegatee,
      issued_by: v.issuedBy,
      grants: v.grants,
      expires_at: v.expiresAt,
      cnf: v.cnf,
    };
  },

  issue_tct_for_delegatee: (p) => ({
    tct: registry.get(p.agent).issueTctForDelegatee(
      {
        delegator: p.verified.delegator,
        delegatee: p.verified.delegatee,
        issuedBy: p.verified.issued_by,
        grants: p.verified.grants,
        expiresAt: p.verified.expires_at,
        cnf: p.verified.cnf,
      },
      p.ttl_secs ?? null,
    ),
  }),

  // ── A3 — revocation list ──────────────────────────────────────────
  sign_revocation_list: (p) => ({
    envelope: registry.get(p.agent).signRevocationList(
      p.entries.map((e) => ({
        jti: e.jti,
        revokedAt: e.revoked_at ?? null,
        reason: e.reason ?? null,
      })),
      p.expires_in_secs ?? null,
    ),
  }),

  // ── A4 — manifest verify ──────────────────────────────────────────
  verify_manifest: (p) => {
    verifyManifestJson(p.manifest);
    return { ok: true };
  },

  // Helper to extract a peer's pubkey from its manifest (needed by A1).
  pubkey_from_manifest: (p) => {
    const env = JSON.parse(p.manifest);
    return { pubkey_b64u: env.manifest.identity_hint.public_key };
  },

  // ── B1 — OIDC interop ─────────────────────────────────────────────
  // Worker-side OIDC issuer: Python asks the worker to mint a JWK +
  // issuer keypair, hands the JWK to its own JwksProvider, and asks
  // the worker to mint JWTs on demand.
  make_oidc_issuer: (p) => ({ jwk: makeOidcIssuer(p.issuer, p.kid) }),

  mint_oidc_jwt: (p) => ({
    jwt: mintJwt(p.kid, {
      sub: p.sub,
      aud: p.aud,
      nonce: p.nonce,
      cnfJkt: p.cnf_jkt,
      now: p.now,
    }),
  }),

  // Node OIDC handshake methods — Python builds the manifest in OIDC
  // mode via the worker, drives a session with a JwksProvider seeded
  // from a worker-minted JWK, and supplies an oidc_mint_jwt that
  // delegates to mint_oidc_jwt.
  new_jwks_provider: (p) => {
    const keys = p.keys ?? {};
    return { handle: store(new JwksProvider(keys)) };
  },

  build_manifest_oidc: (p) => ({
    manifest: registry.get(p.agent).buildManifest({
      displayName: p.display_name,
      handshakeEndpoint: p.handshake_endpoint,
      offeredCaps: p.offered_caps,
      identityType: 'oidc',
      oidcIssuer: p.oidc_issuer,
      oidcSubject: p.oidc_subject,
    }),
  }),

  new_oidc_session: (p) => ({
    handle: store(registry.get(p.agent).newSession(registry.get(p.jwks))),
  }),

  new_oidc_responder: (p) => ({
    handle: store(registry.get(p.agent).newResponder(registry.get(p.jwks))),
  }),

  // Sync mint callback — the kid + claim template comes in once; for
  // each handshake-issued nonce the worker recomputes the JWT inline.
  build_hello_oidc: (p) => ({
    hello: registry.get(p.session).buildHello(
      p.peer_manifest,
      p.requested_grants,
      (nonce) =>
        mintJwt(p.mint_kid, {
          sub: p.mint_sub,
          aud: p.mint_aud,
          nonce,
          cnfJkt: p.mint_cnf_jkt,
          now: p.mint_now,
        }),
    ),
  }),

  process_hello_oidc: (p) => {
    const { ackJson, sessionId } = registry.get(p.responder).processHello(
      p.hello,
      (nonce) =>
        mintJwt(p.mint_kid, {
          sub: p.mint_sub,
          aud: p.mint_aud,
          nonce,
          cnfJkt: p.mint_cnf_jkt,
          now: p.mint_now,
        }),
    );
    return { hello_ack: ackJson, session_id: sessionId };
  },

  // Helper: compute the Ed25519 JWK thumbprint of an AID — needed for
  // the OIDC cnf.jkt binding.
  aid_jkt: (p) => {
    const prefix = 'aid:pubkey:ed25519:';
    const legacy = 'aid:pubkey:';
    const pkB64 = p.aid.startsWith(prefix)
      ? p.aid.slice(prefix.length)
      : p.aid.slice(legacy.length);
    const pk = Buffer.from(pkB64 + '==', 'base64url').subarray(0, 32);
    const canonical = JSON.stringify({
      crv: 'Ed25519',
      kty: 'OKP',
      x: b64url(pk),
    });
    return { jkt: b64url(createHash('sha256').update(canonical).digest()) };
  },

  // ── B4 — session bundle interop ───────────────────────────────────
  build_session_bundle: (p) => {
    const builder = new SessionBundleBuilder(registry.get(p.coordinator));
    for (const part of p.participants) {
      builder.participant(part.aid, part.tct);
    }
    return { envelope: builder.build() };
  },

  verify_session_bundle: (p) => {
    const outcome = verifySessionBundle(p.envelope, p.verifier_aid);
    return {
      kind: outcome.kind,
      active_aids: outcome.activeAids,
      dropped_aids: outcome.droppedAids,
    };
  },
};

const rl = createInterface({ input: process.stdin });
for await (const line of rl) {
  const trimmed = line.trim();
  if (!trimmed) continue;
  const req = JSON.parse(trimmed);
  let resp;
  try {
    const handler = methods[req.method];
    if (!handler) throw new Error(`unknown method: ${req.method}`);
    resp = { id: req.id, ok: true, result: handler(req.params ?? {}) };
  } catch (err) {
    resp = { id: req.id, ok: false, error: String(err?.message ?? err) };
  }
  process.stdout.write(JSON.stringify(resp) + '\n');
}
