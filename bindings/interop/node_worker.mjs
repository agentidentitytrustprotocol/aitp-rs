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
if (!AitpAgent) {
  throw new Error('aitp-node binding not built — run `npm run build:debug`');
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
    const agent = p.seed
      ? AitpAgent.fromSeed(Buffer.from(p.seed))
      : AitpAgent.generate();
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
      .verifyTct(p.tct, p.required_grant);
    return {
      peer_aid: ident.peerAid,
      grants: ident.grants,
      expires_at: ident.expiresAt,
      jti: ident.jti,
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
