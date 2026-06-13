// Stock-JOSE acceptance check (Node) — the headline property of the
// v0.2 compact-JWS migration, proven against the third-party `jose`
// library (NOT the aitp bindings).
//
// A v0.2 TCT / grant voucher / delegation token is an RFC 7515 compact
// JWS; any off-the-shelf JOSE library verifies one given only the
// issuer's public key (RFC-AITP-0001 §5.4.5). The issuer AID's
// identifier is the unpadded-base64url raw Ed25519 public key
// (RFC-AITP-0001 §5.3), so the verifying key comes from the token's
// `iss` claim alone.
//
// Runs standalone (no native binding, no napi build):
//   node --experimental-vm-modules stock_jose_acceptance.mjs
// `jose` is resolved from the sibling aitp-node/node_modules.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { createRequire } from "node:module";

const __dirname = dirname(fileURLToPath(import.meta.url));
// `jose` is vendored under the Node binding's node_modules.
const require = createRequire(join(__dirname, "..", "aitp-node", "package.json"));
const jose = await import(require.resolve("jose"));

const SIGNED_EXAMPLES = join(
  __dirname, "..", "..", "tests", "schemas", "known-answer", "signed-examples",
);

const VECTORS = {
  tct: ["tct/kat-keypair-001-issues-002.json", "tct_token", "aitp-tct+jwt"],
  voucher: ["grant-voucher/kat-voucher-001.json", "voucher_token", "aitp-grant+jwt"],
  delegation: ["delegation/single-hop-001-002-003.json", "delegation_token", "aitp-delegation+jwt"],
};

function load(kind) {
  const [rel, field, typ] = VECTORS[kind];
  const vec = JSON.parse(readFileSync(join(SIGNED_EXAMPLES, rel), "utf8"));
  return { token: vec[field], claims: vec.decoded_claims, typ };
}

// Import the Ed25519 verifying key from an `aid:pubkey:<b64url>` AID as
// an OKP JWK — exactly what a JOSE-generic verifier does.
async function issuerKey(issAid) {
  const prefix = "aid:pubkey:";
  if (!issAid.startsWith(prefix)) throw new Error(`unexpected AID: ${issAid}`);
  const x = issAid.slice(prefix.length); // already unpadded base64url
  return jose.importJWK({ kty: "OKP", crv: "Ed25519", x }, "EdDSA");
}

async function verifyWithJose(kind) {
  const { token, claims, typ } = load(kind);
  const key = await issuerKey(claims.iss);
  // jose does the real work: split, header parse, EdDSA verify over the
  // transmitted bytes, and `typ` enforcement.
  const { payload, protectedHeader } = await jose.compactVerify(token, key);
  if (protectedHeader.alg !== "EdDSA" || protectedHeader.typ !== typ) {
    throw new Error(`${kind}: unexpected header ${JSON.stringify(protectedHeader)}`);
  }
  const decoded = JSON.parse(new TextDecoder().decode(payload));
  // Compare order-independently: the on-wire payload is JCS-sorted,
  // the vector is in authoring order, but they are the same object.
  const canon = (v) =>
    JSON.stringify(v, Object.keys(JSON.parse(JSON.stringify(v))).sort
      ? (_k, val) =>
          val && typeof val === "object" && !Array.isArray(val)
            ? Object.fromEntries(Object.entries(val).sort(([a], [b]) => a.localeCompare(b)))
            : val
      : undefined);
  if (canon(decoded) !== canon(claims)) {
    throw new Error(`${kind}: jose claims diverge from vector`);
  }
  return decoded;
}

async function algNoneRejected() {
  const { token, claims, typ } = load("tct");
  const rest = token.slice(token.indexOf(".") + 1);
  const evilHeader = Buffer.from(JSON.stringify({ alg: "none", typ }))
    .toString("base64url");
  const evil = `${evilHeader}.${rest}`;
  const key = await issuerKey(claims.iss);
  try {
    await jose.compactVerify(evil, key);
  } catch {
    return; // rejected — correct
  }
  throw new Error("stock jose accepted an alg:none token");
}

let failed = false;
for (const kind of Object.keys(VECTORS)) {
  try {
    const c = await verifyWithJose(kind);
    console.log(`  jose verified ${kind.padEnd(11)} iss=${c.iss}`);
  } catch (e) {
    failed = true;
    console.error(`  jose FAILED ${kind}: ${e.message}`);
  }
}
try {
  await algNoneRejected();
  console.log("  jose rejected alg:none");
} catch (e) {
  failed = true;
  console.error(`  ${e.message}`);
}
console.log(failed ? "stock-JOSE (jose) acceptance: FAIL" : "stock-JOSE (jose) acceptance: OK");
process.exit(failed ? 1 : 0);
