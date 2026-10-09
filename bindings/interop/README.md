# AITP cross-language interop tests

These tests prove that the **Python** (`aitp-py`) and **Node**
(`aitp-node`) bindings produce wire-compatible AITP artifacts. They exchange
real handshake messages and tokens *between the two language runtimes*. A
second check confirms that the compact-JWS tokens verify under stock,
third-party JOSE libraries.

## What it does

`test_interop.py` runs the two ends of each exchange in different runtimes:

- the **Python** end runs in-process via the `aitp` extension;
- the **Node** end runs in a `node` subprocess (`node_worker.mjs`),
  driven over line-delimited JSON-RPC on stdin/stdout.

Each artifact one binding produces is fed straight into the other. The tests
cover:

| Test | What crosses the language boundary |
|---|---|
| `test_python_initiator_node_responder` | Python HELLO → Node responder → mutual TCTs |
| `test_node_initiator_python_responder` | Node HELLO → Python responder → mutual TCTs |
| `test_node_rejects_python_issued_tct_for_missing_grant` | Python-issued TCT rejected by Node for an ungranted capability |
| `test_python_rejects_node_issued_tct_for_missing_grant` | Node-issued TCT rejected by Python for an ungranted capability |
| `test_node_presented_tct_verifies_via_python_audience` | presented-TCT model: Node-held TCT verified by Python with `expected_audience` |
| `test_python_presented_tct_verifies_via_node_audience` | presented-TCT model, reverse direction |
| `test_delegation_python_issuer_node_chain` | grant voucher → delegation token → delegatee TCT across both bindings |
| `test_python_revocation_list_parses_on_node` | Python-signed revocation snapshot parsed by Node (wire shape only; the signature is not verified here) |
| `test_python_manifest_verifies_on_node` | manifests built by each binding verify in the other |
| `test_oidc_python_initiator_node_responder` | OIDC-identity handshake (RFC-AITP-0002) across bindings |
| `test_session_bundle_python_coordinator_node_verifier` | Python-built session bundle verified by Node |
| `test_p256_aid_minted_by_python_recognised_by_node` | the same seed yields the same P-256 AID in both bindings |
| `test_p256_handshake_via_oidc_python_to_node` | P-256 Python initiator ↔ Ed25519 Node responder, OIDC identity |

If both directions pass, the two SDKs canonicalize, sign and verify
identically.

Every test skips if `node` is not on `PATH`. The session-bundle test also
skips when the Python binding was built without the `session-bundle`
feature.

### Stock-JOSE acceptance

`stock_jose_acceptance.py` (third-party `pyjwt`) and
`stock_jose_acceptance.mjs` (third-party `jose`) do **not** import the AITP
bindings. Each one verifies the spec's pinned signed-example vectors (a TCT,
a grant voucher and a delegation token, from
`tests/schemas/known-answer/signed-examples/`) using only the issuer key
derived from `iss`. Each also checks that `alg: none` is rejected. Together
they show that AITP tokens are ordinary RFC 7515 compact JWS
([RFC-AITP-0001 §5.4.5](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0001-core.md#545-compact-jws-profile-portable-trust-artifacts)).

Both scripts run standalone, without building a native binding:

```bash
python3 stock_jose_acceptance.py      # needs pyjwt[crypto] + cryptography
node stock_jose_acceptance.mjs        # resolves `jose` from ../aitp-node/node_modules
```

The Python script's filename does not match pytest's default `test_*.py`
pattern, so a plain `pytest` run here does not collect it.
`scripts/interop.sh` runs both scripts explicitly.

## Running

```bash
make interop          # from the repo root — builds both bindings, then runs everything
# or
scripts/interop.sh
```

`scripts/interop.sh` does the following, in order:

1. creates `bindings/interop/.venv/` and installs `maturin`, `pytest`,
   `pyjwt[crypto]` and `cryptography` into it;
2. runs `npm install` in `aitp-node`;
3. runs both stock-JOSE scripts;
4. builds `aitp-py` with `maturin develop --release` and `aitp-node` with
   `npm run build`;
5. runs `pytest -v` over this directory.

### Running pytest directly

If both bindings are already built into the active environment:

```bash
maturin develop -m ../aitp-py/Cargo.toml
(cd ../aitp-node && npm install && npm run build:debug)
pytest -v
```

## Files

| File | Role |
|---|---|
| `test_interop.py` | pytest suite: the Python end, plus the test harness |
| `node_worker.mjs` | the Node end: a JSON-RPC worker over stdio |
| `stock_jose_acceptance.py` | third-party `pyjwt` verifies the pinned signed-example tokens |
| `stock_jose_acceptance.mjs` | third-party `jose` verifies the same tokens |
