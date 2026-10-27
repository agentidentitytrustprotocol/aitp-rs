# AITP conformance adapters

Adapters let `aitp-conformance` test AITP implementations in any language.
Each adapter is an executable that speaks NDJSON over stdin/stdout.

## Templates

- `python-adapter-template.py` — start here for a Python implementation.
  It is a stub: it answers `init`, `generate_keypair` (with a placeholder
  key) and `shutdown`, and every other op returns `OP_NOT_SUPPORTED` until
  you replace the TODO bodies with calls into your implementation.
- (More language templates will be added as implementations appear.)

## Protocol

The spec defines it, in
[`schemas/conformance/ADAPTER.md`](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/schemas/conformance/ADAPTER.md):
messages, `init`, the operations fixtures use and SKIP rules. The inputs
of each operation are in
[PLACEHOLDERS.md, "Operation key"](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/schemas/conformance/PLACEHOLDERS.md#operation-key).
How this runner applies it is in
[`../docs/conformance.md`](../docs/conformance.md#adapter-protocol).

## Testing your adapter

The fixtures live in the spec repo
([`schemas/conformance/`](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/schemas/conformance/README.md)).
With the spec cloned next to this repo, run from the `aitp-rs` root:

```sh
cargo run -p aitp-conformance --bin aitp-conformance -- run \
  --target adapters/python-adapter-template.py \
  --fixtures-dir ../agentidentitytrustprotocol/schemas/conformance \
  --filter tct-
```

- `--target` is a single executable path, spawned directly with no shell
  and no arguments. Make your adapter executable with a shebang line
  (the template already is); `--target "python adapters/…"` fails with
  `failed to spawn adapter: … No such file or directory`.
- `--fixtures-dir` is required in practice: its default,
  `./schemas/conformance`, does not exist in this repo.
- `--filter` is a plain substring match on fixture IDs, not a glob.
  `--filter tct-` selects the TCT fixtures; `--filter "tct-*"` matches
  nothing.
- For results that match CI, check the spec out at the commit pinned in
  `tests/schemas/SPEC_VERSION`.

Against the unmodified template every selected fixture is a SKIP: an op
the template does not list, or one it answers with `OP_NOT_SUPPORTED`, is
not run. A SKIP of a core fixture still fails the core gate, so the runner
exits with status 1. The output looks like this (the fixture count depends
on the spec commit you have checked out):

```text
Loaded 28 fixtures
Adapter: aitp-py-template 0.0.0
  SKIP tct-002 (adapter does not support op verify_tct)
  ...
  SKIP tct-006 (adapter does not support op issue_pop_challenge)
  ...
  SKIP tct-019 (non-core fixture (status=Extension); requires feature `aitp-self-attestation`)
  ...
Summary: 0 passed, 0 failed, 28 skipped of 28 fixtures

core conformance gate FAILED — 25 required fixture(s) did not pass:
  tct-002: SKIP — adapter does not support op verify_tct
  ...
```

That is the expected starting point: implement the ops the SKIPs name
(`verify_tct` first), list them in `supported_ops` in the `init` response,
and re-run. See [CLI surface](../docs/conformance.md#cli-surface) for
`--tag`, `--feature` and the other runner flags.
