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

See [`../docs/conformance.md`](../docs/conformance.md#wire-protocol)
for the full request/response specification and the
[operation vocabulary](../docs/conformance.md#operation-vocabulary).

## Testing your adapter

The fixtures live in the spec repo
([`schemas/conformance/`](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/schemas/conformance/README.md)).
With the spec cloned next to this repo, run from the `aitp-rs` root:

```sh
cargo run -p aitp-conformance -- run \
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

Against the unmodified template every selected fixture fails, and the
runner exits with status 1. The output looks like this (the fixture count
depends on the spec commit you have checked out):

```text
Loaded 11 fixtures
Adapter: aitp-py-template 0.0.0
  FAIL tct-002 [0ms]
        reason: expected error TCT_EXPIRED, got OP_NOT_SUPPORTED
  ...
  FAIL tct-006 [0ms]
        reason: step 1: operation 'issue_pop_challenge' not supported by this adapter
  ...
  FAIL tct-012 [0ms]
        reason: expected success, got error OP_NOT_SUPPORTED
Summary: 0 passed, 11 failed, 0 skipped of 11 fixtures
```

That is the expected starting point: implement the ops the failures name
(`verify_tct` first), list them in `supported_ops` in the `init` response,
and re-run. See [CLI surface](../docs/conformance.md#cli-surface) for
`--tag`, `--feature` and the other runner flags.
