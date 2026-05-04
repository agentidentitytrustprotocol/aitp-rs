# AITP conformance adapters

Adapters let `aitp-conformance` test AITP implementations in any language.
Each adapter is an executable that speaks NDJSON over stdin/stdout.

## Templates

- `python-adapter-template.py` — start here for a Python implementation.
- (More language templates will be added as implementations appear.)

## Protocol

See [`../docs/design/02-conformance-adapter.md`](../docs/design/02-conformance-adapter.md)
for the full request/response specification.

## Testing your adapter

```sh
cargo run -p aitp-conformance -- run \
  --target "python adapters/python-adapter-template.py" \
  --filter "tct-*"
```
