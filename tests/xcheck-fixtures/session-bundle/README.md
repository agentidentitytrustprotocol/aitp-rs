# Session bundle: minted by `aitp-verifier-py`, verified by `aitp-rs`

`kat-keypair-001-bundle.json` is not vendored from the spec repo — the
spec does not yet publish a session-bundle signed example under
`schemas/conformance/known-answer/signed-examples/` (unlike the manifest and
revocation snapshot, which are). It was minted independently by
[`aitp-verifier-py`](https://github.com/agentidentitytrustprotocol/aitp-verifier-py)'s
own minter, `aitp_verifier/minter.py::_mint_bundle` (via `mint_input`), at
the commit pinned in `tests/AITP_VERIFIER_PY_VERSION`, from the spec's
`schemas/conformance/bundle-001-success.json` input (coordinator
`kat-keypair-001`, participants `kat-keypair-002` and `kat-keypair-003`,
reference clock `1711900000`).

This is the reverse of `xcheck-mint`/`xcheck-verify.py` (aitp-rs mints,
aitp-verifier-py verifies): here aitp-verifier-py mints and `aitp-rs`
verifies these exact committed bytes. Neither side re-mints — see
`crates/aitp-experimental/tests/session_bundle_xcheck_committed.rs`'s
`aitp_verifier_py_committed_bundle_verifies` and its negative twin
`aitp_verifier_py_committed_bundle_rejects_the_sibling_shape`.

**Strict-cutover fixture.** `kat-keypair-001-bundle-aitp-0.2.json` is the
same input minted by aitp-verifier-py `43cf702f` at `aitp/0.2`, kept
byte-for-byte (it was this file until the aitp/0.3 regeneration).
`committed_aitp_0_2_bundle_is_rejected_by_the_strict_cutover` asserts
`aitp-rs` refuses it on `version` (`BUNDLE_VERSION_MISMATCH`): aitp/0.3 has
no dual-accept. Never regenerate or hand-edit it; the `version` member is
signed.

Provenance is reproducible, not just asserted: running the command below
against the two pinned commits reproduces `kat-keypair-001-bundle.json`
byte-for-byte. It was last regenerated for `aitp/0.3`, from aitp-verifier-py
`f335f4f` and spec `bf00e75`. If it
ever stops doing so, the fixture is no longer what this README claims and
direction (b) has quietly become circular.

## Regenerating

Only regenerate this file if the minting convention or the protocol
revision changes (e.g. a future spec revision moves the signature placement
again, or bumps the signed `version` literal). Otherwise it must stay
byte-for-byte fixed, the same as any other committed KAT vector.

```sh
# From a checkout of aitp-verifier-py at the commit pinned in
# tests/AITP_VERIFIER_PY_VERSION, with the spec repo checked out at the
# commit pinned in tests/schemas/SPEC_VERSION as ./spec:
python3 -c '
import json
from pathlib import Path
from aitp_verifier.minter import mint_input
from aitp_verifier.keys import load_kat_keys

spec_dir = Path("spec")
fixture = json.loads((spec_dir / "schemas/conformance/bundle-001-success.json").read_text())
keys = load_kat_keys(spec_dir)
minted = mint_input(fixture["input"], 1711900000, keys)
print(json.dumps(minted["session_bundle"], indent=2))
' > kat-keypair-001-bundle.json
```
