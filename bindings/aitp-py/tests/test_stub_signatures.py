"""`aitp.pyi` must describe the compiled extension's real call signatures.

The stub is hand-maintained (PyO3 does not generate one), so it drifts: until
#199 it advertised `build_renewal_request(current_tct_token)` while the
binding's keyword was `current_tct_envelope_json`, and a keyword call written
against the stub raised `TypeError`. This test parses the stub and checks
every function and method's parameter names — and which of them are optional
— against `inspect.signature` of the compiled object, so the next drift fails
CI instead of a caller.

`aitp_experimental.pyi` declares the experimental features' symbols; its
cases run against a build that has them. Symbols behind an optional Cargo
feature that this build omits are skipped. Every public name the module
exports must be declared in one of the two stubs.
"""

import ast
import base64
import inspect
import json
import pathlib

import pytest

import aitp

ROOT = pathlib.Path(__file__).resolve().parent.parent
STUB = ROOT / "aitp.pyi"
EXPERIMENTAL_STUB = ROOT / "aitp_experimental.pyi"


def _stub_params(fn: ast.FunctionDef, *, is_method: bool):
    """`[(name, has_default)]` for a stub `def`, minus a leading `self`."""
    args = fn.args
    positional = args.posonlyargs + args.args
    defaults = [None] * (len(positional) - len(args.defaults)) + list(args.defaults)
    out = [(a.arg, d is not None) for a, d in zip(positional, defaults)]
    out += [(a.arg, d is not None) for a, d in zip(args.kwonlyargs, args.kw_defaults)]
    if is_method and out and out[0][0] == "self":
        out = out[1:]
    return out


def _runtime_params(obj):
    params = inspect.signature(obj).parameters.values()
    return [
        (p.name, p.default is not inspect.Parameter.empty)
        for p in params
        if p.name != "self"
    ]


def _is_property(fn: ast.FunctionDef) -> bool:
    return any(isinstance(d, ast.Name) and d.id == "property" for d in fn.decorator_list)


def _cases(stub):
    tree = ast.parse(stub.read_text())
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            yield node.name, None, node
        elif isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and not _is_property(item):
                    yield node.name, item.name, item


CASES = list(_cases(STUB)) + list(_cases(EXPERIMENTAL_STUB))


def _declared(stub):
    names = set()
    for node in ast.parse(stub.read_text()).body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
        elif isinstance(node, ast.Assign):
            names.update(t.id for t in node.targets if isinstance(t, ast.Name))
    return names


def test_every_export_is_declared():
    declared = _declared(STUB) | _declared(EXPERIMENTAL_STUB)
    # The installed package re-exports its native module's names; the
    # native module itself is not API.
    exported = {
        n for n in dir(aitp)
        if not n.startswith("_") and not inspect.ismodule(getattr(aitp, n))
    }
    missing = sorted(exported - declared)
    assert not missing, f"exported by the binding but not declared in a stub: {missing}"


def test_stable_stub_declares_no_experimental_symbol():
    overlap = sorted(_declared(STUB) & (_declared(EXPERIMENTAL_STUB) - {"AitpAgent"}))
    assert not overlap, f"declared in both aitp.pyi and aitp_experimental.pyi: {overlap}"


@pytest.mark.parametrize(
    "owner,method,fn",
    CASES,
    ids=[f"{o}.{m}" if m else o for o, m, _ in CASES],
)
def test_stub_matches_runtime_signature(owner, method, fn):
    if not hasattr(aitp, owner):
        pytest.skip(f"{owner} is behind a Cargo feature absent from this build")
    target = getattr(aitp, owner)
    if method is not None:
        if method == "__init__":
            # PyO3 attaches the `#[new]` signature to the class itself.
            if target.__text_signature__ is None:
                pytest.skip(f"{owner} exposes no constructor signature")
        else:
            if not hasattr(target, method):
                pytest.skip(f"{owner}.{method} is behind an absent Cargo feature")
            target = getattr(target, method)
    expected = _stub_params(fn, is_method=method is not None)
    assert _runtime_params(target) == expected, (
        f"aitp.pyi signature for {owner}{'.' + method if method else ''} "
        f"disagrees with the compiled binding"
    )


def test_build_renewal_request_accepts_stub_keyword():
    """The #199 regression: the stub's keyword is the real keyword."""
    agent = aitp.AitpAgent.generate()
    if not hasattr(agent, "build_renewal_request"):
        pytest.skip("renewal feature absent from this build")
    # The holder reads `iss` and `jti` from the token's claims without
    # verifying it, so a well-formed unsigned token round-trips into the
    # payload; a wrong keyword would raise TypeError instead.
    def b64(obj):
        raw = json.dumps(obj, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    claims = {
        "ver": "aitp/0.3",
        "jti": "550e8400-e29b-41d4-a716-446655440000",
        "iss": agent.aid,
        "sub": agent.aid,
        "aud": agent.aid,
        "iat": 1711900000,
        "exp": 1711903600,
        "grants": ["demo.echo"],
        "cnf": {"jkt": "1IG2tMH7J2wbJZnOf8LJzQitKf7LMvoAElsuDMVM54Y"},
    }
    token = b64({"alg": "EdDSA", "typ": "aitp-tct+jwt"}) + "." + b64(claims) + ".AA"
    req = json.loads(agent.build_renewal_request(current_tct_token=token))
    assert req["current_tct"] == token
