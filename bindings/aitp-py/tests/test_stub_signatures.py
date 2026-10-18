"""`aitp.pyi` must describe the compiled extension's real call signatures.

The stub is hand-maintained (PyO3 does not generate one), so it drifts: until
#199 it advertised `build_renewal_request(current_tct_token)` while the
binding's keyword was `current_tct_envelope_json`, and a keyword call written
against the stub raised `TypeError`. This test parses the stub and checks
every function and method's parameter names — and which of them are optional
— against `inspect.signature` of the compiled object, so the next drift fails
CI instead of a caller.

Symbols behind an optional Cargo feature that this build omits are skipped.
"""

import ast
import inspect
import json
import pathlib

import pytest

import aitp

STUB = pathlib.Path(__file__).resolve().parent.parent / "aitp.pyi"


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


def _cases():
    tree = ast.parse(STUB.read_text())
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            yield node.name, None, node
        elif isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and not _is_property(item):
                    yield node.name, item.name, item


CASES = list(_cases())


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
    # The holder side does not parse the token, so any string round-trips
    # into the payload; a wrong keyword would raise TypeError instead.
    req = json.loads(agent.build_renewal_request(current_tct_token="held.tct.jws"))
    assert req["current_tct"] == "held.tct.jws"
