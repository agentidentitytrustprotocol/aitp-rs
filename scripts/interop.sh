#!/usr/bin/env bash
#
# Cross-language interop integration tests.
#
# Builds the Python and Node AITP bindings, then runs the pytest suite
# in bindings/interop/, which drives a real four-message AITP handshake
# between the two SDKs in both directions. Exits non-zero on any failure.
#
# Usage:
#   scripts/interop.sh        # or: make interop

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INTEROP="$ROOT/bindings/interop"
PY_DIR="$ROOT/bindings/aitp-py"
NODE_DIR="$ROOT/bindings/aitp-node"

command -v python3 >/dev/null || { echo "interop: python3 not found on PATH" >&2; exit 1; }
command -v node    >/dev/null || { echo "interop: node not found on PATH" >&2; exit 1; }
command -v npm     >/dev/null || { echo "interop: npm not found on PATH" >&2; exit 1; }

echo "interop: building the Python binding (maturin develop)..."
VENV="$INTEROP/.venv"
python3 -m venv "$VENV"
# shellcheck disable=SC1091
source "$VENV/bin/activate"
# `pyjwt[crypto]` + `cryptography` are required by the OIDC interop
# test (mock IdP signs Ed25519 JWTs in-process) AND by the stock-JOSE
# acceptance check (pyjwt verifies the spec's signed-example KATs).
# Default features (the full surface) cover session-bundle interop.
pip install --quiet --upgrade pip maturin pytest 'pyjwt[crypto]>=2.8' 'cryptography>=41'

# Install the Node deps first so the stock-JOSE acceptance check (which
# resolves the third-party `jose` from aitp-node/node_modules) can run
# *before* the native builds — it needs neither maturin nor napi, so it
# provides value even if the native build is unavailable.
echo "interop: installing Node dependencies..."
( cd "$NODE_DIR" && npm install --silent )

# ── Stock-JOSE acceptance checks (no native bindings required) ─────────
# The headline property of the v0.2 compact-JWS migration: the spec's
# signed-example TCT/voucher/delegation tokens verify under *third-party*
# JOSE libraries. Both run here directly (fail the run on non-zero exit)
# before the native builds, so they provide value even when the native
# build is unavailable. They are deliberately NOT named `test_*.py` and
# so are not collected by the pytest run below — these explicit,
# build-free invocations are the canonical path.
echo "interop: stock-JOSE acceptance check (Node, third-party jose)..."
node "$INTEROP/stock_jose_acceptance.mjs"
echo "interop: stock-JOSE acceptance check (Python, third-party pyjwt)..."
python3 "$INTEROP/stock_jose_acceptance.py"

maturin develop --release -m "$PY_DIR/Cargo.toml"

echo "interop: building the Node binding (napi build)..."
( cd "$NODE_DIR" && npm run build --silent )

echo "interop: running cross-language handshake + pyjwt acceptance tests..."
exec pytest -v "$INTEROP"
