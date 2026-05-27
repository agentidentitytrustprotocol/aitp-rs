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

echo "interop: building the Python binding (maturin develop --features experimental)..."
VENV="$INTEROP/.venv"
python3 -m venv "$VENV"
# shellcheck disable=SC1091
source "$VENV/bin/activate"
# `pyjwt[crypto]` + `cryptography` are required by the OIDC interop
# test (mock IdP signs Ed25519 JWTs in-process); the experimental
# feature is needed for session-bundle interop.
pip install --quiet --upgrade pip maturin pytest 'pyjwt[crypto]>=2.8' 'cryptography>=41'
maturin develop --release --features experimental -m "$PY_DIR/Cargo.toml"

echo "interop: building the Node binding (napi build:experimental)..."
( cd "$NODE_DIR" && npm install --silent && npm run build:experimental --silent )

echo "interop: running cross-language handshake tests..."
exec pytest -v "$INTEROP"
