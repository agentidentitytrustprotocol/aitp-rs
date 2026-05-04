#!/usr/bin/env bash
# Run the full local CI gauntlet.
set -euo pipefail
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-features
echo "✓ all checks passed"
