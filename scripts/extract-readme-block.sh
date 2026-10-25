#!/usr/bin/env bash
#
# Print the README's hello world block, the code fence opened with
# ```` ```bash readme-smoke ````, as a shell script.
#
#   scripts/extract-readme-block.sh [README.md]                 # verbatim
#   scripts/extract-readme-block.sh --local ORIGIN [README.md]  # for a local peer
#
# --local rewrites the block for CI against a peer at ORIGIN built from
# this checkout: `cargo install aitp-cli` installs `crates/aitp-cli`, the
# public peer's origin becomes ORIGIN, and a plain-http ORIGIN adds
# --insecure-localhost. Everything else, flags included, runs as written,
# so a wrong flag in the README fails the job.
#
# .github/workflows/readme-smoke.yml pipes the output into bash.
set -euo pipefail

PUBLIC_ORIGIN=https://interop.agentidentitytrustprotocol.io

local_origin=
if [ "${1:-}" = --local ]; then
  local_origin="${2:?--local needs an origin}"
  shift 2
fi
readme="${1:-$(git rev-parse --show-toplevel)/README.md}"

block="$(awk '
  /^```bash readme-smoke[[:space:]]*$/ { on = 1; next }
  on && /^```/                         { on = 0; done = 1 }
  on                                   { print }
  END                                  { if (!done) exit 1 }
' "$readme")" || { echo "no readme-smoke block in $readme" >&2; exit 1; }
[ -n "$block" ] || { echo "the readme-smoke block in $readme is empty" >&2; exit 1; }

if [ -n "$local_origin" ]; then
  insecure=
  case "$local_origin" in http://*) insecure=" --insecure-localhost" ;; esac
  block="$(printf '%s\n' "$block" | awk -v pub="$PUBLIC_ORIGIN" -v loc="$local_origin" -v ins="$insecure" '
    { sub(/^cargo install aitp-cli/, "cargo install --locked --debug --path crates/aitp-cli") }
    index($0, pub) { gsub(pub, loc); $0 = $0 ins }
    { print }
  ')"
fi

printf 'set -euxo pipefail\n%s\n' "$block"
