#!/usr/bin/env bash
# Feature sets that promise a small dependency graph keep it (the
# `features` CI job). Each check reads the normal-dependency tree only.
#
#   - `aitp` with `pinned-admission` alone: the embedded admission seam
#     carries no HTTP stack (no reqwest, axum or hyper), and no tokio
#     with `net`.
#   - `aitp` with `source-ip` alone: no axum, tokio or hyper, so services
#     on another HTTP stack can use it (aitp-rs#205 A-2).
#   - `aitp-experimental` with default features: does not turn on the
#     server (no axum, hyper or tokio).
set -euo pipefail

export CARGO_TERM_COLOR=never
fail=0

packages() {
  cargo tree --color=never -e normal --prefix none "$@" | awk '{print $1}' | sort -u
}

forbid() {
  local label="$1" pattern="$2"
  shift 2
  local hits
  hits=$(packages "$@" | grep -E "^(${pattern})$" || true)
  if [ -n "$hits" ]; then
    echo "::error::${label} pulls in: $(echo "$hits" | tr '\n' ' ')"
    fail=1
  else
    echo "ok: ${label}"
  fi
}

forbid "aitp --features pinned-admission" 'reqwest|axum|hyper' \
  -p aitp --no-default-features --features pinned-admission
if cargo tree --color=never -e normal,features -p aitp --no-default-features --features pinned-admission \
    -i tokio 2>/dev/null | grep -q 'tokio feature "net"'; then
  echo "::error::aitp --features pinned-admission enables tokio/net"
  fail=1
else
  echo "ok: aitp --features pinned-admission has no tokio/net"
fi

forbid "aitp --features source-ip" 'axum|tokio|hyper' \
  -p aitp --no-default-features --features source-ip

forbid "aitp-experimental (default features)" 'axum|hyper|tokio' \
  -p aitp-experimental

exit "$fail"
