#!/usr/bin/env bash
#
# Hello world against an interop peer: enrol a key, then `aitp echo`
# (handshake, then present the issued TCT to /echo with proof of
# possession). Usage:
#
#   scripts/interop-peer-smoke.sh https://interop.agentidentitytrustprotocol.io
#
# Uses `aitp` from PATH (or $AITP) and a throwaway key. Exits non-zero on
# any failure. A plain-http localhost origin adds --insecure-localhost.
set -euo pipefail

origin="${1:?usage: $0 <peer origin>}"
aitp="${AITP:-aitp}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
export AITP_KEY="$work/agent.key"

insecure=()
case "$origin" in
  http://localhost*|http://127.0.0.1*|http://\[::1\]*) insecure=(--insecure-localhost) ;;
esac

"$aitp" enroll "$origin" ${insecure[@]+"${insecure[@]}"} > "$work/enrolled.json"
aid="$(sed -n 's/.*"aid": *"\([^"]*\)".*/\1/p' "$work/enrolled.json" | head -1)"
[ -n "$aid" ] || { echo "enroll printed no aid" >&2; cat "$work/enrolled.json" >&2; exit 1; }

"$aitp" echo "$origin" ${insecure[@]+"${insecure[@]}"} > "$work/echo.json"
grep -q "\"sub\": *\"$aid\"" "$work/echo.json" \
  || { echo "echo did not return our AID" >&2; cat "$work/echo.json" >&2; exit 1; }
echo "ok: $aid enrolled, handshook and echoed at $origin"
