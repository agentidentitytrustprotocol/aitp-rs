#!/usr/bin/env bash
#
# Lockstep-version guard for the AITP workspace.
#
# Every published crate ships at the SAME version. That invariant lives in
# two places today:
#
#   1. `[workspace.package] version` in the root Cargo.toml, inherited by
#      each crate via `version.workspace = true`.
#   2. The inter-crate path dependencies, which pin an explicit
#      `version = "<x.y.z>"` (cargo requires a version on every path dep
#      that is also published to crates.io).
#
# release-plz keeps both in sync on release, but nothing stops a
# hand-edit from bumping one crate or one pin in isolation and quietly
# breaking lockstep. This script fails if either invariant is violated:
#
#   * a crate under crates/ that does not inherit the workspace version, or
#   * an `aitp-* = { path = ... }` dependency whose pinned version != the
#     workspace version.
#
# Run locally with `make check-versions`; CI runs it on every PR.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

# The single source of truth: `[workspace.package] version`. Anchored to
# the start of the line so the `version = "1.0"` entries inside
# `[workspace.dependencies]` (which are indented / inline in `{ ... }`)
# never match.
ws_version="$(sed -n 's/^version = "\([0-9][^"]*\)".*/\1/p' Cargo.toml | head -1)"
if [ -z "$ws_version" ]; then
  echo "✗ could not read [workspace.package] version from Cargo.toml" >&2
  exit 1
fi
echo "workspace version: $ws_version"

fail=0

# 1. Every crate under crates/ inherits the workspace version.
crate_count=0
for toml in crates/*/Cargo.toml; do
  crate_count=$((crate_count + 1))
  if ! grep -qE '^version\.workspace = true' "$toml"; then
    own="$(sed -n 's/^version = "\([0-9][^"]*\)".*/\1/p' "$toml" | head -1)"
    echo "✗ $toml: does not inherit the workspace version (found version = \"${own:-?}\", expected 'version.workspace = true')"
    fail=1
  fi
done

# 2. Every inter-crate path pin equals the workspace version.
pin_count=0
while IFS= read -r line; do
  [ -z "$line" ] && continue
  # grep -rn emits `path:lineno:content`; keep the path, drop the line no.
  file="${line%%:*}"
  rest="${line#*:}"
  rest="${rest#*:}"
  pinned="$(printf '%s' "$rest" | sed -n 's/.*version = "\([0-9][^"]*\)".*/\1/p')"
  [ -z "$pinned" ] && continue
  pin_count=$((pin_count + 1))
  if [ "$pinned" != "$ws_version" ]; then
    dep="$(printf '%s' "$rest" | sed -n 's/^[[:space:]]*\(aitp-[a-z-]*\).*/\1/p')"
    echo "✗ $file: dependency '$dep' pins $pinned, expected $ws_version"
    fail=1
  fi
done < <(grep -rnE '^[[:space:]]*aitp-[a-z-]+ = \{[^}]*path[^}]*\}' crates/*/Cargo.toml)

if [ "$fail" -ne 0 ]; then
  echo ""
  echo "lockstep check FAILED — every published crate and every inter-crate"
  echo "pin must sit at the workspace version ($ws_version)."
  exit 1
fi

echo "✓ $crate_count crates inherit version.workspace = true"
echo "✓ $pin_count inter-crate pins == $ws_version"
echo "lockstep OK"
