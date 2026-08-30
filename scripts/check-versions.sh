#!/usr/bin/env bash
#
# Lockstep-version guard for the AITP workspace.
#
# Every published crate ships at the SAME version. That invariant lives in
# two places today:
#
#   1. `[workspace.package] version` in the root Cargo.toml, inherited by
#      each crate via `version.workspace = true`.
#   2. The inter-crate path dependencies, which pin the EXACT shared
#      version (`version = "=<x.y.z>"`, cargo requires a version on every
#      path dep that is also published to crates.io). The exact `=` form
#      stops a resolver from mixing release generations across the family.
#
# release-plz keeps both in sync on release (the crates share a
# `version_group` so it bumps the whole family together), but nothing
# stops a hand-edit from bumping one crate or one pin in isolation and
# quietly breaking lockstep. This script fails if either invariant is
# violated:
#
#   * a crate under crates/ that does not inherit the workspace version, or
#   * an `aitp* = { path = ... }` dependency whose pin is not exactly
#     `=<workspace version>`.
#
# A THIRD invariant covers the two bindings (bindings/aitp-node,
# bindings/aitp-py): they are excluded from the Cargo workspace (they carry
# their own `[workspace]` table, see the comment atop each binding's
# Cargo.toml) so release-plz never touches them. release-bindings.yml tags
# each binding release at the SAME version as the crate release, but on a
# commit deliberately kept off `main` (main is branch-protected) — so main's
# own binding manifests can drift arbitrarily far behind what's actually
# published and nothing failed loudly. That drift reached 5 releases
# (0.5.0 committed vs. 0.10.0 published) before anyone noticed, because a
# local `npm install`/`pip install -e` against a stale manifest still
# "works" — it just quietly resolves stale prebuilt/published dependency
# versions instead of the workspace's current code. This script now fails
# if any binding manifest's version doesn't match the workspace version, so
# the next release makes that drift a build failure instead of a silent gap.
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
  # Capture the pin verbatim, incl. any leading `=` (exact-version form).
  pinned="$(printf '%s' "$rest" | sed -n 's/.*version = "\(=\{0,1\}[0-9][^"]*\)".*/\1/p')"
  [ -z "$pinned" ] && continue
  pin_count=$((pin_count + 1))
  dep="$(printf '%s' "$rest" | sed -n 's/^[[:space:]]*\(aitp[a-z-]*\) .*/\1/p')"
  # Inter-crate pins must be EXACT (`=x.y.z`) at the workspace version, so a
  # resolver can never mix release generations across the family.
  if [ "$pinned" != "=$ws_version" ]; then
    echo "✗ $file: dependency '$dep' pins \"$pinned\", expected exact \"=$ws_version\""
    fail=1
  fi
done < <(grep -rnE '^[[:space:]]*aitp[a-z-]* = \{[^}]*path[^}]*\}' crates/*/Cargo.toml)


# 3. Each binding's own manifests (excluded from the Cargo workspace, so
#    `version.workspace = true` can't reach them) declare the workspace
#    version directly.
binding_count=0

check_cargo_toml_version() { # $1 = path to a standalone binding's Cargo.toml
  binding_count=$((binding_count + 1))
  local got
  got="$(sed -n 's/^version = "\([0-9][^"]*\)".*/\1/p' "$1" | head -1)"
  if [ "$got" != "$ws_version" ]; then
    echo "✗ $1: declares version \"${got:-?}\", expected \"$ws_version\""
    fail=1
  fi
}

check_package_json_version() { # $1 = path to a package.json
  binding_count=$((binding_count + 1))
  local got
  got="$(sed -n 's/^[[:space:]]*"version": "\([0-9][^"]*\)".*/\1/p' "$1" | head -1)"
  if [ "$got" != "$ws_version" ]; then
    echo "✗ $1: declares version \"${got:-?}\", expected \"$ws_version\""
    fail=1
  fi
}

check_pyproject_toml_version() { # $1 = path to a pyproject.toml
  binding_count=$((binding_count + 1))
  local got
  got="$(awk '/^\[project\]/{p=1} p && /^\[/ && !/^\[project\]/{p=0} p && /^version = "/{gsub(/^version = "|".*/,""); print; exit}' "$1")"
  if [ "$got" != "$ws_version" ]; then
    echo "✗ $1: declares version \"${got:-?}\", expected \"$ws_version\""
    fail=1
  fi
}

check_cargo_toml_version    bindings/aitp-node/Cargo.toml
check_package_json_version  bindings/aitp-node/package.json
check_cargo_toml_version    bindings/aitp-py/Cargo.toml
check_pyproject_toml_version bindings/aitp-py/pyproject.toml

# The aitp-node optionalDependencies block pins the platform-specific
# prebuilt-binary packages, which are published at the same version as the
# main package. A stale pin here is exactly the failure mode that motivated
# this check: `npm install` silently resolves an old prebuilt native
# binary instead of the one this repo's source actually produces.
while IFS= read -r line; do
  pkg="$(printf '%s' "$line" | sed -n 's/^[[:space:]]*"\(@agentidentitytrustprotocol\/aitp-[a-z0-9-]*\)": "[0-9][^"]*".*/\1/p')"
  [ -z "$pkg" ] && continue
  binding_count=$((binding_count + 1))
  got="$(printf '%s' "$line" | sed -n 's/^[[:space:]]*"@agentidentitytrustprotocol\/aitp-[a-z0-9-]*": "\([0-9][^"]*\)".*/\1/p')"
  if [ "$got" != "$ws_version" ]; then
    echo "✗ bindings/aitp-node/package.json: optionalDependencies '$pkg' pins \"${got:-?}\", expected \"$ws_version\""
    fail=1
  fi
done < <(sed -n '/"optionalDependencies"/,/}/p' bindings/aitp-node/package.json)

if [ "$fail" -ne 0 ]; then
  echo ""
  echo "lockstep check FAILED — every published crate, every inter-crate"
  echo "pin, and both bindings' manifests must sit at the workspace version"
  echo "($ws_version)."
  exit 1
fi

echo "✓ $crate_count crates inherit version.workspace = true"
echo "✓ $pin_count inter-crate pins are exact =$ws_version"
echo "✓ $binding_count binding manifest/pin entries match $ws_version"
echo "lockstep OK"
