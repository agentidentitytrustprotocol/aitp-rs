#!/usr/bin/env bash
#
# Version-sync writer for the two SDK bindings (bindings/aitp-node,
# bindings/aitp-py).
#
# Both bindings carry their own `[workspace]` table and are excluded from
# the Cargo workspace (see `exclude` in the root Cargo.toml and the
# comment atop each binding's Cargo.toml), specifically so their PyO3 /
# NAPI-rs `cdylib` crates don't get pulled into `cargo test --workspace`.
# That exclusion has a side effect: `version.workspace = true` can never
# reach them, and release-plz (which only ever looks inside the Cargo
# workspace when it bumps versions) has no way to touch them either.
# Nothing else bumped them, so they silently drifted up to 5 releases
# behind what was actually published (0.5.0 committed vs. 0.10.0
# shipped) before anyone noticed — see the history comment in
# scripts/check-versions.sh.
#
# check-versions.sh is the READER: it fails the build if any binding
# manifest disagrees with the workspace version. This script is the
# WRITER that keeps them from drifting in the first place — it rewrites
# every file check-versions.sh reads to match `[workspace.package]
# version` in the root Cargo.toml. The two scripts are a matched pair; if
# you add a check to one, add the matching read/write to the other.
#
# Usage: ./scripts/sync-binding-versions.sh
#   (No arguments — always syncs to the CURRENT workspace version. Bump
#   `[workspace.package] version` in Cargo.toml first, then run this.)
#
# Written in pure shell + awk/perl (no node/python required) so it runs
# unmodified on both the macOS/BSD toolchain contributors use locally and
# the Linux/GNU toolchain CI uses. check-versions.sh already hit one
# BSD-sed portability bug in its pyproject.toml checker (fixed by
# switching to awk); this script uses the same POSIX awk/perl subset
# throughout and avoids GNU-only sed block syntax (`sed '/x/,/y/{...}'`)
# for the same reason.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

# Same read as check-versions.sh: anchored to the start of the line so the
# `version = "1.0"` entries inside `[workspace.dependencies]` (indented /
# inline in `{ ... }`) never match.
ws_version="$(sed -n 's/^version = "\([0-9][^"]*\)".*/\1/p' Cargo.toml | head -1)"
if [ -z "$ws_version" ]; then
  echo "✗ could not read [workspace.package] version from Cargo.toml" >&2
  exit 1
fi
echo "syncing bindings to workspace version: $ws_version"

# --- writers ---------------------------------------------------------------

# Rewrite the `[package] version = "..."` line of a standalone binding's
# Cargo.toml. Scoped to the `[package]` section only (mirrors
# check-versions.sh's section-scoped pyproject.toml reader below) so a
# future `[dependencies.foo]` multi-line table with its own line-anchored
# `version = "..."` is never touched.
sync_cargo_toml_version() { # $1 = path to a standalone binding's Cargo.toml
  local f="$1" tmp
  tmp="$(mktemp)"
  awk -v ver="$ws_version" '
    /^\[/ { insec = ($0 == "[package]") }
    insec && /^version = "/ { print "version = \"" ver "\""; next }
    { print }
  ' "$f" > "$tmp"
  mv "$tmp" "$f"
}

# Rewrite package.json: the top-level "version" field, plus every
# @agentidentitytrustprotocol/aitp-* pin under optionalDependencies (the
# prebuilt-binary packages, published at the same version as the main
# package). Text-patched with perl rather than a JSON tool so this script
# has no node/python dependency; the `[0-9]` guard on the version value
# keeps this from ever matching the unrelated `"version": "napi version"`
# npm-scripts entry, whose value doesn't start with a digit.
sync_package_json_version() { # $1 = path to bindings/aitp-node/package.json
  V="$ws_version" perl -0777 -i -pe '
    s/^(\s*"version":\s*")[0-9][^"]*(")/${1}$ENV{V}${2}/m;
    s/("\@agentidentitytrustprotocol\/aitp-[a-z0-9-]+":\s*")[0-9][^"]*(")/${1}$ENV{V}${2}/g;
  ' "$1"
}

# napi-rs 3's generated `index.js` bakes `package.json`'s version into a
# runtime `NAPI_RS_ENFORCE_VERSION_CHECK`-gated assertion (once per
# platform-specific optional dependency, plus the WASI fallback) — it is
# not just cosmetic. `bindings.yml`'s freshness gate rebuilds `index.js`
# from a fresh `napi build` and diffs it against the committed copy, so a
# stale baked-in version fails that check the moment `package.json`
# changes underneath it. Rewrite every occurrence of the OLD version in
# the two exact generated patterns (`!== 'X.Y.Z'` and `expected X.Y.Z
# but got`) to the new one, rather than a blind file-wide replace — this
# file also contains this crate's own logic that must not be touched.
#
# The "old" version is read from `index.js` ITSELF, not from
# `package.json` — the two can already have drifted (e.g. a release PR
# whose version got bumped again, by a second release-plz pass, before
# this script's index.js patch had ever run against the first bump), and
# trusting package.json's current value in that case searches for a
# version that was never actually baked into this file, silently leaving
# it stale. Reading index.js's own committed value is self-correcting
# regardless of how far the two files have drifted apart.
sync_index_js_version() { # $1 = path to a binding's generated index.js
  local f="$1" old
  [ -f "$f" ] || return 0
  # Require an X.Y.Z shape (>=2 dots) so a greedy match can't land on
  # the unrelated `NAPI_RS_ENFORCE_VERSION_CHECK !== '0'` flag check
  # that sits later on the same generated line — a bare digit has no
  # dot and never matches this pattern.
  old="$(sed -n "s/.*!== '\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)'.*/\1/p" "$f" | head -1)"
  [ -n "$old" ] || return 0
  [ "$old" = "$ws_version" ] && return 0
  OLD="$old" V="$ws_version" perl -0777 -i -pe '
    s/!== \x27\Q$ENV{OLD}\E\x27/!== \x27$ENV{V}\x27/g;
    s/expected \Q$ENV{OLD}\E but got/expected $ENV{V} but got/g;
  ' "$f"
}

# Rewrite every `aitp-*` PATH package's version in a binding's Cargo.lock.
# A path package is identified the same way cargo's lockfile does: it has
# no `source = "..."` line in its `[[package]]` block (registry /
# git-sourced deps always carry one). This deliberately leaves any
# hypothetical crates.io-published `aitp-*`-named dependency untouched —
# only the internal workspace-path crates this repo builds are rewritten.
sync_cargo_lock_versions() { # $1 = path to a binding's Cargo.lock
  local f="$1" tmp
  tmp="$(mktemp)"
  awk -v ver="$ws_version" '
    function flush() {
      is_path_aitp = (name ~ /^aitp-/) && !has_source
      for (i = 0; i < n; i++) {
        line = buf[i]
        if (is_path_aitp && line ~ /^version = "/) {
          print "version = \"" ver "\""
        } else {
          print line
        }
      }
    }
    BEGIN { n = 0; name = ""; has_source = 0 }
    /^\[\[package\]\]/ {
      flush()
      n = 0; name = ""; has_source = 0
      buf[n++] = $0
      next
    }
    {
      buf[n++] = $0
      if ($0 ~ /^name = "/) {
        name = $0
        sub(/^name = "/, "", name)
        sub(/".*/, "", name)
      }
      if ($0 ~ /^source = /) has_source = 1
    }
    END { flush() }
  ' "$f" > "$tmp"
  mv "$tmp" "$f"
}

# Rewrite pyproject.toml's `[project] version = "..."`. Scoped to the
# `[project]` section only — same trick as check-versions.sh's
# check_pyproject_toml_version awk function — so the `[build-system]`
# section's `requires = ["maturin>=1.5,<2.0"]` line is never touched.
sync_pyproject_toml_version() { # $1 = path to bindings/aitp-py/pyproject.toml
  local f="$1" tmp
  tmp="$(mktemp)"
  awk -v ver="$ws_version" '
    /^\[/ { insec = ($0 == "[project]") }
    insec && /^version = "/ { print "version = \"" ver "\""; next }
    { print }
  ' "$f" > "$tmp"
  mv "$tmp" "$f"
}

# --- apply -------------------------------------------------------------

sync_cargo_toml_version     bindings/aitp-node/Cargo.toml
sync_package_json_version   bindings/aitp-node/package.json
sync_cargo_lock_versions    bindings/aitp-node/Cargo.lock
sync_index_js_version       bindings/aitp-node/index.js

sync_cargo_toml_version     bindings/aitp-py/Cargo.toml
sync_pyproject_toml_version bindings/aitp-py/pyproject.toml
sync_cargo_lock_versions    bindings/aitp-py/Cargo.lock

echo "binding manifests synced to $ws_version"

# Self-verify: whatever this script just wrote must satisfy the exact
# check that motivated writing it. If a rewrite above got something
# wrong, this catches it immediately instead of at the next CI run.
exec ./scripts/check-versions.sh
