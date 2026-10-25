#!/usr/bin/env bash
#
# Every Dockerfile's `FROM rust:<x.y>` must be at least the workspace
# `rust-version`: an older image cannot build the workspace, and the
# failure only shows up when someone runs `docker build`.
set -euo pipefail
cd "$(dirname "$0")/.."

msrv="$(sed -n 's/^rust-version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
[ -n "$msrv" ] || { echo "no rust-version in Cargo.toml" >&2; exit 1; }

# "1.90" / "1.90.0" -> 1090000 for comparison.
num() { IFS=. read -r a b c <<<"$1"; echo $(( a * 1000000 + b * 1000 + ${c:-0} )); }

status=0
found=0
while IFS= read -r file; do
  while IFS= read -r tag; do
    found=1
    if [ "$(num "$tag")" -lt "$(num "$msrv")" ]; then
      echo "::error file=$file::FROM rust:$tag is below rust-version $msrv"
      status=1
    else
      echo "ok: $file rust:$tag (rust-version $msrv)"
    fi
  done < <(sed -n 's/^FROM rust:\([0-9][0-9.]*\).*/\1/p' "$file")
done < <(git ls-files --cached --others --exclude-standard '*Dockerfile*')
[ "$found" = 1 ] || { echo "no FROM rust:<version> lines found" >&2; exit 1; }
exit "$status"
