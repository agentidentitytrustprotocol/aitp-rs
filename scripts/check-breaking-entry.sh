#!/usr/bin/env bash
#
# Fails unless the `## [Unreleased]` section of the CHANGELOG has a
# `### BREAKING` heading with at least one entry under it. The semver
# workflow runs this in place of the blocking `aitp` check when a PR
# carries the `semver-break-approved` label (STABILITY.md).
set -euo pipefail

changelog="${1:-crates/aitp/CHANGELOG.md}"

entries=$(awk '
  /^## \[Unreleased\]/ { in_unreleased = 1; next }
  in_unreleased && /^## / { exit }
  in_unreleased && /^### / { in_breaking = ($0 ~ /^### BREAKING[[:space:]]*$/); next }
  in_unreleased && in_breaking && /^- / { n++ }
  END { print n + 0 }
' "$changelog")

if [ "$entries" -eq 0 ]; then
  echo "::error file=$changelog::semver-break-approved needs a '### BREAKING' entry under '## [Unreleased]'" >&2
  exit 1
fi
echo "$changelog: $entries BREAKING entr$([ "$entries" -eq 1 ] && echo y || echo ies) under [Unreleased]"
