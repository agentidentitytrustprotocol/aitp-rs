#!/usr/bin/env bash
#
# Vendor JSON Schemas from the AITP spec repo into tests/schemas/.
#
# Records the source commit hash to tests/schemas/SPEC_VERSION so that
# CI can detect drift between the vendored copies and the spec repo at
# review time.
#
# Usage:
#   scripts/sync-schemas.sh                      # uses ../agentidentitytrustprotocol
#   AITP_SPEC=/path/to/spec scripts/sync-schemas.sh
#
# After running, review the diff and commit the result.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SPEC_REPO="${AITP_SPEC:-$REPO_ROOT/../agentidentitytrustprotocol}"

if [ ! -d "$SPEC_REPO/schemas/json" ]; then
  echo "error: spec schemas not found at $SPEC_REPO/schemas/json" >&2
  echo "set AITP_SPEC to the spec repo root, or clone it as a sibling." >&2
  exit 1
fi

DEST="$REPO_ROOT/tests/schemas"
mkdir -p "$DEST"

# MIRROR, don't copy. The destination is cleared first so a file DELETED
# upstream disappears here too.
#
# This is not a tidiness preference. Without it the CI drift check
# ("vendored schemas in sync") reports green over a stale file: the check
# re-runs this script and fails on `git diff`, but a copy-only sync never
# removes anything, so there is no diff to see. Demonstrated: deleting
# aitp-tct.schema.json from a spec checkout and re-syncing left the stale
# vendored copy in place with a clean `git status`. A check that cannot
# fail is the same defect class as the KAT harness this repo just fixed.
echo "Mirroring schemas from $SPEC_REPO/schemas/json/ -> $DEST/"
rm -f "$DEST"/*.schema.json
cp "$SPEC_REPO"/schemas/json/*.schema.json "$DEST/"

# Vendor the spec's known-answer test vectors next to the schemas.
# Implementations validate their output byte-for-byte against these files
# in tests/kat.rs in each crate that owns the relevant types.
if [ -d "$SPEC_REPO/schemas/conformance/known-answer" ]; then
  rm -rf "$DEST/known-answer"
  mkdir -p "$DEST/known-answer"
  # `*.md` as well as `*.json`: the spec's known-answer/README.md documents
  # the "verify as committed, never re-mint first" rule and had never been
  # vendored, so the trees were never actually identical.
  cp "$SPEC_REPO"/schemas/conformance/known-answer/*.json "$DEST/known-answer/" 2>/dev/null || true
  cp "$SPEC_REPO"/schemas/conformance/known-answer/*.md "$DEST/known-answer/" 2>/dev/null || true
  # Signed-example vectors (real compact-JWS tokens, v0.2) live one level
  # deeper; vendor them too so jws KAT tests can pin against them.
  if [ -d "$SPEC_REPO/schemas/conformance/known-answer/signed-examples" ]; then
    mkdir -p "$DEST/known-answer/signed-examples"
    cp -R "$SPEC_REPO"/schemas/conformance/known-answer/signed-examples/. \
      "$DEST/known-answer/signed-examples/"
  fi
  echo "Copied known-answer/ test vectors."
fi

# Record source commit hash for drift detection.
if (cd "$SPEC_REPO" && git rev-parse HEAD >/dev/null 2>&1); then
  SPEC_HASH="$(cd "$SPEC_REPO" && git rev-parse HEAD)"
  echo "$SPEC_HASH" > "$DEST/SPEC_VERSION"
  echo "Pinned to spec commit: $SPEC_HASH"
else
  echo "warn: spec repo has no git history; SPEC_VERSION not updated." >&2
fi

echo
echo "Done. Review diff:"
echo "  git diff -- $DEST"
