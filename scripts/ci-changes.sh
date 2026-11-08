#!/usr/bin/env bash
#
# Decide whether a CI run needs the Rust jobs: writes rust=true|false to
# $GITHUB_OUTPUT (or stdout when it is unset). Used by ci.yml's `changes` job.
#
#   EVENT_NAME=pull_request REPO=owner/name PR_NUMBER=N scripts/ci-changes.sh
#
# It FAILS CLOSED: rust=false only when the PR's file list was read
# successfully and no file in it (old or new path of a rename) matches a Rust
# or build input. Any other event (push to main, workflow_dispatch), a listing
# failure, an empty listing (a PR always changes something) or a listing at
# the API's 3000-file cap gives rust=true. A skipped required check counts
# as passing, so a wrong "false" would merge unchecked code; a wrong "true"
# only spends minutes.
set -euo pipefail

out="${GITHUB_OUTPUT:-/dev/stdout}"
emit() { echo "rust=$1" >>"$out"; echo "→ rust=$1${2:+ ($2)}"; }
closed() { echo "::warning::$1 — failing CLOSED: running the Rust jobs"; emit true "FAILED CLOSED"; exit 0; }

# Paths whose change can affect a Rust build, test or the peer image.
# examples/ holds a workspace member (examples/two-agents); keep this in step with Cargo.toml's members.
RUST_RE='^(crates/|tests/|examples/|scripts/|tools/|deploy/|\.cargo/|\.github/workflows/)|^(Cargo\.toml|Cargo\.lock|rust-toolchain\.toml|clippy\.toml|rustfmt\.toml|deny\.toml)$|(^|/)Dockerfile$|^\.dockerignore$'

event="${EVENT_NAME:-}"
if [ "$event" != pull_request ]; then
  emit true "event '${event:-unset}' always runs everything"
  exit 0
fi
[ -n "${REPO:-}" ] && [ -n "${PR_NUMBER:-}" ] || closed "REPO or PR_NUMBER is unset"

# One line per changed file: the path, then the previous path of a rename (or empty).
if ! listing="$(gh api "repos/$REPO/pulls/$PR_NUMBER/files" --paginate \
    --jq '.[] | "\(.filename)\t\(.previous_filename // "")"')"; then
  closed "could not list this PR's changed files"
fi
[ -n "$listing" ] || closed "the PR's file list is empty"
n="$(wc -l <<<"$listing" | tr -d ' ')"
[ "$n" -lt 3000 ] || closed "the PR lists $n files, at the API's 3000-file cap, so the list may be incomplete"

paths="$(tr '\t' '\n' <<<"$listing" | sed '/^$/d' | sort -u)"
echo "changed files ($n):"
while IFS= read -r p; do echo "  $p"; done <<<"$paths"
if grep -Eq "$RUST_RE" <<<"$paths"; then emit true; else emit false "no Rust or build input changed"; fi
