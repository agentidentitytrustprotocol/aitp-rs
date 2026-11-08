#!/usr/bin/env bash
#
# Decide whether a CI run needs the Rust jobs: writes rust=true|false to
# $GITHUB_OUTPUT (or stdout when it is unset). Used by ci.yml's `changes` job.
#
#   EVENT_NAME=pull_request REPO=owner/name PR_NUMBER=N scripts/ci-changes.sh
#   EVENT_NAME=merge_group BASE_SHA=<sha> HEAD_SHA=<sha> scripts/ci-changes.sh
#
# It FAILS CLOSED: rust=false only when the change list was read successfully
# and no file in it (old or new path of a rename) matches a Rust or build
# input. For a pull_request the list is the PR's file listing (API); for a
# merge_group it is `git diff BASE_SHA HEAD_SHA` in the current checkout,
# fetching either commit from origin (depth 1) when it is absent. Any other
# event (push to main, workflow_dispatch), a listing or diff failure, a
# missing or malformed SHA, an empty list (a PR always changes something) or
# a listing at the API's 3000-file cap gives rust=true. A skipped required
# check counts as passing, so a wrong "false" would merge unchecked code; a
# wrong "true" only spends minutes.
set -euo pipefail

out="${GITHUB_OUTPUT:-/dev/stdout}"
emit() { echo "rust=$1" >>"$out"; echo "→ rust=$1${2:+ ($2)}"; }
closed() { echo "::warning::$1 — failing CLOSED: running the Rust jobs"; emit true "FAILED CLOSED"; exit 0; }

# Paths whose change can affect a Rust build, test or the peer image.
# examples/ holds a workspace member (examples/two-agents); keep this in step with Cargo.toml's members.
RUST_RE='^(crates/|tests/|examples/|scripts/|tools/|deploy/|\.cargo/|\.github/workflows/)|^(Cargo\.toml|Cargo\.lock|rust-toolchain\.toml|clippy\.toml|rustfmt\.toml|deny\.toml)$|(^|/)Dockerfile$|^\.dockerignore$'

# classify <newline-separated paths> <count>: print them, emit the verdict.
classify() {
  local paths
  paths="$(sed '/^$/d' <<<"$1" | sort -u)"
  echo "changed files ($2):"
  while IFS= read -r p; do echo "  $p"; done <<<"$paths"
  if grep -Eq "$RUST_RE" <<<"$paths"; then emit true; else emit false "no Rust or build input changed"; fi
}

event="${EVENT_NAME:-}"
case "$event" in
  pull_request) ;;
  merge_group)
    # The queue's temporary branch (HEAD_SHA) against the branch it merges
    # into (BASE_SHA): every PR in the group, not just the last one.
    for sha in "${BASE_SHA:-}" "${HEAD_SHA:-}"; do
      [[ "$sha" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]] || closed "BASE_SHA or HEAD_SHA is unset or not a commit SHA ('$sha')"
      if ! git cat-file -e "$sha^{commit}" 2>/dev/null; then
        if ! { git fetch --no-tags --quiet --depth=1 origin "$sha" && git cat-file -e "$sha^{commit}" 2>/dev/null; }; then
          closed "could not fetch commit $sha"
        fi
      fi
    done
    # --no-renames lists a rename as delete + add, so both paths are
    # classified; -z keeps unusual paths raw (unquoted) so the regex sees them.
    if ! listing="$(git diff -z --name-only --no-renames "$BASE_SHA" "$HEAD_SHA" -- | tr '\0' '\n')"; then
      closed "could not diff $BASE_SHA..$HEAD_SHA"
    fi
    [ -n "$listing" ] || closed "the merge group's diff is empty"
    classify "$listing" "$(wc -l <<<"$listing" | tr -d ' ')"
    exit 0
    ;;
  *)
    emit true "event '${event:-unset}' always runs everything"
    exit 0
    ;;
esac
[ -n "${REPO:-}" ] && [ -n "${PR_NUMBER:-}" ] || closed "REPO or PR_NUMBER is unset"

# One line per changed file: the path, then the previous path of a rename (or empty).
if ! listing="$(gh api "repos/$REPO/pulls/$PR_NUMBER/files" --paginate \
    --jq '.[] | "\(.filename)\t\(.previous_filename // "")"')"; then
  closed "could not list this PR's changed files"
fi
[ -n "$listing" ] || closed "the PR's file list is empty"
n="$(wc -l <<<"$listing" | tr -d ' ')"
[ "$n" -lt 3000 ] || closed "the PR lists $n files, at the API's 3000-file cap, so the list may be incomplete"

classify "$(tr '\t' '\n' <<<"$listing")" "$n"
