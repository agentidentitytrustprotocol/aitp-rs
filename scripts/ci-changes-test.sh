#!/usr/bin/env bash
#
# Offline tests for scripts/ci-changes.sh, with a fake `gh` first on PATH.
#
#   scripts/ci-changes-test.sh
set -euo pipefail

src="$(cd "$(dirname "$0")/.." && pwd -P)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin"
# The fake gh prints $FAKE_GH_LISTING (tab-separated lines, as the --jq filter
# would) or fails when FAKE_GH_FAIL is set.
cat >"$work/bin/gh" <<'EOS'
#!/usr/bin/env bash
[ -z "${FAKE_GH_FAIL:-}" ] || { echo "gh: HTTP 403" >&2; exit 1; }
printf '%s' "${FAKE_GH_LISTING:-}"
EOS
chmod +x "$work/bin/gh"
export PATH="$work/bin:$PATH"

pass=0
fail=0
# check <name> <expected rust value> <expect a fail-closed warning: yes|no> [env assignments...]
check() {
  local name="$1" want="$2" warn="$3"; shift 3
  local o="$work/out" log
  : >"$o"
  log="$(env GITHUB_OUTPUT="$o" "$@" bash "$src/scripts/ci-changes.sh" 2>&1)" || { fail=$((fail + 1)); echo "FAIL $name (exit non-zero)"; return; }
  local got
  got="$(sed -n 's/^rust=//p' "$o")"
  local warned=no
  grep -q '::warning::' <<<"$log" && warned=yes
  if [ "$got" = "$want" ] && [ "$warned" = "$warn" ]; then pass=$((pass + 1)); echo "ok   $name"
  else fail=$((fail + 1)); echo "FAIL $name: rust=$got warning=$warned; $(tr '\n' '|' <<<"$log")"; fi
}
pr=(EVENT_NAME=pull_request REPO=o/r PR_NUMBER=7)
tab=$'\t'

check "listing failure fails closed" true yes "${pr[@]}" FAKE_GH_FAIL=1
check "empty listing fails closed" true yes "${pr[@]}" FAKE_GH_LISTING=
check "missing PR number fails closed" true yes EVENT_NAME=pull_request REPO=o/r
check "docs-only PR skips" false no "${pr[@]}" FAKE_GH_LISTING="docs/interop-peer.md${tab}
README.md${tab}
DECISIONS.md${tab}"
check "crates change runs" true no "${pr[@]}" FAKE_GH_LISTING="docs/a.md${tab}
crates/aitp/src/lib.rs${tab}"
check "a rename out of crates/ runs" true no "${pr[@]}" FAKE_GH_LISTING="docs/moved.rs${tab}crates/aitp/src/old.rs"
check "Cargo.lock runs" true no "${pr[@]}" FAKE_GH_LISTING="Cargo.lock${tab}"
check "a workflow change runs" true no "${pr[@]}" FAKE_GH_LISTING=".github/workflows/fuzz-pr.yml${tab}"
check "deploy/ runs" true no "${pr[@]}" FAKE_GH_LISTING="deploy/doppler-keys.txt${tab}"
check "a nested Dockerfile runs" true no "${pr[@]}" FAKE_GH_LISTING="examples/x/Dockerfile${tab}"
check ".dockerignore runs" true no "${pr[@]}" FAKE_GH_LISTING=".dockerignore${tab}"
check "a workspace example runs" true no "${pr[@]}" FAKE_GH_LISTING="examples/two-agents/src/main.rs${tab}"
check "clippy.toml runs" true no "${pr[@]}" FAKE_GH_LISTING="clippy.toml${tab}"
check "README and CHANGELOG only skip" false no "${pr[@]}" FAKE_GH_LISTING="README.md${tab}
CHANGELOG.md${tab}"
check "a docs path containing crates/ elsewhere skips" false no "${pr[@]}" FAKE_GH_LISTING="docs/crates/notes.md${tab}"
check "push event runs everything" true no EVENT_NAME=push
check "workflow_dispatch runs everything" true no EVENT_NAME=workflow_dispatch
big="$(for i in $(seq 1 3000); do printf 'docs/f%s.md\t\n' "$i"; done)"
check "a listing at the 3000-file cap fails closed" true yes "${pr[@]}" FAKE_GH_LISTING="$big"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" = 0 ]
