#!/usr/bin/env bash
#
# Offline tests for deploy/doppler-sync.sh.
#
#   scripts/doppler-sync-test.sh
#
# Fake `curl` and `doppler` binaries go first on PATH. The fake curl answers
# Railway GraphQL from a JSON state file (and applies variableUpsert to it);
# the fake doppler prints another. Each case runs the sync from a throwaway
# git repo holding a copy of the script and allowlist, so the clean/dirty
# tree checks run for real. Nothing touches the network.
# The bash -c test bodies and the reference strings are single-quoted on purpose.
# shellcheck disable=SC2016
set -euo pipefail

src="$(cd "$(dirname "$0")/.." && pwd -P)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# A fake secret: multi-line, like AITP_PEER_KEY. It must never appear in output or argv.
SECRET=$'-----BEGIN FAKE-----\nfake-SEKRET-7f3a91\naid: aid:pubkey:fake'
SECRET2='fake-SEKRET-rotated-c0ffee'
export SECRET SECRET2

mkdir -p "$work/bin"
cat >"$work/bin/curl" <<'EOF'
#!/usr/bin/env bash
# Fake curl for Railway GraphQL. Logs argv and the operation, never the body.
# The bash -c test bodies and the reference strings are single-quoted on purpose.
# shellcheck disable=SC2016
set -euo pipefail
printf '%s\n' "$*" >>"$FAKE/argv.log"
body="$(cat)"
q="$(jq -r .query <<<"$body")"
if [ -n "${FAKE_GQL_ERROR:-}" ]; then echo '{"errors":[{"message":"boom"}]}'; exit 0; fi
case "$q" in
  *'project(id'*)
    echo 'project' >>"$FAKE/calls.log"
    echo '{"data":{"project":{"environments":{"edges":[{"node":{"id":"env-prod","name":"production"}},{"node":{"id":"env-stg","name":"staging"}}]},"services":{"edges":[{"node":{"id":"svc-1","name":"interop-peer"}}]}}}}' ;;
  *'variableUpsert'*)
    echo 'variableUpsert' >>"$FAKE/calls.log"
    if [ -z "${FAKE_UPSERT_NOOP:-}" ]; then
      jq --argjson i "$(jq -c .variables.i <<<"$body")" '.[$i.name] = $i.value' "$FAKE/railway.json" >"$FAKE/railway.tmp"
      mv "$FAKE/railway.tmp" "$FAKE/railway.json"
    fi
    jq -c .variables.i.skipDeploys <<<"$body" >>"$FAKE/skipdeploys.log"
    echo '{"data":{"variableUpsert":true}}' ;;
  *'serviceInstanceRedeploy'*)
    echo 'serviceInstanceRedeploy' >>"$FAKE/calls.log"
    echo '{"data":{"serviceInstanceRedeploy":true}}' ;;
  *'variables('*)
    echo "variables $(jq -r .variables.e <<<"$body")" >>"$FAKE/calls.log"
    jq -c '{data: {variables: .}}' "$FAKE/railway.json" ;;
  *) echo "fake curl: unexpected query" >&2; exit 1 ;;
esac
EOF
cat >"$work/bin/doppler" <<'EOF'
#!/usr/bin/env bash
# The bash -c test bodies and the reference strings are single-quoted on purpose.
# shellcheck disable=SC2016
set -euo pipefail
printf 'doppler %s\n' "$*" >>"$FAKE/argv.log"
case "$*" in
  'secrets download '*) cat "$FAKE/doppler.json" ;;
  *) echo "fake doppler: unexpected call: $*" >&2; exit 1 ;;
esac
EOF
chmod +x "$work/bin/curl" "$work/bin/doppler"
export PATH="$work/bin:$PATH" RAILWAY_API_TOKEN=fake-token

pass=0
fail=0
ok() { pass=$((pass + 1)); printf 'ok   %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL %s\n' "$1"; [ -z "${2:-}" ] || printf '     %s\n' "$2"; }

# A fresh fixture: a committed repo with the script and allowlist, Doppler and
# Railway agreeing on every managed key, Railway also holding RAILWAY_DOCKERFILE_PATH.
n=0
setup() {
  n=$((n + 1))
  export FAKE="$work/case$n"
  repo="$FAKE/repo"
  mkdir -p "$repo/deploy"
  cp "$src/deploy/doppler-sync.sh" "$src/deploy/doppler-keys.txt" "$repo/deploy/"
  git -C "$repo" init -q
  git -C "$repo" -c commit.gpgsign=false -c core.hooksPath=/dev/null -c user.email=t@example.invalid -c user.name=t add deploy
  git -C "$repo" -c commit.gpgsign=false -c core.hooksPath=/dev/null -c user.email=t@example.invalid -c user.name=t commit -qm fixture
  jq -n --arg s "$SECRET" '{
      AITP_PEER_KEY: $s, AITP_PUBLIC_URL: "https://peer.example", AITP_TRUSTED_PROXIES: "100.64.0.0/10",
      AITP_CLIENT_IP_HEADER: "x-real-ip", RUST_LOG: "info",
      DOPPLER_PROJECT: "aitp-interop-peer", DOPPLER_CONFIG: "prd", DOPPLER_ENVIRONMENT: "prd"}' >"$FAKE/doppler.json"
  jq 'del(.DOPPLER_PROJECT, .DOPPLER_CONFIG, .DOPPLER_ENVIRONMENT) + {RAILWAY_DOCKERFILE_PATH: "deploy/interop-peer/Dockerfile"}' \
    "$FAKE/doppler.json" >"$FAKE/railway.json"
  : >"$FAKE/calls.log"
  : >"$FAKE/argv.log"
  : >"$FAKE/skipdeploys.log"
}
commit_fixture() { git -C "$repo" -c commit.gpgsign=false -c core.hooksPath=/dev/null -c user.email=t@example.invalid -c user.name=t commit -qam change; }
set_doppler() { jq --arg k "$1" --arg v "$2" '.[$k] = $v' "$FAKE/doppler.json" >"$FAKE/d.tmp" && mv "$FAKE/d.tmp" "$FAKE/doppler.json"; }
set_railway() { jq --arg k "$1" --arg v "$2" '.[$k] = $v' "$FAKE/railway.json" >"$FAKE/r.tmp" && mv "$FAKE/r.tmp" "$FAKE/railway.json"; }
del_railway() { jq --arg k "$1" 'del(.[$k])' "$FAKE/railway.json" >"$FAKE/r.tmp" && mv "$FAKE/r.tmp" "$FAKE/railway.json"; }

# Run the sync; sets $code and $out (stdout+stderr).
run() {
  set +e
  out="$(bash "$repo/deploy/doppler-sync.sh" "$@" 2>&1)"
  code=$?
  set -e
  printf '%s\n' "$out" >>"$work/all-output.log"
}
count() { grep -c "^$1" "$FAKE/calls.log" || true; }
expect() { # expect <name> <condition-description> <test-expression...>
  local name="$1"; shift
  if "$@"; then ok "$name"; else bad "$name" "exit=$code; output: $(tr '\n' '|' <<<"$out")"; fi
}
has() { grep -qF -- "$1" <<<"$out"; }
writes() { [ "$(count variableUpsert)" = "$1" ] && [ "$(count serviceInstanceRedeploy)" = "$2" ]; }

# 1. Dry run, everything agrees: exit 0, fingerprints match, no write.
setup; run
expect "dry run, all unchanged: exit 0, match, no write" \
  bash -c '[ "$0" = 0 ] && grep -q "fingerprints match" <<<"$1" && grep -q "AITP_PEER_KEY	unchanged" <<<"$1"' "$code" "$out"
expect "dry run makes no variableUpsert and no serviceInstanceRedeploy" writes 0 0
expect "dry run names the unmanaged Railway key without managing it" has "left alone (not in doppler-keys.txt): RAILWAY_DOCKERFILE_PATH"

# 2. Dry run with a changed key: reports it, exits 0, still no write.
setup; set_doppler RUST_LOG debug; run
expect "dry run, changed key: exit 0, reported, no write" \
  bash -c '[ "$0" = 0 ] && grep -q "RUST_LOG	changed" <<<"$1" && grep -q "disagree on: RUST_LOG" <<<"$1" && grep -q "fingerprints differ" <<<"$1"' "$code" "$out"
expect "dry run with a changed key writes nothing" writes 0 0

# 3. --apply when everything agrees: no-op, no write, no redeploy.
setup; run --apply
expect "apply, all unchanged: exit 0 and prints no-op" bash -c '[ "$0" = 0 ] && grep -q "^no-op" <<<"$1"' "$code" "$out"
expect "apply, all unchanged: 0 upserts, 0 redeploys" writes 0 0

# 4. --apply with a changed key and no --push: refuses, names the key, writes nothing.
setup; set_doppler AITP_PEER_KEY "$SECRET2"; run --apply
expect "apply, changed without --push: non-zero, names the key" \
  bash -c '[ "$0" != 0 ] && grep -q "disagree on AITP_PEER_KEY" <<<"$1"' "$code" "$out"
expect "apply, changed without --push: 0 upserts, 0 redeploys" writes 0 0

# 5. --apply --push K: exactly 1 upsert (skipDeploys) and 1 redeploy; Railway now holds Doppler's value.
setup; set_doppler AITP_PEER_KEY "$SECRET2"; run --apply --push AITP_PEER_KEY
expect "apply --push K: exit 0, fingerprint match after the write" bash -c '[ "$0" = 0 ] && grep -q "fingerprint after the write: .* (match)" <<<"$1"' "$code" "$out"
expect "apply --push K: 1 upsert, 1 redeploy" writes 1 1
expect "apply --push K: the upsert sets skipDeploys" bash -c '[ "$(cat "$0")" = true ]' "$FAKE/skipdeploys.log"
expect "apply --push K: Railway now holds the Doppler value" bash -c '[ "$(jq -r .AITP_PEER_KEY "$0")" = "$SECRET2" ]' "$FAKE/railway.json"

# 6. --apply --push K --no-redeploy: 1 upsert, 0 redeploys.
setup; set_doppler RUST_LOG debug; run --apply --push RUST_LOG --no-redeploy
expect "apply --push K --no-redeploy: exit 0" bash -c '[ "$0" = 0 ]' "$code"
expect "apply --push K --no-redeploy: 1 upsert, 0 redeploys" writes 1 0

# 7. A key Railway lacks is new: written without --push.
setup; del_railway AITP_PUBLIC_URL; run --apply
expect "apply, new key: exit 0" bash -c '[ "$0" = 0 ] && grep -q "AITP_PUBLIC_URL	new" <<<"$1"' "$code" "$out"
expect "apply, new key: 1 upsert, 1 redeploy" writes 1 1

# 8. The write did not land (fingerprint after differs): non-zero and no redeploy.
setup; set_doppler RUST_LOG debug; FAKE_UPSERT_NOOP=1 run --apply --push RUST_LOG
expect "apply, write did not land: non-zero, no redeploy" bash -c '[ "$0" != 0 ] && grep -q "no redeploy" <<<"$1"' "$code" "$out"
expect "apply, write did not land: 0 redeploys" bash -c '[ "$(grep -c serviceInstanceRedeploy "$0" || true)" = 0 ]' "$FAKE/calls.log"

# 9. Dirty allowlist under --apply: refuses before any network call.
setup; echo EXTRA_KEY >>"$repo/deploy/doppler-keys.txt"; run --apply
expect "apply, dirty allowlist: non-zero before any network call" \
  bash -c '[ "$0" != 0 ] && grep -q "uncommitted changes" <<<"$1" && [ ! -s "$2" ]' "$code" "$out" "$FAKE/argv.log"

# 10. Dirty sync script under --apply: refuses.
setup; echo '# local edit' >>"$repo/deploy/doppler-sync.sh"; run --apply
expect "apply, dirty sync script: non-zero before any network call" \
  bash -c '[ "$0" != 0 ] && grep -q "uncommitted changes" <<<"$1" && [ ! -s "$2" ]' "$code" "$out" "$FAKE/argv.log"

# 11. Untracked script and allowlist under --apply: refuses.
setup; git -C "$repo" rm -q --cached deploy/doppler-sync.sh deploy/doppler-keys.txt
git -C "$repo" -c commit.gpgsign=false -c core.hooksPath=/dev/null -c user.email=t@example.invalid -c user.name=t commit -qm untrack; run --apply
expect "apply, untracked allowlist: non-zero before any network call" \
  bash -c '[ "$0" != 0 ] && grep -q "is not committed" <<<"$1" && [ ! -s "$2" ]' "$code" "$out" "$FAKE/argv.log"

# 12. An unrelated dirty file does not block --apply.
setup; echo scratch >"$repo/unrelated.txt"; run --apply
expect "apply, unrelated dirty file: not blocked (no-op)" bash -c '[ "$0" = 0 ] && grep -q "^no-op" <<<"$1"' "$code" "$out"

# 13. A dry run does not check the tree.
setup; echo EXTRA_KEY_TWO >>"$repo/deploy/doppler-keys.txt"; set_doppler EXTRA_KEY_TWO x; set_railway EXTRA_KEY_TWO x; run
expect "dry run, dirty allowlist: still runs" bash -c '[ "$0" = 0 ]' "$code"

# 14. RAILWAY_* on the allowlist: refused, dry run included.
setup; echo RAILWAY_X >>"$repo/deploy/doppler-keys.txt"; commit_fixture; run
expect "RAILWAY_X on the allowlist: non-zero, names the key" \
  bash -c '[ "$0" != 0 ] && grep -q "RAILWAY_X is a Railway system variable" <<<"$1"' "$code" "$out"

# 15. A Railway reference in Doppler, in Railway, and an unresolved Doppler reference: all refused in a dry run.
setup; set_doppler AITP_PUBLIC_URL '${{ shared.URL }}'; run
expect "\${{ in a Doppler value: non-zero, names the key" \
  bash -c '[ "$0" != 0 ] && grep -q "AITP_PUBLIC_URL	doppler-value-is-a-reference" <<<"$1" && grep -q "refusing: AITP_PUBLIC_URL" <<<"$1"' "$code" "$out"
setup; set_railway AITP_PUBLIC_URL '${{ shared.URL }}'; run
expect "\${{ in a Railway value: non-zero, names the key" \
  bash -c '[ "$0" != 0 ] && grep -q "AITP_PUBLIC_URL	railway-reference" <<<"$1"' "$code" "$out"
setup; set_doppler AITP_PEER_KEY '${prd.AITP_PEER_KEY}'; run
expect "\${ (unresolved) in a Doppler value: non-zero, names the key" \
  bash -c '[ "$0" != 0 ] && grep -q "AITP_PEER_KEY	doppler-value-unresolved" <<<"$1"' "$code" "$out"
setup; set_railway AITP_PUBLIC_URL '${{ shared.URL }}'; run --apply
expect "\${{ in a Railway value under --apply: 0 upserts, 0 redeploys" writes 0 0

# 16. A key missing in Doppler: refused, dry run included.
setup; jq 'del(.RUST_LOG)' "$FAKE/doppler.json" >"$FAKE/d.tmp" && mv "$FAKE/d.tmp" "$FAKE/doppler.json"; run
expect "key missing in Doppler: non-zero, names the key" \
  bash -c '[ "$0" != 0 ] && grep -q "RUST_LOG	missing-in-doppler" <<<"$1" && grep -q "refusing: RUST_LOG" <<<"$1"' "$code" "$out"

# 17. A GraphQL error: non-zero.
setup; FAKE_GQL_ERROR=1 run
expect "GraphQL error: non-zero, error text not echoed" bash -c '[ "$0" != 0 ] && grep -q "railway: the API returned 1 error" <<<"$1" && ! grep -q boom <<<"$1"' "$code" "$out"

# 18. Arguments.
setup; run --bogus
expect "unknown argument: exit 2" bash -c '[ "$0" = 2 ]' "$code"
setup; run --environment dev
expect "unknown environment: exit 2" bash -c '[ "$0" = 2 ]' "$code"
setup; run --apply --push NOT_LISTED
expect "--push of a key not on the allowlist: non-zero" bash -c '[ "$0" != 0 ] && grep -q "not in doppler-keys.txt" <<<"$1"' "$code" "$out"

# 19. staging reads Doppler config stg and Railway environment staging.
setup; run --environment staging
expect "staging: Doppler config stg, Railway env-stg" \
  bash -c '[ "$0" = 0 ] && grep -q -- "--config stg" "$1" && grep -q "variables env-stg" "$2"' "$code" "$FAKE/argv.log" "$FAKE/calls.log"

# 20. No secret value in any output or in any argv, and no delete mutation in the script.
leaks=0
for f in "$work"/all-output.log "$work"/case*/argv.log; do
  if grep -qF -e 'fake-SEKRET' -e 'fake-token' "$f"; then leaks=1; fi
done
if [ "$leaks" = 0 ]; then ok "no fake secret or token in any output or argv"; else bad "no fake secret or token in any output or argv"; fi
if grep -qE '[A-Za-z]+Delete[[:space:]]*\(' "$src/deploy/doppler-sync.sh"; then
  bad "the sync script has no delete mutation"
else ok "the sync script has no delete mutation"; fi

# A dry run with a key that is new to Railway still writes nothing.
setup; del_railway RUST_LOG; run
expect "dry run, new key: exit 0, says it would write, no write" \
  bash -c '[ "$0" = 0 ] && grep -q "would be written: RUST_LOG" <<<"$1"' "$code" "$out"
expect "dry run, new key: 0 upserts, 0 redeploys" writes 0 0

# A missing-in-Doppler key gets the "set it in Doppler first" hint.
setup; jq 'del(.RUST_LOG)' "$FAKE/doppler.json" >"$FAKE/d.tmp" && mv "$FAKE/d.tmp" "$FAKE/doppler.json"; run
expect "missing in Doppler: non-zero, says set it in Doppler first" \
  bash -c '[ "$0" != 0 ] && grep -q "RUST_LOG not set in Doppler; set each in Doppler first" <<<"$1"' "$code" "$out"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" = 0 ]
