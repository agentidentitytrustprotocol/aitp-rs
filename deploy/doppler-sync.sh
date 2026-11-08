#!/usr/bin/env bash
#
# Sync the interop peer's Railway variables from Doppler, the source of truth.
#
#   deploy/doppler-sync.sh [--environment E]          # dry run (default): key names and statuses, never values
#   deploy/doppler-sync.sh --apply [--environment E]  # write new keys into Railway, then redeploy
#   deploy/doppler-sync.sh --apply --push KEY ...     # also overwrite KEY, whose Railway value differs
#   deploy/doppler-sync.sh --apply --no-redeploy      # write, but leave the running deployment alone
#
#   --environment E   Railway environment: production (default; Doppler config
#                     prd) or staging (Doppler config stg).
#   --push KEY        Repeatable. Acknowledges that Doppler's value of KEY is the
#                     one to keep. Without it, --apply refuses a key whose
#                     Railway value differs from Doppler's: when the two
#                     disagree, a person decides which one wins, never the script.
#
# Only the keys listed in deploy/doppler-keys.txt are managed. The script never
# deletes a variable and never touches a key it does not list. It refuses
# RAILWAY_* system variables, Railway references (values containing "${{") on
# either side, and Doppler values still containing "${" (an unresolved Doppler
# reference). Refusals exit non-zero, in a dry run too.
#
# Values move by pipe only: Doppler -> jq -> the Railway GraphQL request body on
# curl's stdin. Nothing is printed, written to disk or passed in argv. The check
# is a sha256 over the managed KEY=VALUE pairs, Doppler vs Railway, before and
# after a write. A redeploy happens only when at least one value was written.
#
# Needs bash, git, jq, curl and the doppler CLI logged in, plus a Railway token:
# RAILWAY_API_TOKEN (an account or workspace token) or the railway CLI login
# (~/.railway/config.json). --apply refuses to run while this script or the
# allowlist is uncommitted or modified, so what it applies is what was reviewed.
# It runs from your checkout, not from the git ref being deployed.

# Railway GraphQL queries are single-quoted on purpose.
# shellcheck disable=SC2016
set -euo pipefail

RAILWAY_PROJECT_ID=25c1e9f5-cf97-4a97-ac99-420d8b049088 # Railway: aitp-interop-peer
RAILWAY_SERVICE=interop-peer
DOPPLER_PROJECT=aitp-interop-peer

usage() { sed -n '2,32p' "$0"; }

mode=dry-run
redeploy=1
environment=production
push=()
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) mode=dry-run ;;
    --apply) mode=apply ;;
    --no-redeploy) redeploy=0 ;;
    --environment)
      [ $# -ge 2 ] || { echo "--environment needs a name" >&2; exit 2; }
      environment="$2"; shift ;;
    --push)
      [ $# -ge 2 ] || { echo "--push needs a key name" >&2; exit 2; }
      push+=("$2"); shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

case "$environment" in
  production) doppler_config=prd ;;
  staging) doppler_config=stg ;;
  *) echo "unknown environment: $environment (production or staging)" >&2; exit 2 ;;
esac

say() { printf '%s\n' "$*" >&2; }
die() { say "error: $*"; exit 1; }
for c in git jq curl doppler; do command -v "$c" >/dev/null || die "$c is not on PATH"; done
if command -v sha256sum >/dev/null; then sha256() { sha256sum; }
elif command -v shasum >/dev/null; then sha256() { shasum -a 256; }
else die "neither sha256sum nor shasum is on PATH"; fi

here="$(cd "$(dirname "$0")" && pwd -P)"
repo="$(git -C "$here" rev-parse --show-toplevel)"
keys_file="$here/doppler-keys.txt"
[ -f "$keys_file" ] || die "$keys_file is missing"

# --apply uses only what is committed: this script and the allowlist must be
# tracked and unmodified. Other files in the tree do not matter.
if [ "$mode" = apply ]; then
  for f in "$here/doppler-sync.sh" "$keys_file"; do
    git -C "$repo" ls-files --error-unmatch -- "$f" >/dev/null 2>&1 ||
      die "${f#"$repo"/} is not committed; commit it so --apply uses the reviewed version"
  done
  git -C "$repo" diff --quiet HEAD -- "$here/doppler-sync.sh" "$keys_file" ||
    die "deploy/doppler-sync.sh or deploy/doppler-keys.txt has uncommitted changes; commit or stash them first"
fi

# The allowlist: one KEY per line; '#' comments and blank lines are ignored.
keys=()
while IFS= read -r line || [ -n "$line" ]; do
  k="${line%%#*}"
  k="$(printf '%s' "$k" | tr -d '[:space:]')"
  [ -n "$k" ] || continue
  [[ "$k" =~ ^[A-Z_][A-Z0-9_]*$ ]] || die "doppler-keys.txt: '$k' is not a valid variable name"
  [[ "$k" == RAILWAY_* ]] && die "doppler-keys.txt: $k is a Railway system variable; Railway owns it"
  keys+=("$k")
done <"$keys_file"
[ "${#keys[@]}" -gt 0 ] || die "doppler-keys.txt lists no keys"
keys_json="$(printf '%s\n' "${keys[@]}" | jq -R . | jq -sc 'unique')"

push_json='[]'
if [ "${#push[@]}" -gt 0 ]; then
  for k in "${push[@]}"; do
    jq -e --arg k "$k" 'index($k) != null' <<<"$keys_json" >/dev/null ||
      die "--push $k: not in doppler-keys.txt"
  done
  push_json="$(printf '%s\n' "${push[@]}" | jq -R . | jq -sc 'unique')"
fi

railway_token="${RAILWAY_API_TOKEN:-$(jq -r '.user.accessToken // .user.token // empty' ~/.railway/config.json 2>/dev/null || true)}"
[ -n "$railway_token" ] || die "no Railway token: log in with the railway CLI or set RAILWAY_API_TOKEN"

# POST a GraphQL request whose JSON body arrives on stdin, so values never reach argv.
# The token reaches curl as a config file on a process-substitution fd, also not argv.
railway_gql() {
  curl -fsS https://backboard.railway.com/graphql/v2 \
    -K <(printf 'header = "Authorization: Bearer %s"\n' "$railway_token") \
    -H 'content-type: application/json' --data-binary @- |
    jq -e 'if .errors then error("railway: the API returned \(.errors | length) error(s); the message text is not printed in case it quotes a submitted value") else .data end'
}
gql() { jq -nc --arg q "$1" --argjson v "${2:-{\}}" '{query: $q, variables: $v}' | railway_gql; }

ids="$(gql 'query($p: String!){project(id: $p){environments{edges{node{id name}}} services{edges{node{id name}}}}}' \
  "$(jq -nc --arg p "$RAILWAY_PROJECT_ID" '{p: $p}')")"
env_id="$(jq -r --arg n "$environment" '.project.environments.edges[].node | select(.name == $n) | .id' <<<"$ids")"
svc_id="$(jq -r --arg n "$RAILWAY_SERVICE" '.project.services.edges[].node | select(.name == $n) | .id' <<<"$ids")"
[ -n "$env_id" ] || die "Railway environment $environment not found in project $RAILWAY_PROJECT_ID"
[ -n "$svc_id" ] || die "Railway service $RAILWAY_SERVICE not found in project $RAILWAY_PROJECT_ID"
scope="$(jq -nc --arg p "$RAILWAY_PROJECT_ID" --arg e "$env_id" --arg s "$svc_id" '{p: $p, e: $e, s: $s}')"

# Raw (unrendered) service variables, so a reference shows up as ${{...}}, not its resolved value.
railway_vars() {
  gql 'query($p: String!, $e: String!, $s: String!){variables(projectId: $p, environmentId: $e, serviceId: $s, unrendered: true)}' \
    "$scope" | jq -c '.variables'
}
# Resolved (computed) values: a Doppler cross-config reference arrives as the value it points at.
doppler_vars() {
  doppler secrets download --project "$DOPPLER_PROJECT" --config "$doppler_config" --no-file --format json
}

# sha256 over the managed KEY=VALUE pairs, in key order, NUL-separated so a
# multi-line value hashes exactly. A key the side lacks is left out.
managed_hash() {
  jq -j --argjson k "$keys_json" '. as $v | [$k[] | select(. as $key | $v | has($key)) | "\(.)=\($v[.])"] | join("\u0000")' |
    sha256 | cut -c1-16
}

rv="$(railway_vars)"
dv="$(doppler_vars)"
jq -e 'type == "object"' <<<"$rv" >/dev/null || die "Railway returned no variables object"
jq -e 'type == "object"' <<<"$dv" >/dev/null || die "Doppler returned no secrets object"

# Per key: status only. The comparison happens inside jq; values never leave it.
plan="$(printf '%s\n%s\n' "$dv" "$rv" | jq -sc --argjson k "$keys_json" '
  .[0] as $d | .[1] as $r |
  [$k[] | . as $key | {key: $key, status: (
    if ($d | has($key) | not) then "missing-in-doppler"
    elif ($d[$key] | tostring | contains("${{")) then "doppler-value-is-a-reference"
    elif ($d[$key] | tostring | contains("${")) then "doppler-value-unresolved"
    elif ($r | has($key)) and ($r[$key] | tostring | contains("${{")) then "railway-reference"
    elif ($r | has($key) | not) then "new"
    elif $r[$key] == $d[$key] then "unchanged"
    else "changed" end)}]')"

say "Doppler $DOPPLER_PROJECT/$doppler_config -> Railway $RAILWAY_SERVICE ($environment), ${#keys[@]} managed key(s):"
jq -r '.[] | "  \(.key)\t\(.status)"' <<<"$plan" >&2
unmanaged="$(jq -r --argjson k "$keys_json" 'keys - $k | join(" ")' <<<"$rv")"
[ -z "$unmanaged" ] || say "  left alone (not in doppler-keys.txt): $unmanaged"

before="$(managed_hash <<<"$rv")"
want="$(managed_hash <<<"$dv")"
if [ "$before" = "$want" ]; then say "fingerprints match: railway $before, doppler $want"
else say "fingerprints differ: railway $before, doppler $want"; fi

missing="$(jq -r '[.[] | select(.status == "missing-in-doppler") | .key] | join(" ")' <<<"$plan")"
refs="$(jq -r '[.[] | select(.status | IN("doppler-value-is-a-reference", "doppler-value-unresolved", "railway-reference")) | .key] | join(" ")' <<<"$plan")"
[ -z "$missing" ] || say "refusing: $missing not set in Doppler; set each in Doppler first (by pipe, see docs/interop-peer.md)"
[ -z "$refs" ] || say "refusing: $refs hold a reference; Railway references stay Railway-managed, so drop them from doppler-keys.txt"
[ -z "$missing$refs" ] || die "refusing: see the lines above"

changed="$(jq -r '[.[] | select(.status == "changed") | .key] | join(" ")' <<<"$plan")"
unacked="$(jq -r --argjson p "$push_json" '[.[] | select(.status == "changed") | .key | select(. as $k | $p | index($k) | not)] | join(" ")' <<<"$plan")"
todo="$(jq -r --argjson p "$push_json" '.[] | select(.status == "new" or (.status == "changed" and (.key as $k | $p | index($k) != null))) | .key' <<<"$plan")"

if [ "$mode" = dry-run ]; then
  [ -z "$changed" ] || say "dry run: Doppler and Railway disagree on: $changed. --apply refuses these unless each is named with --push KEY"
  if [ -n "$todo" ]; then say "dry run: $(wc -w <<<"$todo" | tr -d ' ') key(s) would be written: $(tr '\n' ' ' <<<"$todo")"
  else say "dry run: nothing to write"; fi
  exit 0
fi

[ -z "$unacked" ] || die "refusing: Doppler and Railway disagree on $unacked. Decide which value is right; to keep Doppler's, rerun with --push KEY for each"

if [ -z "$todo" ]; then
  say "no-op: nothing to write, no redeploy"
  exit 0
fi

for key in $todo; do
  # The value goes Doppler -> jq -> curl stdin; it is never in argv or on disk.
  doppler_vars | jq -c --arg key "$key" --argjson s "$scope" '{
      query: "mutation($i: VariableUpsertInput!){variableUpsert(input: $i)}",
      variables: {i: {projectId: $s.p, environmentId: $s.e, serviceId: $s.s, name: $key, value: .[$key], skipDeploys: true}}}' |
    railway_gql >/dev/null
  say "  set $key"
done

after="$(railway_vars | managed_hash)"
[ "$after" = "$want" ] || die "fingerprint after the write is $after, expected $want; no redeploy. Check the service in Railway"
say "fingerprint after the write: $after (match)"

if [ "$redeploy" = 1 ]; then
  gql 'mutation($e: String!, $s: String!){serviceInstanceRedeploy(environmentId: $e, serviceId: $s)}' "$scope" >/dev/null
  say "redeploy triggered for $RAILWAY_SERVICE ($environment) so the new values take effect"
else
  say "no redeploy (--no-redeploy): the values apply on the next deploy"
fi
