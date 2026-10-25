#!/usr/bin/env bash
#
# Deploy the public interop peer (docs/interop-peer.md) to Railway.
#
#   deploy/interop-peer/deploy.sh [--dry-run]        # default: print the plan, change nothing
#   deploy/interop-peer/deploy.sh --apply [--ref R]  # deploy git ref R (default origin/main)
#   deploy/interop-peer/deploy.sh --previous         # redeploy the deployment before the live one
#   deploy/interop-peer/deploy.sh --rollback         # take the peer offline; prints the DNS step
#
#   --environment E   Railway environment (default production). Any other
#                     environment is served at its Railway domain only.
#
# Needs git, jq, curl, dig and the railway and doppler CLIs, logged in;
# the post-deploy smoke test needs `aitp` on PATH (or $AITP).
#
# The peer key lives only in Doppler (aitp-interop-peer/prd, AITP_PEER_KEY)
# and is piped from there into Railway, never printed. It is the peer's
# identity: a new key is a new peer AID.
#
# DNS: in production, interop.agentidentitytrustprotocol.io is a CNAME at
# the domain's DNS host (Squarespace, which has no API) to the target
# Railway gives the custom domain. The script prints that record when it
# is missing, and the one to delete on --rollback.

# Railway GraphQL queries are single-quoted on purpose.
# shellcheck disable=SC2016
set -euo pipefail

PROJECT_ID=25c1e9f5-cf97-4a97-ac99-420d8b049088 # Railway: aitp-interop-peer
SERVICE=interop-peer
DOPPLER_PROJECT="aitp-interop-peer"
DOPPLER_CONFIG=prd
DOMAIN=interop.agentidentitytrustprotocol.io

mode=dry-run
ref=origin/main
environment=production
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) mode=dry-run ;;
    --apply) mode=apply ;;
    --previous) mode=previous ;;
    --rollback) mode=rollback ;;
    --ref) ref="${2:?--ref needs a git ref}"; shift ;;
    --environment) environment="${2:?--environment needs a name}"; shift ;;
    -h|--help) sed -n '2,23p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

repo="$(git rev-parse --show-toplevel)"
say() { printf '%s\n' "$*" >&2; }

railway_api() {
  local token="${RAILWAY_API_TOKEN:-$(jq -r '.user.accessToken // .user.token // empty' ~/.railway/config.json)}"
  curl -fsS https://backboard.railway.com/graphql/v2 \
    -H "Authorization: Bearer $token" -H 'content-type: application/json' \
    -d "$(jq -n --arg q "$1" --argjson v "${2:-null}" '{query: $q, variables: ($v // {})}')"
}

# The service's domains in $environment, as JSON.
domains() {
  railway_api 'query($p: String!){project(id: $p){environments{edges{node{name serviceInstances{edges{node{serviceName domains{serviceDomains{domain} customDomains{domain status{dnsRecords{requiredValue}}}}}}}}}}}}' \
    "$(jq -nc --arg p "$PROJECT_ID" '{p: $p}')" |
    jq -c --arg e "$environment" --arg s "$SERVICE" \
      '.data.project.environments.edges[].node | select(.name == $e)
       | .serviceInstances.edges[].node | select(.serviceName == $s) | .domains'
}
railway_domain() { domains | jq -r '.serviceDomains[0].domain // empty'; }
cname_target() { domains | jq -r --arg d "$DOMAIN" '.customDomains[] | select(.domain == $d) | .status.dnsRecords[0].requiredValue'; }

# The peer AID the Doppler key gives, without printing the key.
expected_aid() {
  doppler secrets get AITP_PEER_KEY --project "$DOPPLER_PROJECT" --config "$DOPPLER_CONFIG" --plain |
    sed -n 's/^aid: *//p'
}

status_of() { [ -n "$1" ] && curl -fsS -m 10 "https://$1/status" 2>/dev/null || true; }
# One line: the live peer's AID and version, or "unreachable".
live() {
  local s
  s="$(status_of "$1")"
  if [ -n "$s" ]; then jq -c '{aid, version, enrolled}' <<<"$s"; else echo unreachable; fi
}

# Wait until three probes in a row show the peer as $2 (an AID, or ""
# for offline): Railway's edge flaps while a deployment comes up or goes.
wait_for_aid() {
  local host="$1" want="$2" ok=0 _
  for _ in $(seq 1 90); do
    if [ "$(status_of "$host" | jq -r '.aid // empty' 2>/dev/null)" = "$want" ]; then
      ok=$((ok + 1))
      [ "$ok" -ge 3 ] && return 0
    else
      ok=0
    fi
    sleep 5
  done
  return 1
}

public_url() {
  if [ "$environment" = production ]; then echo "https://$DOMAIN"; else echo "https://$1"; fi
}

dns_note() {
  [ "$environment" = production ] || return 0
  if [ -z "$(dig +short CNAME "$DOMAIN")" ]; then
    say "DNS: $DOMAIN does not resolve yet. At the DNS host add: CNAME ${DOMAIN%%.*} -> $(cname_target)"
    return 1
  fi
}

# railway commands act on the directory's link; link a scratch one.
work="$(mktemp -d)"
trap 'git -C "$repo" worktree remove --force "$work/src" 2>/dev/null || true; rm -rf "$work"' EXIT
link() { (cd "$1" && railway link --project "$PROJECT_ID" --service "$SERVICE" --environment "$environment" >/dev/null); }
rw() { (cd "$work" && railway "$@"); }

case "$mode" in
dry-run)
  host="$(railway_domain)"
  say "plan for Railway $PROJECT_ID/$SERVICE ($environment); nothing changes without --apply:"
  say "  deploy:    $ref ($(git -C "$repo" rev-parse --short "$ref"))"
  say "  variables: AITP_PUBLIC_URL=$(public_url "${host:-<railway domain>}") AITP_TRUSTED_PROXIES=100.64.0.0/10"
  say "             AITP_CLIENT_IP_HEADER=x-real-ip RAILWAY_DOCKERFILE_PATH=deploy/interop-peer/Dockerfile RUST_LOG=info"
  say "             AITP_PEER_KEY=<doppler $DOPPLER_PROJECT/$DOPPLER_CONFIG> (peer $(expected_aid))"
  say "  live now:  ${host:-no Railway domain yet} $(live "$host")"
  dns_note || true
  ;;
apply)
  want="$(expected_aid)"
  [ -n "$want" ] || { say "no AITP_PEER_KEY in doppler $DOPPLER_PROJECT/$DOPPLER_CONFIG"; exit 1; }
  git -C "$repo" fetch -q origin
  git -C "$repo" worktree add -q --detach "$work/src" "$ref"
  link "$work"
  host="$(railway_domain)"
  [ -n "$host" ] || { rw domain --service "$SERVICE" >/dev/null; host="$(railway_domain)"; }
  say "setting variables"
  doppler secrets get AITP_PEER_KEY --project "$DOPPLER_PROJECT" --config "$DOPPLER_CONFIG" --plain |
    rw variable set AITP_PEER_KEY --stdin --service "$SERVICE" --skip-deploys >/dev/null
  # Railway's edge connects from 100.64.0.0/10, appends its own rotating
  # public hop to X-Forwarded-For and writes the client into X-Real-IP,
  # replacing any value the client sent (docs/interop-peer.md).
  rw variable set --service "$SERVICE" --skip-deploys \
    "AITP_PUBLIC_URL=$(public_url "$host")" \
    AITP_TRUSTED_PROXIES=100.64.0.0/10 \
    AITP_CLIENT_IP_HEADER=x-real-ip \
    RAILWAY_DOCKERFILE_PATH=deploy/interop-peer/Dockerfile \
    RUST_LOG=info >/dev/null
  say "deploying $ref ($(git -C "$work/src" rev-parse --short HEAD))"
  (cd "$work/src" && railway up --ci --service "$SERVICE" --project "$PROJECT_ID" --environment "$environment")
  wait_for_aid "$host" "$want" || { say "the peer did not come up as $want; see: railway logs"; exit 1; }
  say "live: https://$host $(live "$host")"
  if dns_note; then
    AITP="${AITP:-aitp}" "$repo/scripts/interop-peer-smoke.sh" "$(public_url "$host")"
  fi
  ;;
previous)
  link "$work"
  prev="$(rw deployment list --service "$SERVICE" --json |
    jq -r '[.[] | select(.status | IN("SUCCESS", "REMOVING", "REMOVED"))][1].id // empty')"
  [ -n "$prev" ] || { say "no earlier deployment to go back to"; exit 1; }
  say "redeploying $prev"
  railway_api 'mutation($id: String!){deploymentRollback(id: $id)}' "$(jq -nc --arg id "$prev" '{id: $id}')" >/dev/null
  host="$(railway_domain)"
  wait_for_aid "$host" "$(expected_aid)" || { say "the peer did not come back up; see: railway logs"; exit 1; }
  say "live: https://$host $(live "$host")"
  ;;
rollback)
  link "$work"
  host="$(railway_domain)"
  say "removing the live deployment of $SERVICE ($environment)"
  rw down --service "$SERVICE" --yes >/dev/null
  wait_for_aid "$host" "" || { say "https://$host still answers"; exit 1; }
  say "offline: https://$host no longer serves the peer. --apply brings it back."
  if [ "$environment" = production ]; then
    say "DNS: delete the CNAME ${DOMAIN%%.*} -> $(cname_target) at the DNS host if the peer is gone for good."
  fi
  ;;
esac
