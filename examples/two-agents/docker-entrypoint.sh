#!/bin/sh
# Two-agent demo entrypoint: start the responder (agent-b) on loopback,
# wait for it to bind, then run the initiator (agent-a). agent-a polls
# for the peer Manifest, drives the four-message handshake, and invokes
# /echo. When it returns, tear down agent-b and propagate the exit code.
set -eu

PORT="${AITP_DEMO_PORT:-8002}"

agent-b --port "$PORT" &
B_PID=$!

# Ensure agent-b is reaped on any exit.
trap 'kill "$B_PID" 2>/dev/null || true' EXIT INT TERM

agent-a --peer "http://localhost:${PORT}"
