# Two-agent demo

Two AITP agents — `agent-a` (initiator) and `agent-b` (target) — running
on `localhost`, establishing trust via the four-message Mutual Handshake
and exchanging a single `demo.echo` capability invocation.

The demo uses **pinned-key identity** (RFC-AITP-0002 §3) so it has no
external OIDC dependency.

## Run it

From the repo root:

```sh
make demo
```

…which runs:

```sh
cargo build --release -p aitp-example-two-agents
./target/release/agent-b &
sleep 0.3
./target/release/agent-a
```

Sample output (AIDs vary because they're seeded from the CLI):

```text
agent-b: AID = aid:pubkey:7VOvad1ssMw_gyeOki_heG6Y3Tx6Ep5GVMf9J80fxO0
agent-b: listening on http://localhost:8002
agent-a: AID = aid:pubkey:HYiLSklPVkOe2GysNkraj2EmQpZKbXjE6QA4S7ROIzQ
agent-a: fetched B's manifest, AID = aid:pubkey:7VOvad1ssMw_gyeOki_heG6Y3Tx6Ep5GVMf9J80fxO0
agent-a: sending MUTUAL_HELLO
agent-a: building MUTUAL_COMMIT
agent-a: handshake complete — holding TCT issued by aid:pubkey:7VO… with grants ["demo.echo"]
agent-a: /echo => 200 OK echo from agent-b to aid:pubkey:HYi…: hello world
```

## What the code shows

| Concept | Where to look |
|---|---|
| Generating a key from a seed | `agent-a.rs::main` (`AitpSigningKey::from_seed`) |
| Building a Manifest | `lib.rs::build_demo_manifest` (`ManifestBuilder`) |
| Serving a Manifest | `agent-b.rs::serve_manifest` |
| Fetching + verifying a Manifest | `agent-a.rs::main` |
| Driving the initiator | `Initiator::start`, `on_hello_ack`, `on_commit_ack` |
| Driving the responder | `Responder::on_hello`, `on_commit` |
| Wrapping a payload in a signed envelope | `lib.rs::sign_envelope_with` |
| Verifying a TCT at request time | `agent-b.rs::handle_echo` |

## Tweaking the demo

```sh
# Different ports / seeds
./target/release/agent-b --port 9002 --seed customseed
./target/release/agent-a --port 9001 --peer http://localhost:9002 \
    --seed differentseed --message "hello earth"

# Fail handshake by changing what each peer offers/requires (see
# `lib.rs::build_demo_manifest`). Empty intersection => POLICY_VIOLATION.
```

## Why HTTP, not HTTPS?

The Mutual Handshake spec mandates HTTPS in production. The demo runs on
`localhost` and uses HTTP so you don't need to mint a self-signed cert
just to read the output. `ManifestFetcher` allows HTTP only for
`localhost` / `127.0.0.1`; non-local origins are rejected with
`FetchError::InsecureUrl`.
