# Two-agent demo

A small crate of runnable AITP demos. The headline demo is two agents —
`agent-a` (initiator) and `agent-b` (target) — running on `localhost`,
establishing trust via the four-message Mutual Handshake and exchanging a
single `demo.echo` capability invocation. Four smaller binaries exercise
the OIDC, revocation, renewal, and delegation surfaces in-process.

All demos use **pinned-key identity** (RFC-AITP-0002 §3) unless noted, so
they run with no external OIDC dependency.

## The handshake demo (`agent-a` + `agent-b`)

This demo is built on the **high-level API**, the path most integrations
should use:

- `agent-a` drives the entire handshake with one call to
  [`aitp::facade::run_initiator_handshake`].
- `agent-b` serves the handshake routes with
  [`aitp::transport::HandshakeServer`], merging two app routes on top
  (`/.well-known/aitp-manifest` for discovery and `/echo` for the
  capability).

> Want the per-message state machine instead? Drive
> `aitp::handshake::{Initiator, Responder}` directly — see the
> `oidc-demo` below, which steps through all four messages by hand.

### Run it

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
agent-a: handshake complete — holding TCT issued by aid:pubkey:7VO… with grants ["demo.echo"]
agent-a: /echo => 200 OK echo from agent-b to aid:pubkey:HYi…: hello world
```

### What the code shows

| Concept | Where to look |
|---|---|
| Generating a key from a seed | `agent-a.rs::main` (`AitpSigningKey::from_seed`) |
| Building + serving a Manifest | `lib.rs::build_demo_manifest`, `agent-b.rs::serve_manifest` |
| Pinning a peer key (TOFU) | `agent-a.rs::main` (`ManifestFetcher` → `StaticPinnedKeyStore`) |
| Driving the whole handshake in one call | `agent-a.rs::main` (`run_initiator_handshake`) |
| Serving the handshake routes | `agent-b.rs::main` (`HandshakeServer::router`) |
| Verifying a TCT at request time | `lib.rs::verify_echo_tct`, called from `agent-b.rs::handle_echo` |

### Tweaking the demo

```sh
# Different ports / seeds
./target/release/agent-b --port 9002 --seed customseed
./target/release/agent-a --port 9001 --peer http://localhost:9002 \
    --seed differentseed --message "hello earth"
```

To watch a handshake *fail*, change what each peer offers in
`lib.rs::build_demo_manifest` so the grant intersection is empty — the
initiator surfaces a `FacadeError::Protocol` carrying the peer's
`POLICY_VIOLATION` code.

### Why HTTP, not HTTPS?

The Mutual Handshake spec mandates HTTPS in production. The demo runs on
`localhost` and uses HTTP so you don't need to mint a self-signed cert
just to read the output. `ManifestFetcher` allows HTTP only for
`localhost` / `127.0.0.1`; non-local origins are rejected with
`FetchError::InsecureUrl`.

## The other demos

Each is a single self-contained binary — no servers to coordinate, no
external network.

| Binary | Run | Shows |
|---|---|---|
| `delegation-demo` | `cargo run -p aitp-example-two-agents --bin delegation-demo` | Single-hop delegation (RFC-AITP-0006): A grants to B, B re-delegates a *subset* to C, A verifies C's token; plus the two failure modes (over-broad scope, non-grantor verifier). |
| `oidc-demo` | `cargo run -p aitp-example-two-agents --bin oidc-demo` | A full Mutual Handshake where both peers present **OIDC** identities, against an in-process mock IdP. Drives the `Initiator`/`Responder` state machine by hand. |
| `revocation-demo` | `cargo run -p aitp-example-two-agents --bin revocation-demo` | Publishing a signed revocation list and querying `RevocationCache::is_revoked` (RFC-AITP-0008 §1.5). |
| `tct-renewal-demo` | `cargo run -p aitp-example-two-agents --bin tct-renewal-demo --features experimental-renewal` | Renewing a TCT against an issuer's `/aitp/handshake/renew` endpoint via `aitp::facade::renew_tct`. Gated behind the `experimental-renewal` feature. |

## Tests

`tests/demo.rs` spawns `agent-b` on a random port, runs `agent-a` against
it, and asserts a successful `/echo`. Run with:

```sh
cargo test -p aitp-example-two-agents --all-features
```

[`aitp::facade::run_initiator_handshake`]: https://docs.rs/aitp/latest/aitp/facade/fn.run_initiator_handshake.html
[`aitp::transport::HandshakeServer`]: https://docs.rs/aitp/latest/aitp/transport/struct.HandshakeServer.html
