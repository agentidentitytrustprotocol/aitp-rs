# Phase 4b Report — two-agent demo

## Tasks completed

- EX-001 (`agent-a` binary)
- EX-002 (`agent-b` binary)
- EX-003 (top-level `Makefile` with `make demo`)
- EX-004 (`examples/two-agents/README.md`)

## Test counts

| Suite | Count |
|---|---|
| `tests/demo.rs` | 1 (spawns both binaries, asserts /echo returns 200) |

## Sample run

```text
Starting two-agent demo...
agent-b: AID = aid:pubkey:LfBBJfABWvtHzoU674dyCU_5SYwUyxueEpc8KSfaD6Y
agent-b: listening on http://localhost:8002
agent-a: AID = aid:pubkey:rwaj4ykXFOTzVsGcmxXNGVHsbmZiqne-B1R_KJODNB0
agent-a: fetched B's manifest, AID = aid:pubkey:LfBBJfABWvtHzoU674dyCU_5SYwUyxueEpc8KSfaD6Y
agent-a: sending MUTUAL_HELLO
agent-a: building MUTUAL_COMMIT
agent-a: handshake complete — holding TCT issued by aid:pubkey:LfBB… with grants ["demo.echo"]
agent-a: /echo => 200 OK echo from agent-b to aid:pubkey:rwaj…: hello world
```

## Key learnings

1. **Pinned-key identity proof timing.** The proof is signed over
   `<envelope.message_id>|<envelope.timestamp>`. The same `(mid, ts)` MUST
   be used for the envelope's own signature. Forgetting this — using
   `Uuid::new_v4()` inside the envelope wrapper helper — caused
   `Identity("pinned_key signature invalid")` failures in the first run.
   Fixed by adding `sign_envelope_with(mid, ts)` and using it everywhere
   identity proofs ride along.
2. **Mutual handshake's grant intersection bites.** A non-symmetric
   demo where Bob requested no grants from Alice produced
   `PolicyViolation` because Alice's `requested∩offered = ∅`. Fixed by
   making both sides offer + request `demo.echo`.
3. **HTTP-on-localhost relaxation.** `ManifestFetcher` allows HTTP for
   `localhost` / `127.0.0.1` so the demo doesn't need a self-signed TLS
   setup. Documented in the demo README.
4. **`X-Aitp-Session-Id` header** correlates HELLO/COMMIT requests
   without changing the on-the-wire envelope format. Server returns the
   id on HELLO_ACK; client echoes it on COMMIT.
5. **Demo binaries are ~250 lines combined.** Most of that is HTTP
   plumbing (axum routes, reqwest calls, header juggling). The actual
   AITP work — manifest build, handshake start/on_hello_ack/on_commit_ack,
   TCT verify — is short.

## UX papercuts noticed

- `agent-a` retries fetching B's manifest up to 40 times at 100ms — fine
  for `make demo`, but a real client should configure that.
- The integration test reads stdout AFTER the process exits. Long output
  could deadlock; raised the timeout to 15s and writes go to pipes.
- `Makefile` `demo` target uses `&` and `wait` — works on macOS/Linux,
  not POSIX-strict on Windows. CI on Windows would need a separate
  invocation.

## Things the human reviewer should look at

1. Both peers symmetrically offer + request `demo.echo` to keep the demo
   readable. A more interesting demo would have asymmetric grants —
   add it as a follow-up if useful.
2. The `/echo` handler in `agent-b.rs` parses the `X-AITP-TCT` header
   as a `TctEnvelope` (`{"tct": {...}}`). This is the most defensible
   wire form, but requires JSON-encoding the TCT into a single header.
   Production deployments may want a binary-friendly representation
   (base64 of the JSON) — left as a v0.2 concern.
3. `Initiator::on_hello_ack` does not currently re-verify the envelope
   signature on the ack — that's the transport's job per the bootstrap
   verification order. The demo's request handler in `agent-a.rs` does
   not call `verify_envelope` on the response. Adding it would be a
   one-line fix.
