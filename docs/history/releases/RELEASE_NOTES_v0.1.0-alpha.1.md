# aitp-rs v0.1.0-alpha.1

First implementation milestone for the
[Agent Identity & Trust Protocol](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol)
in Rust. Tracks AITP spec v0.1.0-rc.1.

## What works

- **Manifest issuance, verification, and HTTP discovery** — full
  RFC-AITP-0003 §5 verification order, well-known endpoint, fetch-with-cache.
- **Mutual handshake** — four messages, both pinned-key and OIDC identity
  paths, full bootstrap verification per RFC-AITP-0004 §5.1.
- **TCT issuance, verification, downstream PoP** — RFC-AITP-0005 §9
  consumer rules; `verify_strict` Ed25519 verification.
- **Single-hop delegation** — RFC-AITP-0006 §4, all 11 checks enforced.
- **Conformance runner** — subprocess + NDJSON adapter protocol; the
  aitp-rs adapter implements every Tier-A verification op.
- **Two-agent demo** — `make demo` runs an end-to-end handshake and
  capability invocation on `localhost`.

## What doesn't work yet

- **Multi-hop delegation** — RFC-AITP-0011 reserved for v0.2.
- **Session Trust Bundle** — RFC-AITP-0010 reserved.
- **Conformance Tier B/C/D ops** in the Rust adapter — issuance, stateful
  flows, and test-only ops (clock override, deny-list injection) are
  deferred to v0.1.0-alpha.2.
- **Spec known-answer hashes** — pinned reference hashes for TCT,
  Manifest, and JWK thumbprints (`SPEC-005`/`SPEC-006`) are pending in
  the spec repo.
- **Surrogate-pair JCS ordering** — `serde_jcs` 0.1 sorts by UTF-8 byte
  order rather than UTF-16 code-unit order; one test vector is
  `#[ignore]`'d (`BLOCKED-JCS-SURROGATE`).

See `docs/design/PENDING.md` and the per-phase reports
(`phase-0-report.md` … `phase-6-report.md`) for the full state.

## Try it

```sh
git clone https://github.com/agentidentitytrustprotocol/aitp-rs
cd aitp-rs
make demo
```

```text
agent-b: AID = aid:pubkey:LfBBJfABWvtHzoU674dyCU_5SYwUyxueEpc8KSfaD6Y
agent-b: listening on http://localhost:8002
agent-a: AID = aid:pubkey:rwaj4ykXFOTzVsGcmxXNGVHsbmZiqne-B1R_KJODNB0
agent-a: fetched B's manifest, AID = …
agent-a: sending MUTUAL_HELLO
agent-a: building MUTUAL_COMMIT
agent-a: handshake complete — holding TCT issued by … with grants ["demo.echo"]
agent-a: /echo => 200 OK echo from agent-b to …: hello world
```

## Feedback

Open issues at the repo. Especially interested in:

- Implementer experience reports from other-language adapters.
- Cross-language interop — write an adapter in Python/Go and let us
  know which parts of the spec need disambiguation.
- Spec ambiguities you hit during implementation — see the
  `BLOCKED-*` sections in `docs/design/PENDING.md` for the ones we
  surfaced this run.
