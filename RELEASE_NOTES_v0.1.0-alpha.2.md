# aitp-rs v0.1.0-alpha.2

Spec-alignment release for the
[Agent Identity & Trust Protocol](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol)
Rust reference implementation. Tracks AITP spec v0.1.0-rc.1 with
post-alpha.1 corrections.

## What's new since alpha.1

- **Schema-validation drift firewall.** Vendored AITP JSON Schemas
  under `tests/schemas/` (pinned to a specific spec commit via
  `tests/schemas/SPEC_VERSION`). Per-crate `tests/schema.rs` validates
  fully-populated wire types against the spec schemas: Manifest, TCT,
  Delegation, and the four Mutual Handshake payloads. A new CI job
  fails if the vendored copies drift from the pinned spec commit.
  This guards against the field-level drift that prompted the alpha.2
  scope.
- **Conformance Tier B/C/D operations** in `aitp-rs-adapter`. Issuance
  (`generate_keypair`, `issue_manifest`, `issue_tct`,
  `issue_delegation_token`, `sign_envelope`), stateful flows
  (`revoke_tct`, initiator-side `start_handshake` /
  `process_handshake_message`), and test-only ops (`set_clock`,
  `inject_revocation`, `dump_session`) are now wired and exercised by
  end-to-end runner integration tests.
- **Handshake session expiry.** `HandshakeServer` now accepts an
  explicit `session_ttl: Duration` (default 60 s). Inline sweep on
  every request drops expired entries; expired sessions on a
  `commit` request return `400 session expired`.
- **`serde_jcs` 0.2.** Upstream fixed RFC 8785 §3.2.3 UTF-16 code-unit
  ordering for object keys; the previously-ignored
  `jcs_surrogate_pair_ordering` test now passes.

## Breaking change

- **`Manifest.description` removed.** The field was carried in the
  Rust types but was never in RFC-AITP-0003 §3.1/§3.2 or the
  Manifest JSON Schema (which sets `additionalProperties: false`).
  Callers that set this field would have produced wire bytes that
  fail spec validation. No alpha.1 code is known to set it; if your
  fork does, drop the call to `ManifestBuilder::description`.

## Numbers

- 152 tests passing, 0 failed, 2 intentionally ignored
- New: 11 conformance-runner integration tests (Tier A/B/C/D), 7
  schema-validation tests across 4 protocol crates, 2 session-expiry
  tests, 1 manifest legacy-description regression guard
- All workspace crates bumped to `0.1.0-alpha.2`
- `cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings`,
  `cargo doc --no-deps`: all clean

## Still deferred

- **Multi-hop delegation** — RFC-AITP-0011 reserved for v0.2
- **Session Trust Bundle** — RFC-AITP-0010 reserved
- **Responder-side handshake conformance ops** — initiator-side covers
  the high-value test scenarios; responder is on the alpha.3 list
  (`NOTE-RESPONDER-CONFORMANCE`)
- **`verify_revocation_snapshot`** — v0.1 has no spec-defined
  revocation snapshot type; the conformance runner correctly SKIPs
  fixtures that ask for it
- **In-process conformance adapter** — subprocess adapter is the
  conformance path; in-process is fast-local-development only and not
  on the critical path
- **Spec-side fixture migration** — the spec's
  `schemas/conformance/*.json` still uses placeholder strings that
  predate the runner's wire protocol; PR pending against
  `agentidentitytrustprotocol/`

See `docs/design/PENDING.md` for the full open-items list.

## Try it

```sh
git clone https://github.com/agentidentitytrustprotocol/aitp-rs
cd aitp-rs
make demo
```

## Feedback

Open issues at the repo. The alpha.2 surface is small relative to
alpha.1 — most of this release is hardening, drift detection, and
conformance breadth. Especially interested in:

- Cross-language adapters using the new Tier B/C/D ops — does the
  op vocabulary cover what your impl needs?
- Spec-text passages that the schema-validation firewall surfaced as
  drift candidates.
- Any wire-type drift the firewall *missed* — we want it noisy.
