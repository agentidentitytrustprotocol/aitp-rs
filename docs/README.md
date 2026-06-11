# `aitp-rs` documentation

These docs cover **this implementation** — how `aitp-rs` is built, why the
crates are split the way they are, and how to drive the SDKs and the
conformance runner.

They are deliberately **not** a copy of the protocol. The protocol is
*normatively* defined by the AITP RFCs in the sibling
[`agentidentitytrustprotocol`](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol)
repo. Where a wire detail matters, these docs **point to the RFC section**
rather than restating it — if an RFC and a page here ever disagree, the
RFC wins. `aitp-rs` tracks **AITP v0.1.0** (spec commit pinned in
[`../tests/schemas/SPEC_VERSION`](../tests/schemas/SPEC_VERSION)).

## Start here

| If you want to… | Read |
|---|---|
| Understand the codebase + why it's split this way | [`architecture.md`](architecture.md) |
| Use the Python SDK | [`sdk-python.md`](sdk-python.md) |
| Use the Node SDK | [`sdk-node.md`](sdk-node.md) |
| Understand the conformance runner / check status | [`conformance.md`](conformance.md) |
| Track HTTP-transport hardening | [`transport-hardening.md`](transport-hardening.md) |
| See open / deferred work | [`../plans/defered/deferred.md`](../plans/defered/deferred.md) |

## All pages

The *why* behind the implementation — rationale and implementation-specific
detail, not normative protocol text. Each page points to the RFC section
that governs it.

| Doc | Topic | Normative spec |
|---|---|---|
| [`architecture.md`](architecture.md) | Topology, crate map, workspace-split rationale, sync/async boundary, MSRV | — (build rationale) |
| [`jcs.md`](jcs.md) | JSON canonicalization strategy + test vectors | RFC-AITP-0001 §5.4.1, [RFC 8785](https://datatracker.ietf.org/doc/html/rfc8785) |
| [`conformance.md`](conformance.md) | NDJSON adapter protocol, runner, and the 44-fixture matrix | spec `schemas/conformance/` |
| [`handshake-transcripts.md`](handshake-transcripts.md) | Reproducible four-message byte transcript | RFC-AITP-0004, RFC-AITP-0002 §3.1 |
| [`session-bundle.md`](session-bundle.md) | Session Trust Bundle (draft, opt-in) | RFC-AITP-0010 |
| [`multihop-delegation.md`](multihop-delegation.md) | Multi-hop delegation (draft, opt-in) | RFC-AITP-0011 |
| [`tct-renewal.md`](tct-renewal.md) | Shortened TCT renewal (draft, opt-in) | RFC-AITP-0013, RFC-AITP-0004 §8.1 |
| [`sdk-python.md`](sdk-python.md) · [`sdk-node.md`](sdk-node.md) | Per-language SDK feature guides | per-feature, cited inline |
| [`transport-hardening.md`](transport-hardening.md) | `aitp-transport-http` hardening register | RFC-AITP-0007/0008/0009 + RFC 9449/8693/7469 |

## Protocol reference (sibling spec repo)

For the protocol itself — and for non-normative *protocol-level* guides
this repo intentionally does not duplicate:

- [AITP RFC index](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/README.md) — the normative RFCs, in dependency order
- [Implementer Quickstart](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/docs/implementer-quickstart.md) — reading order for building a peer
- [Integration Guide](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/docs/integration-guide.md) — consuming a peer-issued TCT
- [Architecture (non-normative)](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/docs/architecture.md) · [Threat Model](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/docs/threat-model.md) · [Operational Guidance](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/docs/operational-guidance.md) · [Glossary](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/docs/GLOSSARY.md)
