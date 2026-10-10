# Security policy

## Supported versions

| Version | Supported |
|---|---|
| Latest released minor line (0.13.x at the time of writing; the workspace version is in `Cargo.toml`) | ✅ Active security fixes |
| Earlier minor lines | ❌ Not patched — upgrade to the latest minor |

All published crates ship in lockstep at one shared version, so "the
latest minor line" means the same thing for every crate. While the project
is pre-1.0, a breaking change bumps the minor digit (for example 0.12 →
0.13), and security fixes ship as a patch release on the latest minor line
only. Releases are listed on the
[GitHub releases page](https://github.com/agentidentitytrustprotocol/aitp-rs/releases).

Language SDKs (`@agentidentitytrustprotocol/aitp` on npm, `aitp-sdk` on
PyPI) are versioned in lockstep with the crates and follow the same policy:
the latest published minor line receives security fixes.

## Reporting a vulnerability

**Do not open a public GitHub issue.** Email
[security@agentidentitytrustprotocol.org](mailto:security@agentidentitytrustprotocol.org)
or use GitHub's "Report a vulnerability" workflow on this repository's *Security* tab.

We aim to acknowledge within 72 hours and issue a fix within 30 days.
Coordinated disclosure is preferred for issues affecting on-the-wire trust
decisions, signature handling, or cryptographic verification.

## In scope

- Signature forgery or acceptance bugs in either supported suite
  (Ed25519/EdDSA and P-256/ES256, signing and verification); compact-JWS
  profile bypasses (`alg`/`typ` confusion, header smuggling); JCS
  canonicalization divergence from RFC 8785
- Key handling; memory hygiene of secret material (`AitpSigningKey`
  zeroizes its secret scalar on drop and redacts it from `Debug`)
- Replay, downgrade, or audience-confusion attacks against handshake, TCT
  verification, or single-hop delegation flows
- Any way to get a multi-hop delegation `chain` accepted while
  `max_delegation_hops` is at its default of 0 (the strict default must
  reject every chained token; see
  [`docs/multihop-delegation.md`](docs/multihop-delegation.md))
- Parser denial-of-service in any AITP protocol message
- Policy bypass in revocation, soft-fail grant restriction, or trust-mode enforcement
- The language SDK bindings (`bindings/aitp-node`, `bindings/aitp-py`)
  for any of the above

## Out of scope

- Denial-of-service requiring transport-layer control below `aitp-transport-http`
- Third-party dependency issues — report those upstream
- Feature-gated draft-RFC surfaces (`experimental-renewal`,
  `experimental-session-bundle`) and multi-hop delegation once a caller has
  opted in with `max_delegation_hops > 0` — reports welcome, but no patching SLA until the
  corresponding RFCs leave Draft
