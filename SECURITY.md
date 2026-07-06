# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 0.4.x | ✅ Active security fixes |
| < 0.4.0 | ❌ End of life |

Language SDKs (`@agentidentitytrustprotocol/aitp` on npm, `aitp-sdk` on
PyPI) follow the same policy: the latest published minor line receives
security fixes.

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
  verification, or delegation flows (single- and multi-hop)
- Parser denial-of-service in any AITP protocol message
- Policy bypass in revocation, soft-fail grant restriction, or trust-mode enforcement
- The language SDK bindings (`bindings/aitp-node`, `bindings/aitp-py`)
  for any of the above

## Out of scope

- Denial-of-service requiring transport-layer control below `aitp-transport-http`
- Third-party dependency issues — report those upstream
- Feature-gated draft-RFC surfaces (`experimental-renewal`,
  `experimental-session-bundle`) and multi-hop delegation enabled via
  `max_hops > 0` — reports welcome, but no patching SLA until the
  corresponding RFCs leave Draft
