# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | ✅ Active security fixes |
| < 0.1.0 | ❌ End of life |

## Reporting a vulnerability

**Do not open a public GitHub issue.** Email
[security@agentidentitytrustprotocol.org](mailto:security@agentidentitytrustprotocol.org)
or use GitHub's "Report a vulnerability" workflow on this repository's *Security* tab.

We aim to acknowledge within 72 hours and issue a fix within 30 days.
Coordinated disclosure is preferred for issues affecting on-the-wire trust
decisions, signature handling, or cryptographic verification.

## In scope

- Signature forgery or acceptance bugs; JCS canonicalization divergence from RFC 8785
- Key handling; memory hygiene of secret material (`AitpSigningKey`, `secretbox`)
- Replay, downgrade, or audience-confusion attacks against handshake, TCT
  verification, or delegation flows
- Parser denial-of-service in any AITP protocol message
- Policy bypass in revocation, soft-fail grant restriction, or trust-mode enforcement

## Out of scope

- Denial-of-service requiring transport-layer control below `aitp-transport-http`
- Third-party dependency issues — report those upstream
- P-256 ECDSA signing (verifier is implemented; signer is deferred)
- Experimental features (`experimental-renewal`, `experimental-session-bundle`,
  `experimental-multihop-delegation`) — report issues but no patching SLA
