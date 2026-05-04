# Security policy

## Supported versions

aitp-rs is in pre-alpha. Only the latest `0.1.0-alpha.x` is supported with
security fixes.

## Reporting a vulnerability

**Do not open a public issue.** Email
[security@agentidentitytrustprotocol.org](mailto:security@agentidentitytrustprotocol.org)
or use GitHub's "Report a vulnerability" workflow on this repository's
*Security* tab.

We aim to acknowledge reports within 72 hours and to issue a fix or
mitigation within 30 days. Coordinated disclosure is preferred for
issues that affect on-the-wire trust decisions or signature handling.

## Scope

In scope:

- Signature forgery, signature-acceptance bugs, JCS canonicalization
  divergence from RFC 8785.
- Key handling, including memory hygiene of secret material.
- Replay, downgrade, or audience-confusion attacks against the handshake,
  TCT verification, or delegation flows.
- Parser denial-of-service in any AITP message.

Out of scope:

- Denial-of-service that requires control of the transport layer below
  `aitp-transport-http`.
- Issues in third-party dependencies — please report those upstream.
