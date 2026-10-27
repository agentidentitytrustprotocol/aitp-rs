# Security policy

## Supported versions

| Line | Supported |
|---|---|
| The latest minor | ✅ Bug fixes and security fixes |
| The previous minor | ✅ Security fixes, for 6 months after the latest minor's first release |
| Older lines | ❌ Not patched: upgrade to the latest minor |

A fix ships as a patch release on each supported line it applies to. All
published crates and the language SDKs (`@agentidentitytrustprotocol/aitp`
on npm, `aitp-sdk` on PyPI) ship in lockstep at one shared version, so a
line means the same thing for every package. Releases are listed on the
[GitHub releases page](https://github.com/agentidentitytrustprotocol/aitp-rs/releases).

A security fix can change observable behaviour, for example by rejecting
input that used to be accepted, even when that brings the crate into line
with the spec. It still ships in a patch, with a `### Fixed` entry that
says what changes ([`STABILITY.md`](STABILITY.md#behaviour-that-follows-the-spec)).

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
- Any way to get a multi-hop delegation `chain` accepted by
  `aitp::delegation::verify_delegation` (it must reject every chained
  token; see
  [`docs/multihop-delegation.md`](docs/multihop-delegation.md))
- Parser denial-of-service in any AITP protocol message
- Policy bypass in revocation, soft-fail grant restriction, or trust-mode enforcement
- The language SDK bindings (`bindings/aitp-node`, `bindings/aitp-py`)
  for any of the above

## Out of scope

- Denial-of-service requiring transport-layer control below `aitp::transport`
- Third-party dependency issues — report those upstream
- Draft-RFC surfaces (the `aitp-experimental` crate: multi-hop
  delegation, Session Trust Bundles, TCT renewal) — reports
  welcome, but no patching SLA until the corresponding RFCs leave Draft
