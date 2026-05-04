# History

Past releases of `aitp-rs`. Live state lives elsewhere:

- **What ships now** → [`../../CHANGELOG.md`](../../CHANGELOG.md)
- **What's open** → [`../design/PENDING.md`](../design/PENDING.md)
- **Why the code looks the way it does** → [`../design/`](../design/)
- **How the protocol fits together** → [`../architecture.md`](../architecture.md)

## Released

| Version | Notes |
|---|---|
| v0.1.0-alpha.1 | [release notes](releases/RELEASE_NOTES_v0.1.0-alpha.1.md) |

## Why this directory is small

Everything else (per-phase plans, per-phase execution reports, a
cross-phase audit, the prompt-engineering rules) was development
process material — useful while phases were being executed, no
longer load-bearing once they shipped. `git log` records what
landed in each commit, the `CHANGELOG` records what changed
between releases, and `docs/architecture.md` records what the
project *is* today. The historical material added noise without
informing anyone reading the project for the first time.
