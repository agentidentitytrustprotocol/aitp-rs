# Changelog

The release notes are in [`crates/aitp/CHANGELOG.md`](crates/aitp/CHANGELOG.md): what changed in each `aitp` release, and the migration for each breaking change. It also holds the workspace history that was kept in this file until 0.24.0.

`aitp-experimental` and `aitp-cli` release in lockstep with `aitp`. Their generated changelogs are [`crates/aitp-experimental/CHANGELOG.md`](crates/aitp-experimental/CHANGELOG.md) and [`crates/aitp-cli/CHANGELOG.md`](crates/aitp-cli/CHANGELOG.md).

## 1.0 API candidate: 0.25.1

The **0.25.1** release (tag `aitp-v0.25.1`, 2026-11-01) is the **1.0 API candidate**. It is on crates.io, PyPI (`aitp-sdk`) and npm (`@agentidentitytrustprotocol/aitp` and its six platform packages, musl included).

What is frozen is the surface [`STABILITY.md`](STABILITY.md) covers: the stable surface of `aitp` and the Python and Node SDKs. `aitp-experimental` and the `aitp-cli` command line stay outside the promise, as before.

Until `1.0.0-rc.1`, that surface changes only for:

- a bug fix;
- a security fix;
- alignment with the Release Candidate text of RFC-AITP-0001 to 0009.

Each such change, whether it adds, removes or alters a signature or only changes behaviour, has an entry in [`crates/aitp/CHANGELOG.md`](crates/aitp/CHANGELOG.md) that names which of the three reasons applies. [`STABILITY.md`](STABILITY.md#10-api-candidate) says how this is checked.
