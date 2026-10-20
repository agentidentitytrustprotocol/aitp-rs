# Upgrading from 0.17 to 0.18

0.18.0 is a small release about revocation snapshots
([#266](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/266),
which closes
[#265](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/265)
and
[#268](https://github.com/agentidentitytrustprotocol/aitp-rs/issues/268)).
The protocol revision is still `aitp/0.3`, and the wire format does not
change, so 0.18 and 0.17 peers interoperate.

It is a breaking release in two ways:

- **In what is reported for an unknown snapshot version.** The
  conformance adapter reports `REVOCATION_SNAPSHOT_INVALID` instead of
  `UNKNOWN_VERSION`, and the HTTP revocation fetch returns a different
  `RevocationError` variant (section 1).
- **In what revocation signing accepts.** Rust, Python and Node refuse
  to sign an `entries[].jti` that is not a lowercase UUID v4, and plain
  serde of a `RevocationListEnvelope` refuses one too (sections 2 and 3).

The per-crate `crates/*/CHANGELOG.md` files are the authoritative record
of what shipped. The root [`CHANGELOG.md`](../CHANGELOG.md) has a summary.

## Who is affected

| You... | Affected by | Action |
|---|---|---|
| match on `RevocationError` from `aitp_transport_http::RevocationCache` | section 1 | Match `Malformed` for an unknown snapshot version |
| run the conformance adapter or compare its codes | section 1 | Expect `REVOCATION_SNAPSHOT_INVALID` |
| sign revocation lists with a `jti` that is uppercase, braced, a URN, unhyphenated, or not version 4 | section 2 | Pass a lowercase UUID v4 |
| deserialize `RevocationListEnvelope` / `RevocationEntry` with serde | section 3 | Make sure stored `jti` values are lowercase UUID v4 |
| vendor the spec's fixtures or run the conformance or xcheck jobs | section 4 | Update to spec `299f89a` and verifier-py `e335348` |
| depend on the crates from crates.io | section 5 | Run `cargo update -p rustls-webpki -p webpki-roots` |

If you only verify snapshots, generate `jti` values with
`Uuid::new_v4()`, `uuid.uuid4()` or `randomUUID()`, and treat any
`RevocationError` as "reject", nothing changes for you.

## 1. Unknown snapshot version reports `REVOCATION_SNAPSHOT_INVALID`

The spec's `VERSIONING.md` gives each artifact its own unknown-version
code, and a revocation snapshot's is `REVOCATION_SNAPSHOT_INVALID`.
0.17.0 reported `UNKNOWN_VERSION`.

| Where | 0.17 | 0.18 |
|---|---|---|
| Adapter op `verify_revocation_snapshot` | `UNKNOWN_VERSION` | `REVOCATION_SNAPSHOT_INVALID` |
| `RevocationCache` fetch | `RevocationError::SignatureInvalid(TctError::VersionUnknown)` | `RevocationError::Malformed(_)` |
| Python / Node `verify_revocation_list` cause | `version_unknown` | `version_unknown` (unchanged) |

TCTs keep `UNKNOWN_VERSION`, and session bundles keep
`BUNDLE_VERSION_MISMATCH`. `version` is still checked before the
signature, for snapshots and for session bundles, so a validly signed
artifact whose `version` was changed afterwards reports the version
code, not a signature failure.

Under `FailClosed` the snapshot is still rejected; only the variant
changes.

**Migration.** Move any arm that matched the old variant:

```rust
// 0.17
Err(RevocationError::SignatureInvalid(TctError::VersionUnknown)) => { /* ... */ }

// 0.18
Err(RevocationError::Malformed(_)) => { /* ... */ }
```

The bindings keep the lowercase `version_unknown` cause. It has been
public API since 0.6.0. [`sdk-python.md`](sdk-python.md) and
[`sdk-node.md`](sdk-node.md) now say that both `version_unknown` and
`malformed` correspond to the spec's `REVOCATION_SNAPSHOT_INVALID`.

## 2. Revocation signing refuses a non-v4 or non-lowercase `jti`

The verifier already rejected a snapshot whose `entries[].jti` was not a
lowercase hyphenated UUID v4, so 0.17.0 could sign snapshots no one would
accept. Signing now runs the same check:

- **Rust.** `aitp_tct::revocation_signing_bytes`, and through it
  `sign_revocation_list`, return `TctError::JtiNotV4` for an entry whose
  `jti` is not UUID v4 with the RFC 9562 variant. `verify_revocation_list`
  goes through the same function, so an envelope built in code with a
  non-v4 `jti` fails verification too.
- **Python.** `AitpAgent.sign_revocation_list` raises `ValueError`
  (`entries[i].jti is not a lowercase UUID v4: ...`).
- **Node.** `AitpAgent.signRevocationList` throws
  (`jti is not a lowercase UUID v4: ...`).

In 0.17 the bindings parsed `jti` leniently: any case and any version.
An uppercase input was signed in lowercase form, which is why it seemed
to verify. Verify was always strict, and an uppercase `jti` on the wire
is `malformed`.

**Migration.** Pass the output of `Uuid::new_v4()`, `str(uuid.uuid4())`
or `crypto.randomUUID()` unchanged. Don't uppercase it, wrap it in
braces, add a `urn:uuid:` prefix or strip the hyphens. If you revoke
`jti` values read from your own storage, normalize them once with a
strict v4 parse and fix the records that fail. Such a TCT `jti` was never
valid on the wire.

## 3. Strict `jti` parsing in serde

`RevocationEntry::jti` deserializes through `aitp_core::ids::serde_v4`.
Plain `serde_json::from_*` of a `RevocationListEnvelope` now refuses an
uppercase, braced, URN, simple (unhyphenated) or non-v4 `jti`, as
`parse_revocation_snapshot_wire` already did.
`parse_revocation_snapshot_wire` checks `jti` before the serde step, so
it still reports `TctError::JtiNotV4`.

The serialized form and the signing bytes are unchanged. A canonical
input round-trips byte for byte.

**Migration.** If you persist snapshots and read them back with serde,
check that the stored `jti` values are lowercase v4. Anything that fails
now would also have failed verification on the wire.

## 4. Spec pin, conformance and cross-implementation checks

`tests/schemas/SPEC_VERSION` moves from `597efbd` to `299f89a` in two
steps. The first step, to `4bbda67` (spec #94, in #266), adds two
fixtures:

- `rev-010-version-unknown` (core, `REVOCATION_SNAPSHOT_INVALID`);
- `bundle-008-version-unknown` (draft, `BUNDLE_VERSION_MISMATCH`, needs
  `experimental-session-bundle`).

The vendored schemas and known-answer vectors are unchanged.

The second step, to `299f89a` (spec #95 and #96, in
[#270](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/270)),
changes only spec docs: `VERSIONING.md`, the media-type registry and the
implementer quickstart. These changes are not normative, and no schema,
vector or fixture changes.

At pin `299f89a` (104 fixtures), the rs adapter passes 80, fails 0 and
skips 24 in the strict run. With all four features it passes 102, fails
0 and skips 2. `rev-010` and `bundle-008` both pass. See
[`conformance.md`](conformance.md).

`tests/AITP_VERIFIER_PY_VERSION` moves from aitp-verifier-py `f335f4f`
to `e335348`, its #66. That verifier also reports
`REVOCATION_SNAPSHOT_INVALID` for an unknown snapshot version, so it
agrees with section 1. The CI `xcheck` job runs against that pin.

## 5. Lockfile bump for RUSTSEC-2026-0381 and RUSTSEC-2026-0382

`Cargo.lock` moves to `rustls-webpki` 0.103.16 and `webpki-roots` 1.0.10
([#275](https://github.com/agentidentitytrustprotocol/aitp-rs/pull/275)),
which fixes advisories RUSTSEC-2026-0381 and RUSTSEC-2026-0382. No
manifest or code changes.

A crate published to crates.io does not ship its lockfile, so this bump
does not reach you automatically. **Migration.** If you depend on the
`aitp-*` crates from crates.io, update the two crates in your own
lockfile:

```sh
cargo update -p rustls-webpki -p webpki-roots
```
