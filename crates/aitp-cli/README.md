# aitp-cli

A small command-line tool (`aitp`) for working with AITP artifacts
offline — key generation, AID derivation, and inspecting/verifying TCTs
and Manifests. No network, so it composes into scripts and CI checks.

Built on the pure `aitp` crates; ships in-repo (not yet published to
crates.io).

## Build & run

```bash
cargo run -p aitp-cli -- <command>
# or build once:
cargo build -p aitp-cli && ./target/debug/aitp <command>
```

## Commands

```text
aitp keygen [--suite ed25519|p256] [--seed <hex>]
    Generate a keypair (or derive from a 32-byte hex seed) → prints
    the suite, seed, and AID. Deterministic when --seed is given.

aitp aid --seed <hex> [--suite ...]
    Print just the AID for a 32-byte hex seed.

aitp tct inspect --token <jws|->
    Decode and pretty-print a TCT's claims WITHOUT verifying — for
    inspection only.

aitp tct verify --token <jws|-> [--issuer <aid>] [--audience <aid>] [--at <unix>]
    Verify a TCT's signature and claims, then print the trusted claims.
    issuer/audience default to the token's own iss/aud; --at overrides
    the clock (handy for fixed/historical tokens).

aitp manifest verify [--file <path|->] [--at <unix>]
    Verify a signed Manifest envelope (signature + proof-of-possession)
    and print its AID, endpoint, and offered capabilities.
```

`-` reads from stdin, so tokens/manifests pipe through:

```bash
echo "$TCT" | aitp tct verify --token -
cat manifest.json | aitp manifest verify --file -
```

## Examples

```bash
# New identity:
$ aitp keygen
suite: ed25519
seed:  9f3c...
aid:   aid:pubkey:...

# Reproduce the all-zero-seed KAT identity:
$ aitp aid --seed 0000000000000000000000000000000000000000000000000000000000000000
aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik

# Inspect then verify a token:
$ aitp tct inspect --token "$TCT"
$ aitp tct verify  --token "$TCT"
```

Commands exit non-zero on any failure (verification, malformed input),
so they slot into shell pipelines and CI gates.
