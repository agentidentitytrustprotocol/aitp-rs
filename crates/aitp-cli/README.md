# aitp-cli

A command-line tool (`aitp`) for AITP: key generation, AID derivation,
inspecting and verifying TCTs and Manifests offline, and, with the
default `http-client` feature, fetching a peer's Manifest or running a
full handshake against it.

The full guide, including the handshake options and error codes, is
[`docs/cli.md`](../../docs/cli.md).

## Install

```bash
cargo install aitp-cli            # the binary is `aitp`
cargo install aitp-cli --no-default-features   # offline commands only
```

Prebuilt binaries are attached to each `aitp-cli-v*` GitHub Release.
From a checkout: `cargo run -p aitp-cli -- <command>`.

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

aitp manifest fetch <url> [--timeout <secs>] [--insecure-localhost]
    Fetch <url>/.well-known/aitp-manifest, verify it, and print the
    envelope (pipes into `manifest verify`).

aitp handshake <url> (--key <file> | --ephemeral) [--grant <cap>]...
               [--offer <cap>]... [--peer-aid <aid>]
               [--revocation-fail-open] [--timeout <secs>]
               [--insecure-localhost]
    Run the four-message handshake as initiator and print the claims of
    the TCT the peer issues us. A failure prints the AITP error code.
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

# Handshake with a peer, presenting a persistent key:
$ aitp keygen > agent.key
$ aitp handshake https://peer.example --key agent.key --grant demo.echo --offer demo.echo
```

Commands exit non-zero on any failure (verification, malformed input, a
rejected handshake), so they slot into shell pipelines and CI gates.
