# aitp-cli

A command-line tool (`aitp`) for AITP: key generation, AID derivation,
inspecting and verifying TCTs and Manifests offline, and, with the
default `http-client` feature, fetching a peer's Manifest or running a
full handshake against it. With the `serve` feature, `aitp serve
--interop` runs the public interop peer.

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
    inspection only. A token whose typ is not aitp-tct+jwt is refused.

aitp tct verify --token <jws|-> [--issuer <aid>] [--audience <aid>] [--at <unix>]
    Verify a TCT's signature and claims, then print the trusted claims.
    issuer/audience default to the token's own iss/aud; --at overrides
    the clock (handy for fixed/historical tokens).

aitp manifest verify [--file <path|->] [--at <unix>] [--insecure-localhost]
    Verify a signed Manifest envelope (signature + proof-of-possession)
    and print its AID, endpoint, and offered capabilities.

aitp manifest fetch <url> [--timeout <secs>] [--insecure-localhost]
                         [--dangerous-allow-private-network]
    Fetch <url>/.well-known/aitp-manifest, verify it, and print the
    envelope (pipes into `manifest verify`).

aitp enroll <url> [--key <file>] [--timeout <secs>] [--insecure-localhost]
                  [--dangerous-allow-private-network]
    Register a key with the interop peer at <url>. Without --key, uses
    (and on first use creates) the default key, ~/.config/aitp/agent.key.

aitp handshake <url> [--key <file> | --ephemeral] [--grant <cap>]...
               [--offer <cap>]... [--peer-aid <aid>]
               [--revocation-fail-open] [--timeout <secs>]
               [--insecure-localhost] [--dangerous-allow-private-network]
    Run the four-message handshake as initiator and print the claims of
    the TCT the peer issues us. Without
    --key / --ephemeral, uses the default key. A failure prints the AITP
    error code.

aitp echo <url> [--key <file> | --ephemeral] [--peer-aid <aid>]
          [--timeout <secs>] [--insecure-localhost]
          [--dangerous-allow-private-network]
    Hello world against an interop peer: handshake for
    aitp.interop.echo, then present the issued TCT to the peer's /echo
    with proof of possession (RFC-AITP-0005 §10.5) and print the claims
    it echoes.

aitp serve --interop [--listen <addr>] [--public-url <url>] [--key <file>]
    Run the public interop peer (`serve` feature; docs/interop-peer.md).
```

### Private networks

The networked commands resolve the peer's host and refuse private
addresses (RFC 1918, loopback, CGNAT `100.64.0.0/10`, IPv6 unique-local),
as well as link-local, multicast, broadcast and unspecified ones. Two flags
relax this:

- `--insecure-localhost` accepts a plain `http://localhost` or
  `http://127.0.0.1` peer and admits loopback addresses, for local
  development.
- `--dangerous-allow-private-network` admits private addresses (the
  library's `GuardMode::WarnPrivate`) and logs a warning for each, for a
  peer on an intranet. Link-local (including the cloud metadata range
  `169.254.0.0/16`), multicast, broadcast and unspecified addresses are
  still refused. HTTPS is still required.

The flags apply to every outbound request: the Manifest fetch, the
handshake endpoint, the revocation list fetch, `aitp enroll` and the
`/echo` request of `aitp echo`.

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

# Hello world against the public interop peer:
$ aitp enroll https://interop.agentidentitytrustprotocol.io
$ aitp echo https://interop.agentidentitytrustprotocol.io

# Handshake with a peer, presenting a persistent key:
$ aitp keygen > agent.key
$ aitp handshake https://peer.example --key agent.key --grant demo.echo
```

Commands exit non-zero on any failure (verification, malformed input, a
rejected handshake), so they slot into shell pipelines and CI gates.
