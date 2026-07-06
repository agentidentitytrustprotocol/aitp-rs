//! `aitp` — a small command-line tool for AITP.
//!
//! Offline helpers for the things you reach for while building or
//! debugging an AITP integration: generate a keypair, derive an AID,
//! and inspect/verify a TCT or a Manifest. Everything here is offline —
//! no network — so it composes into scripts and CI checks.
//!
//! ```text
//! aitp keygen                         # new keypair → seed + AID
//! aitp aid --seed <hex>               # derive the AID from a seed
//! aitp tct inspect --token <jws|->    # decode claims (no verification)
//! aitp tct verify  --token <jws|->    # verify signature + claims
//! aitp manifest verify --file <p|->   # verify a signed Manifest
//! ```

use std::io::Read;

use aitp::core::{Aid, Timestamp};
use aitp::crypto::{jws, AitpSigningKey};
use aitp::manifest::{verify_manifest, ManifestEnvelope, VerifyManifestContext};
use aitp::tct::{verify_tct, TctClaims, TctVerifyContext};
use clap::{Parser, Subcommand, ValueEnum};

type CliResult = Result<(), Box<dyn std::error::Error>>;

#[derive(Parser)]
#[command(
    name = "aitp",
    version,
    about = "AITP command-line tool: keys, TCTs, and Manifests (offline)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new signing keypair and print its seed and AID.
    Keygen {
        /// Signature suite.
        #[arg(long, value_enum, default_value_t = Suite::Ed25519)]
        suite: Suite,
        /// Use this 32-byte hex seed instead of generating a random one
        /// (deterministic — the same seed always yields the same AID).
        #[arg(long)]
        seed: Option<String>,
    },
    /// Derive the AID for a given 32-byte hex seed.
    Aid {
        /// 32-byte seed, hex-encoded (64 hex chars).
        #[arg(long)]
        seed: String,
        /// Signature suite.
        #[arg(long, value_enum, default_value_t = Suite::Ed25519)]
        suite: Suite,
    },
    /// TCT operations.
    Tct {
        #[command(subcommand)]
        command: TctCommand,
    },
    /// Manifest operations.
    Manifest {
        #[command(subcommand)]
        command: ManifestCommand,
    },
}

#[derive(Subcommand)]
enum TctCommand {
    /// Decode and pretty-print a TCT's claims **without** verifying the
    /// signature. For inspection only — never trust these claims.
    Inspect {
        /// Compact-JWS TCT, or `-` to read from stdin.
        #[arg(long)]
        token: String,
    },
    /// Verify a TCT's signature and claims, then print the trusted claims.
    Verify {
        /// Compact-JWS TCT, or `-` to read from stdin.
        #[arg(long)]
        token: String,
        /// Expected issuer AID. Defaults to the token's own `iss` claim
        /// (a self-consistency check that the signature matches the
        /// claimed issuer's key).
        #[arg(long)]
        issuer: Option<String>,
        /// Expected audience AID. Defaults to the token's own `aud` claim.
        #[arg(long)]
        audience: Option<String>,
        /// Evaluate expiry/freshness at this Unix time (seconds) instead
        /// of the current clock — useful for checking a fixed/historical
        /// token.
        #[arg(long)]
        at: Option<i64>,
    },
}

#[derive(Subcommand)]
enum ManifestCommand {
    /// Verify a signed Manifest envelope (`{"manifest": {...}}`) and
    /// print its AID, endpoint, and offered capabilities.
    Verify {
        /// Path to a Manifest-envelope JSON file, or `-` for stdin.
        #[arg(long, default_value = "-")]
        file: String,
        /// Evaluate expiry at this Unix time (seconds) instead of the
        /// current clock — useful for a fixed/historical Manifest.
        #[arg(long)]
        at: Option<i64>,
    },
}

#[derive(Copy, Clone, ValueEnum)]
enum Suite {
    Ed25519,
    P256,
}

fn main() {
    if let Err(e) = run(Cli::parse()) {
        eprintln!("aitp: error: {e}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> CliResult {
    match cli.command {
        Command::Keygen { suite, seed } => keygen(suite, seed),
        Command::Aid { seed, suite } => {
            let key = key_from_hex_seed(&seed, suite)?;
            println!("{}", key.aid());
            Ok(())
        }
        Command::Tct { command } => match command {
            TctCommand::Inspect { token } => tct_inspect(read_arg_or_stdin(&token)?.trim()),
            TctCommand::Verify {
                token,
                issuer,
                audience,
                at,
            } => tct_verify(read_arg_or_stdin(&token)?.trim(), issuer, audience, at),
        },
        Command::Manifest { command } => match command {
            ManifestCommand::Verify { file, at } => {
                manifest_verify(&read_file_or_stdin(&file)?, at)
            }
        },
    }
}

fn keygen(suite: Suite, seed: Option<String>) -> CliResult {
    let (seed_bytes, key) = match seed {
        Some(hex) => {
            let bytes = parse_seed(&hex)?;
            (bytes, build_key(&bytes, suite)?)
        }
        None => random_key(suite)?,
    };
    println!("suite: {}", suite_name(suite));
    println!("seed:  {}", hex::encode(seed_bytes));
    println!("aid:   {}", key.aid());
    Ok(())
}

fn tct_inspect(token: &str) -> CliResult {
    let claims = decode_claims(token)?;
    println!("{}", serde_json::to_string_pretty(&claims)?);
    Ok(())
}

fn tct_verify(
    token: &str,
    issuer: Option<String>,
    audience: Option<String>,
    at: Option<i64>,
) -> CliResult {
    // The claimed iss/aud provide sensible defaults; overriding them lets
    // a caller assert the token was issued by / for a specific party.
    let claimed = decode_claims(token)?;
    let issuer = match issuer {
        Some(s) => Aid::parse(&s)?,
        None => claimed.iss.clone(),
    };
    let audience = match audience {
        Some(s) => Aid::parse(&s)?,
        None => claimed.aud.clone(),
    };
    let now = at.map_or_else(Timestamp::now, Timestamp);
    // Offline verify: signature + claim structure. No revocation source
    // or issuer Manifest is available to a CLI, so those checks are
    // explicitly skipped (permissive) — the signature is the gate.
    let ctx = TctVerifyContext::permissive_at(&audience, &issuer, now);
    let verified = verify_tct(token, &ctx)?;
    println!("OK: TCT verifies under issuer {issuer}");
    println!("{}", serde_json::to_string_pretty(&verified.claims)?);
    Ok(())
}

fn manifest_verify(json: &str, at: Option<i64>) -> CliResult {
    let env: ManifestEnvelope = serde_json::from_str(json)?;
    let ctx = at.map_or_else(VerifyManifestContext::now, |t| VerifyManifestContext {
        now: Timestamp(t),
    });
    verify_manifest(&env.manifest, &ctx)?;
    let m = &env.manifest;
    println!("OK: Manifest signature + proof-of-possession verify");
    println!("aid:      {}", m.aid);
    println!("endpoint: {}", m.handshake_endpoint.as_str());
    if let Some(name) = &m.display_name {
        println!("name:     {name}");
    }
    println!("offers:   {}", m.offered_capabilities.join(", "));
    Ok(())
}

// --- helpers ---------------------------------------------------------------

fn decode_claims(token: &str) -> Result<TctClaims, Box<dyn std::error::Error>> {
    let payload = jws::decode_payload_unverified(token.trim())
        .map_err(|e| format!("not a compact JWS: {e}"))?;
    Ok(serde_json::from_slice::<TctClaims>(&payload)?)
}

fn suite_name(suite: Suite) -> &'static str {
    match suite {
        Suite::Ed25519 => "ed25519",
        Suite::P256 => "p256",
    }
}

fn parse_seed(hex_str: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let bytes = hex::decode(hex_str.trim()).map_err(|e| format!("seed is not valid hex: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| "seed must be exactly 32 bytes (64 hex chars)".into())
}

fn build_key(seed: &[u8; 32], suite: Suite) -> Result<AitpSigningKey, Box<dyn std::error::Error>> {
    Ok(match suite {
        Suite::Ed25519 => AitpSigningKey::from_ed25519_seed(seed),
        Suite::P256 => AitpSigningKey::from_p256_seed(seed)
            .map_err(|e| format!("seed is not a valid P-256 scalar: {e}"))?,
    })
}

fn key_from_hex_seed(
    hex_str: &str,
    suite: Suite,
) -> Result<AitpSigningKey, Box<dyn std::error::Error>> {
    let seed = parse_seed(hex_str)?;
    build_key(&seed, suite)
}

fn random_key(suite: Suite) -> Result<([u8; 32], AitpSigningKey), Box<dyn std::error::Error>> {
    use rand::RngCore;
    // Almost every 32-byte value is a valid seed for both suites (only
    // the P-256 zero/overflow scalars fail, astronomically rarely); retry
    // a few times to be safe.
    for _ in 0..8 {
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        if let Ok(key) = build_key(&seed, suite) {
            return Ok((seed, key));
        }
    }
    Err("failed to sample a valid seed".into())
}

fn read_arg_or_stdin(arg: &str) -> Result<String, Box<dyn std::error::Error>> {
    if arg == "-" {
        read_stdin()
    } else {
        Ok(arg.to_string())
    }
}

fn read_file_or_stdin(path: &str) -> Result<String, Box<dyn std::error::Error>> {
    if path == "-" {
        read_stdin()
    } else {
        Ok(std::fs::read_to_string(path)?)
    }
}

fn read_stdin() -> Result<String, Box<dyn std::error::Error>> {
    let mut buf = String::new();
    std::io::stdin().read_to_string(&mut buf)?;
    Ok(buf)
}
