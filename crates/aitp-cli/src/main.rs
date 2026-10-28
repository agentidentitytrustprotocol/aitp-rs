//! `aitp` — a small command-line tool for AITP.
//!
//! Helpers for the things you reach for while building or debugging an
//! AITP integration: generate a keypair, derive an AID, inspect/verify a
//! TCT or a Manifest, and (with the default `http-client` feature) fetch
//! a peer's Manifest, enrol a key with an interop peer, run a full
//! handshake, or present the TCT back to the interop peer. With the `serve` feature, `aitp serve --interop` runs the
//! public interop peer. The offline commands never touch the network,
//! so they compose into scripts and CI checks.
//!
//! ```text
//! aitp keygen                         # new keypair → seed + AID
//! aitp aid --seed <hex>               # derive the AID from a seed
//! aitp tct inspect --token <jws|->    # decode claims (no verification)
//! aitp tct verify  --token <jws|->    # verify signature + claims
//! aitp manifest verify --file <p|->   # verify a signed Manifest
//! aitp manifest fetch <url>           # fetch + verify a peer's Manifest
//! aitp enroll <url>                   # register our key with an interop peer
//! aitp handshake <url> --grant <cap>  # handshake → print the TCT claims
//! aitp echo <url>                     # handshake, then prove the TCT at /echo
//! aitp serve --interop                # run the interop peer (`serve` feature)
//! ```

use std::io::Read;

use aitp::core::{Aid, Timestamp};
use aitp::crypto::{jws, AitpSigningKey};
use aitp::manifest::{verify_manifest, ManifestEnvelope, VerifyManifestContext};
use aitp::tct::{verify_tct, TctClaims, TctVerifyContext};
use clap::{Parser, Subcommand, ValueEnum};

#[cfg(feature = "http-client")]
mod echo;
#[cfg(feature = "http-client")]
mod enrol;
#[cfg(feature = "http-client")]
mod net;
#[cfg(feature = "serve")]
mod serve;

type CliResult = Result<(), Box<dyn std::error::Error>>;

#[derive(Parser)]
#[command(
    name = "aitp",
    version,
    about = "AITP command-line tool: keys, TCTs, Manifests, and handshakes"
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
    /// Run the four-message handshake as initiator against a peer and
    /// print the claims of the TCT it issues us.
    #[cfg(feature = "http-client")]
    Handshake {
        /// Peer origin; its Manifest is fetched from
        /// `<url>/.well-known/aitp-manifest`.
        url: String,
        #[command(flatten)]
        identity: KeyChoice,
        /// Signature suite of a `--key` file holding a bare hex seed (a
        /// file written by `aitp keygen` names its own suite).
        #[arg(long, value_enum, default_value_t = Suite::Ed25519)]
        suite: Suite,
        /// Capability to request; repeat for several.
        #[arg(long = "grant", value_name = "CAP")]
        grants: Vec<String>,
        /// Capability we offer the peer; repeat for several. The
        /// handshake is mutual, so the peer also gets a TCT from us,
        /// granting what it requests that we offer, and it fails if
        /// none overlaps. Defaults to the `--grant` capabilities.
        #[arg(long = "offer", value_name = "CAP")]
        offers: Vec<String>,
        /// Pin the peer to this AID. Without it, the AID in the peer's
        /// Manifest is trusted on first use.
        #[arg(long)]
        peer_aid: Option<String>,
        /// Accept a peer whose revocation status cannot be determined
        /// (default: refuse it, RFC-AITP-0008 fail_closed).
        #[arg(long)]
        revocation_fail_open: bool,
        #[command(flatten)]
        net: NetArgs,
    },
    /// Handshake with an interop peer, requesting `aitp.interop.echo`,
    /// then present the TCT it issues back to its `/echo` with proof of
    /// possession of our key, and print the claims the peer verified.
    #[cfg(feature = "http-client")]
    Echo {
        /// Interop peer origin.
        url: String,
        #[command(flatten)]
        identity: KeyChoice,
        /// Signature suite of a `--key` file holding a bare hex seed.
        #[arg(long, value_enum, default_value_t = Suite::Ed25519)]
        suite: Suite,
        /// Pin the peer to this AID. Without it, the AID in the peer's
        /// Manifest is trusted on first use.
        #[arg(long)]
        peer_aid: Option<String>,
        #[command(flatten)]
        net: NetArgs,
    },
    /// Register our key with an interop peer (`POST <url>/enroll`), so
    /// that its handshakes accept it. Creates the default key file if
    /// it does not exist yet.
    #[cfg(feature = "http-client")]
    Enroll {
        /// Peer origin.
        url: String,
        /// Signing key file (default: `$AITP_KEY`, else
        /// `~/.config/aitp/agent.key`, created if missing).
        #[arg(long, value_name = "FILE")]
        key: Option<String>,
        #[command(flatten)]
        net: NetArgs,
    },
    /// Run a responder. `--interop` is the only mode: the public interop
    /// peer described in docs/interop-peer.md.
    #[cfg(feature = "serve")]
    Serve(serve::ServeArgs),
}

/// The identity `aitp handshake` presents: a key file, a throwaway key,
/// or (neither given) the default key file.
#[cfg(feature = "http-client")]
#[derive(clap::Args)]
#[group(multiple = false)]
struct KeyChoice {
    /// Signing key file: the output of `aitp keygen`, or a bare 32-byte
    /// hex seed. Default: `$AITP_KEY`, else `~/.config/aitp/agent.key`
    /// (the file `aitp enroll` creates).
    #[arg(long, value_name = "FILE")]
    key: Option<String>,
    /// Generate a throwaway Ed25519 key for this run. Peers that pin
    /// keys will reject it until it is enrolled.
    #[arg(long)]
    ephemeral: bool,
}

#[cfg(feature = "http-client")]
impl KeyChoice {
    /// The key to present: `--key`, a throwaway, or the default key file,
    /// which must exist (`aitp enroll` creates it).
    fn resolve(&self, suite: Suite) -> Result<AitpSigningKey, Box<dyn std::error::Error>> {
        match &self.key {
            Some(path) => key_from_file(path, suite),
            None if self.ephemeral => Ok(random_key(Suite::Ed25519)?.1),
            None => {
                let path = default_key_path()?;
                if !path.exists() {
                    return Err(format!(
                        "no key: pass --key <FILE> or --ephemeral, or run \
                         `aitp enroll <url>` to create {}",
                        path.display()
                    )
                    .into());
                }
                key_from_file(&path.to_string_lossy(), suite)
            }
        }
    }
}

#[cfg(feature = "http-client")]
#[derive(clap::Args)]
struct NetArgs {
    /// Per-request HTTP timeout, in seconds.
    #[arg(long, default_value_t = 10, value_name = "SECS")]
    timeout: u64,
    /// Allow a plain `http://localhost` / `http://127.0.0.1` peer and
    /// loopback addresses (local development only; RFC-AITP-0003 §4.1
    /// requires HTTPS, and other hosts on private addresses are refused).
    #[arg(long)]
    insecure_localhost: bool,
}

#[cfg(feature = "http-client")]
impl NetArgs {
    fn into_opts(self) -> net::NetOpts {
        net::NetOpts {
            timeout: std::time::Duration::from_secs(self.timeout),
            insecure_localhost: self.insecure_localhost,
        }
    }
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
        /// Expected audience AID. Defaults to the token's own `aud` claim,
        /// which checks nothing: the output then says the audience was not
        /// authenticated.
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
    /// Fetch a peer's Manifest from `<url>/.well-known/aitp-manifest`,
    /// verify it, and print the envelope (pipes into `manifest verify`).
    #[cfg(feature = "http-client")]
    Fetch {
        /// Peer origin.
        url: String,
        #[command(flatten)]
        net: NetArgs,
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
            #[cfg(feature = "http-client")]
            ManifestCommand::Fetch { url, net } => {
                net::manifest_fetch(parse_url(&url)?, net.into_opts())
            }
        },
        #[cfg(feature = "http-client")]
        Command::Handshake {
            url,
            identity,
            suite,
            grants,
            offers,
            peer_aid,
            revocation_fail_open,
            net,
        } => net::handshake(net::HandshakeArgs {
            peer: parse_url(&url)?,
            key: identity.resolve(suite)?,
            ephemeral: identity.ephemeral,
            peer_aid: peer_aid.as_deref().map(Aid::parse).transpose()?,
            grants,
            offers,
            revocation_fail_open,
            net: net.into_opts(),
        }),
        #[cfg(feature = "http-client")]
        Command::Echo {
            url,
            identity,
            suite,
            peer_aid,
            net,
        } => net::echo(net::HandshakeArgs {
            peer: parse_url(&url)?,
            key: identity.resolve(suite)?,
            ephemeral: identity.ephemeral,
            peer_aid: peer_aid.as_deref().map(Aid::parse).transpose()?,
            grants: vec![],
            offers: vec![],
            // The interop peer advertises its list; check it.
            revocation_fail_open: false,
            net: net.into_opts(),
        }),
        #[cfg(feature = "http-client")]
        Command::Enroll { url, key, net } => {
            let key = match key {
                Some(path) => key_from_file(&path, Suite::Ed25519)?,
                None => load_or_create_default_key()?,
            };
            net::enroll(parse_url(&url)?, &key, net.into_opts())
        }
        #[cfg(feature = "serve")]
        Command::Serve(args) => serve::run(args),
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
    let audience_given = audience.is_some();
    let audience = match audience {
        Some(s) => Aid::parse(&s)?,
        None => claimed.aud.clone(),
    };
    let now = at.map_or_else(Timestamp::now, Timestamp);
    // Offline verify: signature + claim structure. No revocation source
    // or issuer Manifest is available to a CLI, so those checks are
    // explicitly skipped (permissive) — the signature is the gate.
    let ctx = TctVerifyContext::builder(&audience, &issuer, now)
        .revocation(aitp::tct::RevocationSource::FailOpen)
        .skip_manifest_expiry_cap_dangerous()
        .build()
        .expect("both decisions are made");
    let verified = verify_tct(token, &ctx)?;
    println!("OK: TCT verifies under issuer {issuer}");
    if !audience_given {
        // An inspection default, not a check: a server must take the
        // presenter's AID from an authenticated source (RFC-AITP-0005 §6).
        println!("audience taken from the token (not authenticated): {audience}");
    }
    println!("{}", serde_json::to_string_pretty(&verified.claims)?);
    Ok(())
}

fn manifest_verify(json: &str, at: Option<i64>) -> CliResult {
    let env: ManifestEnvelope = serde_json::from_str(json)?;
    let ctx = at.map_or_else(VerifyManifestContext::now, |t| {
        VerifyManifestContext::at(Timestamp(t))
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

/// Load a signing key from a file holding either `aitp keygen` output
/// (`suite:` / `seed:` lines) or a bare hex seed in `suite`.
#[cfg(feature = "http-client")]
fn key_from_file(path: &str, suite: Suite) -> Result<AitpSigningKey, Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("reading key {path}: {e}"))?;
    key_from_text(&text, path, suite)
}

/// Parse `aitp keygen` output or a bare hex seed; `origin` names the
/// source in errors.
#[cfg(feature = "http-client")]
fn key_from_text(
    text: &str,
    origin: &str,
    suite: Suite,
) -> Result<AitpSigningKey, Box<dyn std::error::Error>> {
    let field = |name: &str| {
        text.lines()
            .find_map(|l| l.trim().strip_prefix(name).map(str::trim))
    };
    match field("seed:") {
        Some(seed) => {
            let suite = match field("suite:") {
                Some("ed25519") | None => Suite::Ed25519,
                Some("p256") => Suite::P256,
                Some(other) => return Err(format!("{origin}: unknown suite {other:?}").into()),
            };
            key_from_hex_seed(seed, suite)
        }
        None => key_from_hex_seed(text, suite),
    }
}

/// `$AITP_KEY`, else `$XDG_CONFIG_HOME/aitp/agent.key`, else
/// `~/.config/aitp/agent.key` (`%APPDATA%\aitp\agent.key` on Windows).
#[cfg(feature = "http-client")]
fn default_key_path() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    use std::path::PathBuf;
    let var = |name: &str| std::env::var_os(name).filter(|v| !v.is_empty());
    if let Some(path) = var("AITP_KEY") {
        return Ok(PathBuf::from(path));
    }
    let config = var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| var("APPDATA").map(PathBuf::from))
        .or_else(|| var("HOME").map(|h| PathBuf::from(h).join(".config")))
        .ok_or("cannot locate a config directory; pass --key <FILE>")?;
    Ok(config.join("aitp").join("agent.key"))
}

/// The default key, generated (Ed25519, `aitp keygen` format, mode 0600
/// on Unix) on first use.
#[cfg(feature = "http-client")]
fn load_or_create_default_key() -> Result<AitpSigningKey, Box<dyn std::error::Error>> {
    let path = default_key_path()?;
    if path.exists() {
        return key_from_file(&path.to_string_lossy(), Suite::Ed25519);
    }
    let (seed, key) = random_key(Suite::Ed25519)?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let contents = format!(
        "suite: ed25519\nseed:  {}\naid:   {}\n",
        hex::encode(seed),
        key.aid()
    );
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    std::io::Write::write_all(
        &mut options
            .open(&path)
            .map_err(|e| format!("creating {}: {e}", path.display()))?,
        contents.as_bytes(),
    )?;
    eprintln!("aitp: created key {} ({})", path.display(), key.aid());
    Ok(key)
}

#[cfg(feature = "http-client")]
fn parse_url(s: &str) -> Result<url::Url, Box<dyn std::error::Error>> {
    url::Url::parse(s).map_err(|e| format!("invalid URL {s:?}: {e}").into())
}

fn random_key(suite: Suite) -> Result<([u8; 32], AitpSigningKey), Box<dyn std::error::Error>> {
    use rand::TryRng;
    // Almost every 32-byte value is a valid seed for both suites (only
    // the P-256 zero/overflow scalars fail, astronomically rarely); retry
    // a few times to be safe.
    for _ in 0..8 {
        let mut seed = [0u8; 32];
        // `SysRng` (rand 0.10's renamed `OsRng`) is fallible, unlike the
        // old infallible `RngCore::fill_bytes`; this fn already returns a
        // `Result`, so propagate rather than paper over a failed OS RNG
        // read with an unwrap.
        rand::rngs::SysRng.try_fill_bytes(&mut seed)?;
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
