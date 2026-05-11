//! `aitp-conformance` CLI.

use aitp_conformance::adapter::subprocess::SubprocessAdapter;
use aitp_conformance::adapter::Adapter;
use aitp_conformance::fixture::FixtureLoader;
use aitp_conformance::runner::{
    render_json, render_summary, render_tap, render_text, FixtureResult, OutputFormat, Runner,
};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "aitp-conformance", about = "AITP v0.1 conformance test runner")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run fixtures against an adapter.
    Run {
        /// Adapter executable path (NDJSON over stdin/stdout).
        #[arg(long)]
        target: PathBuf,
        /// Path to the fixtures directory.
        #[arg(long, default_value = "./schemas/conformance")]
        fixtures_dir: PathBuf,
        /// Substring filter on fixture IDs.
        #[arg(long)]
        filter: Option<String>,
        /// Only run fixtures with this tag.
        #[arg(long)]
        tag: Option<String>,
        /// Opt into a feature flag, allowing non-core fixtures
        /// with a matching `feature` field to run instead of
        /// being SKIPped. Repeat the flag to opt into multiple.
        /// Examples:
        ///   --feature experimental-multihop-delegation
        ///   --feature experimental-session-bundle
        #[arg(long = "feature")]
        features: Vec<String>,
        /// Output format: text|json|tap.
        #[arg(long, default_value = "text")]
        output: String,
        /// Stop on first failure.
        #[arg(long)]
        fail_fast: bool,
    },
    /// List available fixtures.
    List {
        /// Path to the fixtures directory.
        #[arg(long, default_value = "./schemas/conformance")]
        fixtures_dir: PathBuf,
        /// Filter by tag.
        #[arg(long)]
        tag: Option<String>,
    },
    /// Print one fixture's JSON.
    Describe {
        /// Path to the fixtures directory.
        #[arg(long, default_value = "./schemas/conformance")]
        fixtures_dir: PathBuf,
        /// Fixture ID.
        id: String,
    },
}

fn main() {
    let cli = Cli::parse();
    let exit = match cli.command {
        Command::Run {
            target,
            fixtures_dir,
            filter,
            tag,
            features,
            output,
            fail_fast,
        } => run(target, fixtures_dir, filter, tag, features, output, fail_fast),
        Command::List { fixtures_dir, tag } => list(fixtures_dir, tag),
        Command::Describe { fixtures_dir, id } => describe(fixtures_dir, id),
    };
    std::process::exit(exit);
}

fn run(
    target: PathBuf,
    fixtures_dir: PathBuf,
    filter: Option<String>,
    tag: Option<String>,
    features: Vec<String>,
    output: String,
    fail_fast: bool,
) -> i32 {
    let format = match OutputFormat::parse(&output) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    let fixtures = match FixtureLoader::load_dir(&fixtures_dir) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("failed to load fixtures: {e}");
            return 2;
        }
    };
    let fixtures: Vec<_> = fixtures
        .into_iter()
        .filter(|f| {
            if let Some(s) = &filter {
                if !f.id.contains(s) {
                    return false;
                }
            }
            if let Some(t) = &tag {
                if !f.tags.iter().any(|x| x == t) {
                    return false;
                }
            }
            true
        })
        .collect();

    let target_str = target.to_string_lossy().into_owned();
    let mut adapter = match SubprocessAdapter::spawn(&target_str, &[]) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("failed to spawn adapter: {e}");
            return 2;
        }
    };
    let info = match adapter.init() {
        Ok(i) => i,
        Err(e) => {
            eprintln!("adapter init failed: {e}");
            return 2;
        }
    };

    if format == OutputFormat::Text {
        println!("Loaded {} fixtures", fixtures.len());
        println!("Adapter: {} {}", info.implementation, info.version);
    }

    let mut runner = Runner::new(adapter);
    for feat in &features {
        runner = runner.with_feature(feat.clone());
    }
    let mut results: Vec<FixtureResult> = Vec::new();
    for fixture in &fixtures {
        let r = runner.run(fixture);
        if format == OutputFormat::Text {
            println!("{}", render_text(&r));
        }
        let is_fail = matches!(r, FixtureResult::Fail { .. });
        results.push(r);
        if fail_fast && is_fail {
            break;
        }
    }

    let any_fail = results
        .iter()
        .any(|r| matches!(r, FixtureResult::Fail { .. }));
    match format {
        OutputFormat::Text => println!("{}", render_summary(&results)),
        OutputFormat::Json => println!("{}", render_json(&results)),
        OutputFormat::Tap => println!("{}", render_tap(&results)),
    }

    if any_fail {
        1
    } else {
        0
    }
}

fn list(fixtures_dir: PathBuf, tag: Option<String>) -> i32 {
    let fixtures = match FixtureLoader::load_dir(&fixtures_dir) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    for f in fixtures {
        if let Some(t) = &tag {
            if !f.tags.iter().any(|x| x == t) {
                continue;
            }
        }
        println!("{}\t{}", f.id, f.description);
    }
    0
}

fn describe(fixtures_dir: PathBuf, id: String) -> i32 {
    let fixtures = match FixtureLoader::load_dir(&fixtures_dir) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    for f in fixtures {
        if f.id == id {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::to_value(f).unwrap_or_default())
                    .unwrap_or_default()
            );
            return 0;
        }
    }
    eprintln!("fixture not found: {id}");
    1
}
