//! `aitp-conformance` CLI.

use aitp_conformance::adapter::subprocess::SubprocessAdapter;
use aitp_conformance::adapter::Adapter;
use aitp_conformance::fixture::FixtureLoader;
use aitp_conformance::runner::report::{
    build_report, fixtures_dir_digest, is_commit_sha, Implementation, ReportMeta, RunnerInfo,
    SpecInfo, PROTOCOL,
};
use aitp_conformance::runner::{
    check_gate, render_json, render_summary, render_tap, render_text, FixtureResult, OutputFormat,
    Profile, Runner,
};
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::process::Command as Process;

#[derive(Debug, Parser)]
#[command(
    name = "aitp-conformance",
    about = "AITP conformance test runner (gates on the core tier by default; see `run --profile`)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

// Parsed once per process; boxing `Run` buys nothing.
#[allow(clippy::large_enum_variant)]
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
        /// Fixture gate key: `core` (default) fails the run when any
        /// `required_for_core` fixture (the `aitp/0.3` core tier) fails
        /// or is SKIPped (e.g. OP_NOT_SUPPORTED). `v0.1` gates on
        /// `required_for_v0_1` instead. Any FAIL fails the run under
        /// either profile.
        #[arg(long, default_value_t = Profile::Core)]
        profile: Profile,
        #[command(flatten)]
        report: ReportArgs,
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

/// `--report` and the report fields the run cannot discover itself.
#[derive(Debug, clap::Args)]
struct ReportArgs {
    /// Also write the spec's conformance report (report_version "1",
    /// aitp-conformance-report.schema.json) to this path. The report
    /// covers the whole fixture set, so it cannot be combined with
    /// --filter, --tag or --fail-fast.
    #[arg(long, value_name = "PATH")]
    report: Option<PathBuf>,
    /// Spec commit (full SHA) the fixtures came from. Default: a
    /// SPEC_VERSION file in or above --fixtures-dir, else HEAD of the
    /// spec checkout whose clean `schemas/conformance` is
    /// --fixtures-dir; otherwise --report fails.
    #[arg(long, value_name = "SHA")]
    spec_commit: Option<String>,
    /// Newest spec release tag at or before the spec commit, e.g.
    /// v0.3.2-draft. Default: `git describe --tags --match 'v[0-9]*'`
    /// in that spec checkout; otherwise --report fails.
    #[arg(long, value_name = "TAG")]
    spec_version: Option<String>,
    /// Source repository URL of the implementation. Default: the
    /// adapter init reply's `repository`.
    #[arg(long, value_name = "URL")]
    implementation_repository: Option<String>,
    /// Full SHA of the implementation source tested. Default: the
    /// adapter init reply's `commit`, if any.
    #[arg(long, value_name = "SHA")]
    implementation_commit: Option<String>,
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
            profile,
            report,
        } => run(
            target,
            fixtures_dir,
            filter,
            tag,
            features,
            output,
            fail_fast,
            profile,
            report,
        ),
        Command::List { fixtures_dir, tag } => list(fixtures_dir, tag),
        Command::Describe { fixtures_dir, id } => describe(fixtures_dir, id),
    };
    std::process::exit(exit);
}

#[allow(clippy::too_many_arguments)]
fn run(
    target: PathBuf,
    fixtures_dir: PathBuf,
    filter: Option<String>,
    tag: Option<String>,
    features: Vec<String>,
    output: String,
    fail_fast: bool,
    profile: Profile,
    report_args: ReportArgs,
) -> i32 {
    let format = match OutputFormat::parse(&output) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    if report_args.report.is_some() && (filter.is_some() || tag.is_some() || fail_fast) {
        eprintln!("--report covers the whole fixture set; drop --filter, --tag and --fail-fast");
        return 2;
    }
    // Resolve the spec side of the report before running anything, so a
    // missing commit fails fast instead of after the whole corpus.
    let spec = match &report_args.report {
        Some(_) => match resolve_spec(&fixtures_dir, &report_args) {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!("--report: {e}");
                return 2;
            }
        },
        None => None,
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

    // Conformance gate (spec conformance README, "Conformance runner
    // enforcement rules"): a fixture marked `required_for_v0_N` for the
    // selected profile MUST pass — it may neither fail nor be SKIPped
    // because the adapter lacks the op (OP_NOT_SUPPORTED). A skip whose
    // assertion was negated by an opted-in experimental feature (e.g.
    // `del-007` under `experimental-multihop-delegation`) is exempt —
    // that is a deliberate draft-feature run, not a missing capability —
    // but is still listed so the exemption is visible.
    let gate = check_gate(profile, &fixtures, &results);
    if !gate.exempted.is_empty() {
        eprintln!(
            "\n{profile} conformance gate: {} required fixture(s) exempted by feature negation:",
            gate.exempted.len()
        );
        for e in &gate.exempted {
            eprintln!("{e}");
        }
    }
    if !gate.passed() {
        eprintln!(
            "\n{profile} conformance gate FAILED — {} required fixture(s) did not pass:",
            gate.violations.len()
        );
        for v in &gate.violations {
            eprintln!("{v}");
        }
    }

    if let (Some(path), Some(spec)) = (&report_args.report, spec) {
        if let Err(e) = write_report(
            path,
            &fixtures_dir,
            &fixtures,
            &results,
            &features,
            &info,
            &report_args,
            spec,
        ) {
            eprintln!("--report: {e}");
            return 2;
        }
    }

    if any_fail || !gate.passed() {
        1
    } else {
        0
    }
}

/// The spec repository; the git fallbacks only trust a checkout of it.
const SPEC_REPO: &str = "agentidentitytrustprotocol/agentidentitytrustprotocol";

/// The report's `spec` object. Never guessed: `commit` is
/// --spec-commit, else a `SPEC_VERSION` file in or above
/// --fixtures-dir (a consumer's vendored pin, e.g.
/// `tests/schemas/SPEC_VERSION`), else HEAD of a clean spec checkout;
/// `version` is --spec-version, else `git describe` in a spec checkout.
fn resolve_spec(fixtures_dir: &Path, args: &ReportArgs) -> Result<SpecInfo, String> {
    let commit = match &args.spec_commit {
        Some(c) => c.clone(),
        None => match pinned_spec_commit(fixtures_dir)? {
            Some(c) => c,
            None => spec_checkout(fixtures_dir)
                .and_then(|_| git(fixtures_dir, &["rev-parse", "HEAD"]))
                .map_err(|e| format!("no spec commit: {e}; pass --spec-commit"))?,
        },
    };
    if !is_commit_sha(&commit) {
        return Err(format!(
            "spec commit {commit:?} is not a full lowercase 40-hex SHA"
        ));
    }
    let version = match &args.spec_version {
        Some(v) => v.clone(),
        None => spec_checkout(fixtures_dir)
            .and_then(|_| {
                git(
                    fixtures_dir,
                    &[
                        "describe",
                        "--tags",
                        "--match",
                        "v[0-9]*",
                        "--abbrev=0",
                        &commit,
                    ],
                )
            })
            .map_err(|e| format!("no spec release tag: {e}; pass --spec-version"))?,
    };
    Ok(SpecInfo {
        commit,
        version,
        protocol: PROTOCOL,
    })
}

/// The first `SPEC_VERSION` file in `fixtures_dir` or an ancestor.
fn pinned_spec_commit(fixtures_dir: &Path) -> Result<Option<String>, String> {
    let dir = fixtures_dir
        .canonicalize()
        .map_err(|e| format!("{}: {e}", fixtures_dir.display()))?;
    for d in dir.ancestors() {
        let pin = d.join("SPEC_VERSION");
        if pin.is_file() {
            let text =
                std::fs::read_to_string(&pin).map_err(|e| format!("{}: {e}", pin.display()))?;
            return Ok(Some(text.trim().to_owned()));
        }
    }
    Ok(None)
}

/// Ok when `fixtures_dir` is the `schemas/conformance` of a checkout of
/// the spec repository with no local changes there, so its HEAD and
/// tags really describe the fixtures that ran.
fn spec_checkout(fixtures_dir: &Path) -> Result<(), String> {
    let origin = git(fixtures_dir, &["remote", "get-url", "origin"])?;
    let origin = origin.trim_end_matches('/').trim_end_matches(".git");
    if !origin.ends_with(&format!("/{SPEC_REPO}")) && !origin.ends_with(&format!(":{SPEC_REPO}")) {
        return Err(format!(
            "{} is not in a checkout of {SPEC_REPO} (origin {origin})",
            fixtures_dir.display()
        ));
    }
    let top = git(fixtures_dir, &["rev-parse", "--show-toplevel"])?;
    let expected = Path::new(&top).join("schemas").join("conformance");
    let same = match (expected.canonicalize(), fixtures_dir.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    };
    if !same {
        return Err(format!(
            "{} is not the schemas/conformance of the spec checkout at {top}",
            fixtures_dir.display()
        ));
    }
    if !git(fixtures_dir, &["status", "--porcelain", "--", "."])?.is_empty() {
        return Err(format!("{} has local changes", fixtures_dir.display()));
    }
    Ok(())
}

fn git(dir: &Path, args: &[&str]) -> Result<String, String> {
    let out = Process::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .map_err(|e| format!("git: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "git {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

#[allow(clippy::too_many_arguments)]
fn write_report(
    path: &Path,
    fixtures_dir: &Path,
    fixtures: &[aitp_conformance::Fixture],
    results: &[FixtureResult],
    features: &[String],
    info: &aitp_conformance::AdapterInfo,
    args: &ReportArgs,
    spec: SpecInfo,
) -> Result<(), String> {
    let repository = args
        .implementation_repository
        .clone()
        .or_else(|| info.repository.clone())
        .ok_or("the adapter's init reply has no `repository`; pass --implementation-repository")?;
    if !repository.starts_with("https://") {
        return Err(format!(
            "implementation repository {repository:?} is not an https:// URL"
        ));
    }
    let commit = args
        .implementation_commit
        .clone()
        .or_else(|| info.commit.clone());
    if let Some(c) = &commit {
        if !is_commit_sha(c) {
            return Err(format!(
                "implementation commit {c:?} is not a full lowercase 40-hex SHA"
            ));
        }
    }
    let digest = fixtures_dir_digest(fixtures_dir)
        .map_err(|e| format!("digest of {}: {e}", fixtures_dir.display()))?;
    let report = build_report(
        fixtures,
        results,
        ReportMeta {
            implementation: Implementation {
                name: info.implementation.clone(),
                version: info.version.clone(),
                repository,
                commit,
            },
            runner: Some(RunnerInfo::this()),
            spec,
            fixtures_dir_digest: digest,
            features_enabled: features.to_vec(),
            generated_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        },
    );
    let mut json = serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?;
    json.push('\n');
    std::fs::write(path, json).map_err(|e| format!("write {}: {e}", path.display()))?;
    for g in &report.gates {
        let verdict = if g.passed { "passed" } else { "not passed" };
        eprintln!("report gate {:?}: {verdict}", g.name);
        for id in &g.blocking {
            eprintln!("  blocked by {id}");
        }
    }
    eprintln!("report written to {}", path.display());
    Ok(())
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
