# CI cost

This page records the one-time CI-cost pass (2026-11-08): what CI used, what changed, and the next step if it needs to drop further. The repository is public, so GitHub-hosted runner minutes cost $0. The numbers matter for queue time and for the shared runner limits, not for billing.

## Baseline: 2026-10-08 to 2026-11-07

The baseline covers the 2,810 workflow runs fetched from the Actions runs API for the window (their jobs' durations, each rounded up to the minute the way GitHub meters it), about **42.5k job-minutes**. Run counts from other queries of the same window differ (the runs API's filtered counts are not stable), so treat the absolute figures as approximate; the savings below are ratios of this same sample.

| Workflow | Job-min | Main contributors |
|---|---:|---|
| ci | 23,888 | coverage (tarpaulin) 4,479 · test matrix 5,107 (Windows 1,992, macOS 1,147, Linux 1,968) · feature matrix 1,865 · cargo-audit 1,691 · bench-check 968 · interop peer (docker) 711 |
| bindings | 6,626 | cargo-audit 1,226 · aitp-py ×3 Python versions ~1,880 · interop (python ↔ node) 625 |
| fuzz-pr | 6,551 | 14 targets, ~2.2 min each per run |
| fuzz (schedule) | 1,686 | nightly |
| everything else | ~3,750 | release, semver, readme-smoke, release-plz, … |

By event, `pull_request` used 33.4k, `push` 7.2k and `schedule` 1.8k.

Other measurements:

- Runner OS: Linux 38.1k, Windows 2.0k, macOS 1.8k, ARM 0.6k. Every job except the test matrix's Windows and macOS legs already runs on the standard `ubuntu-latest` runner, the smallest GitHub-hosted runner. No job needed to move to a smaller one.
- PR runs: 159 of the 270 `fuzz-pr` runs, and 159 of the 419 `ci` pull-request runs, were on `release-plz-*` branches. 123 `ci` pull-request runs were cancelled by concurrency.
- PR contents: 96 of the 242 PRs opened in the window touched no Rust-relevant path, as `scripts/ci-changes.sh` defines it.

## What changed

| Change | Where | Estimated saving / 30 days |
|---|---|---:|
| Install cargo-audit as a prebuilt binary (`taiki-e/install-action`) instead of `cargo install` (~3.2 min to ~0.3 min) | `ci.yml` audit, `bindings.yml` audit | ~2.6k |
| Skip `fuzz-pr` on `release-plz-*` PRs, which only bump versions and changelogs. The scheduled `fuzz` run and normal PRs still fuzz. Add concurrency (cancel-in-progress) per PR. | `fuzz-pr.yml` | ~3.8k |
| Gate the test matrix, coverage, bench-check and interop peer (docker) on the `changes` job, as the feature matrix, conformance, xcheck, wasm and e2e jobs already were | `ci.yml` | ~2.2k–3.6k (25–40% of the PR runs of ~8.9k PR job-min) |
| Replace `dorny/paths-filter` with `scripts/ci-changes.sh`, which fails closed and has its own tests (`scripts/ci-changes-test.sh`) | `ci.yml` changes job | — (safety, not minutes) |

The estimated total is **~8.6k–10k job-min per 30 days, about 20–24%** of the baseline.

### Fail-closed gating

On a pull request, the `changes` job lists the PR's changed files with `gh api …/pulls/N/files`, counting both the old and new path of a renamed file. It sets `rust=true` if any path matches a Rust-relevant pattern: crates, tests, examples, scripts, tools, deploy, workflows, Cargo and toolchain files, any `Dockerfile`, or `.dockerignore`. Any of the following also gives `rust=true`, with a warning:

- a failed API call;
- an empty list;
- a missing repository or PR number;
- a list at the API's 3,000-file cap.

Every other event (push to `main`, manual dispatch) always runs everything.

The gated jobs run unless the `changes` job succeeded and said `rust=false`:

```yaml
if: ${{ !cancelled() && (needs.changes.result != 'success' || needs.changes.outputs.rust != 'false') }}
```

A broken `changes` job therefore runs everything; it never skips everything. The required checks keep their names. A required job that is skipped reports as skipped, which branch protection treats as passing, so a docs-only PR can still merge. The `test` matrix gates each step, not the job: its required contexts (`test (<os> / <toolchain>)`) are expanded from the matrix, and a job-level `if` would leave them pending. So on a docs-only PR the four test runners still start (Windows and macOS included) and finish in seconds, but GitHub bills each job as at least a minute: a docs-only PR still costs about 4 job-min for the test legs (2 of them Windows and macOS) plus the ungated lint, docs, deny, audit and semver jobs.

Deploy and release workflows were not touched. That includes the PR-triggered `aitp-py-release.yml` and `bindings-release.yml`, which have no concurrency group (~1.7k PR job-min); adding one is a release-workflow change for the owner.

Two limits of the filter, both accepted: a PR that edits `scripts/ci-changes.sh` is classified by its own edited copy (no worse than editing `ci.yml`), and the `release-plz-` skip in `fuzz-pr.yml` keys on the branch name, which any contributor can choose. `fuzz-pr` is not a required check; if it becomes one, its job-level `if` must move to the steps like `test`.

## Next lever: a merge queue

The repository has no merge queue today: a PR's own run is its last run before merge, plus the `push` run on `main` (7.2k job-min). If a merge queue is enabled:

1. Add `merge_group:` to `ci.yml`'s triggers.
2. In `scripts/ci-changes.sh`, add a `merge_group` branch. It should diff `github.event.merge_group.base_sha` against `head_sha`, which needs a checkout deep enough to hold both commits. It should fail closed on a missing SHA or a failed diff, and cover each of those cases in `scripts/ci-changes-test.sh`.
3. Consider dropping the `push`-to-`main` run of the heavy jobs (coverage, feature matrix), because the queue already tested the exact merge commit.

Together these would save about another 5–6k job-min per 30 days. Not done in this pass, because it changes how PRs merge and that needs an owner decision.
