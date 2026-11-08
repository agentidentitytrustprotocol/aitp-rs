# CI cost

This page records the one-time CI-cost pass (2026-11-08): what CI used, what changed, and the merge queue enabled afterwards. The repository is public, so GitHub-hosted runner minutes cost $0. The numbers matter for queue time and for the shared runner limits, not for billing.

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

In the merge queue (`merge_group`) the list is a `git diff` of the group instead; see [Merge queue](#merge-queue-enabled-2026-11-08). Every other event (push to `main`, manual dispatch) always runs everything.

The gated jobs run unless the `changes` job succeeded and said `rust=false`:

```yaml
if: ${{ !cancelled() && (needs.changes.result != 'success' || needs.changes.outputs.rust != 'false') }}
```

A broken `changes` job therefore runs everything; it never skips everything. The required checks keep their names. A required job that is skipped reports as skipped, which branch protection treats as passing, so a docs-only PR can still merge. The `test` matrix gates each step, not the job: its required contexts (`test (<os> / <toolchain>)`) are expanded from the matrix, and a job-level `if` would leave them pending. So on a docs-only PR the four test runners still start (Windows and macOS included) and finish in seconds, but GitHub bills each job as at least a minute: a docs-only PR still costs about 4 job-min for the test legs (2 of them Windows and macOS) plus the ungated lint, docs, deny, audit and semver jobs.

Deploy and release workflows were not touched. That includes the PR-triggered `aitp-py-release.yml` and `bindings-release.yml`, which have no concurrency group (~1.7k PR job-min); adding one is a release-workflow change for the owner.

Two limits of the filter, both accepted: a PR that edits `scripts/ci-changes.sh` is classified by its own edited copy (no worse than editing `ci.yml`), and the `release-plz-` skip in `fuzz-pr.yml` keys on the branch name, which any contributor can choose. `fuzz-pr` is not a required check; if it becomes one, its job-level `if` must move to the steps like `test`.

## Merge queue (enabled 2026-11-08)

The owner enabled a merge queue on `main` on 2026-11-08 (DECISIONS.md D19). PRs merge through the queue. A PR's own run is no longer its last run: the queue builds a temporary `gh-readonly-queue/main/pr-<N>-<sha>` branch (`main` plus every PR queued ahead of it, squashed) and runs every required check on it as a `merge_group` event. Only a green group merges.

- **Triggers.** `ci.yml`, `semver.yml` and `readme-smoke.yml` own all the required checks, and each runs on `merge_group`. The required checks are the original 21 plus `shell scripts`, which became required the same day. The live README job (public peer) does not run in the queue. With a queue on, a required check that never reports on `merge_group` blocks every PR until the check-response timeout. So a new required check must run on `merge_group` too, or report "skipped" through a job-level `if:`. The jobs must not be absent.
- **Gating.** `scripts/ci-changes.sh` has a `merge_group` branch. It diffs `merge_group.base_sha..head_sha` in the checkout, fetching a missing commit at depth 1, and reads the paths with `-z` so unusual paths are not quoted. It fails closed (runs everything) on a missing or malformed SHA, an unfetchable commit, a failed diff or an empty diff. `scripts/ci-changes-test.sh` covers each of these cases. A docs-only group therefore skips the Rust jobs the same way a docs-only PR does.
- **semver.** In the queue the baseline is the queue's base commit, and the `semver-break-approved` label is read from the PR named in the group's `head_ref`. If the label lookup fails, the break counts as not approved. One limit is accepted: if an earlier PR in the same group carries an approved break, a later group fails as well. Re-queue it after the earlier PR has landed.
- **Settings.** Classic branch protection is unchanged apart from the added `shell scripts` context. The queue is the repository ruleset `main merge queue`, which holds a single `merge_queue` rule: squash, build concurrency 3, merge up to 3, minimum group size 1, wait 1 min, all-green grouping, check-response timeout 60 min. To disable the queue, delete that ruleset (Settings → Rules, or `gh api -X DELETE repos/agentidentitytrustprotocol/aitp-rs/rulesets/26786315`). Classic protection keeps working on its own.

**Estimate.** The queue adds one `merge_group` run per merged PR. That run costs about the same as the `push` run on `main` (7.2k job-min per 30 days, all events), and less for docs-only groups. It also removes the "update branch, run again" cycles that strict up-to-date protection forced on PRs. Net, it is roughly cost-neutral at first. The saving of about 5–6k job-min per 30 days arrives once the heavy `push`-to-`main` jobs (coverage, the feature matrix) are dropped, because the queue already tested the exact commit that lands. That step has **not** been taken: it changes what runs on `main`, and it should wait until the queue has run cleanly for a while.
