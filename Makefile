.PHONY: demo demo-build test interop fmt clippy doc clean \
        deny audit msrv semver coverage schemas-check ci \
        check-versions sync-versions docs-check public-api public-api-check \
        api-classification api-classification-check stable-deps-check \
        stable-experimental-check binding-api binding-api-check

demo-build:
	cargo build --release -p aitp-example-two-agents

# Run the two-agent demo: spawn agent-b in the background, give it a
# moment, then run agent-a in the foreground. agent-a exits cleanly after
# one /echo round-trip.
demo: demo-build
	@echo "Starting two-agent demo..."
	@./target/release/agent-b & \
	BPID=$$!; \
	sleep 0.3; \
	./target/release/agent-a; \
	STATUS=$$?; \
	kill $$BPID 2>/dev/null || true; \
	wait $$BPID 2>/dev/null || true; \
	exit $$STATUS

# Local CI gauntlet.
test:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets --all-features -- -D warnings
	cargo test --workspace --all-features

# Cross-language interop: a real Python <-> Node AITP handshake exercised
# through the native bindings. Builds aitp-py and aitp-node, then runs
# the pytest suite in bindings/interop/.
interop:
	./scripts/interop.sh

fmt:
	cargo fmt --all

clippy:
	cargo clippy --workspace --all-targets --all-features -- -D warnings

doc:
	RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features

# --- CI-parity targets -------------------------------------------------
# Each mirrors a job in .github/workflows/ci.yml so failures surface
# locally before a push. The cargo-* tools are not part of the pinned
# toolchain; install them once with the printed command if missing.

deny:
	@command -v cargo-deny >/dev/null || { echo "cargo-deny missing: cargo install --locked cargo-deny"; exit 1; }
	cargo deny check --all-features

audit:
	@command -v cargo-audit >/dev/null || { echo "cargo-audit missing: cargo install --locked cargo-audit"; exit 1; }
	cargo audit

# cargo-msrv and cargo-tarpaulin need a rustc newer than the repo's
# pinned 1.89 to *install*; install them from outside the repo (see the
# matching ci.yml comments), e.g.: (cd /tmp && cargo install --locked cargo-msrv)
msrv:
	@command -v cargo-msrv >/dev/null || { echo "cargo-msrv missing: (cd /tmp && cargo install --locked cargo-msrv)"; exit 1; }
	cargo msrv verify --manifest-path crates/aitp/Cargo.toml

# The blocking half of semver.yml; the internal crates are advisory there.
semver:
	@command -v cargo-semver-checks >/dev/null || { echo "cargo-semver-checks missing: cargo install --locked cargo-semver-checks"; exit 1; }
	cargo semver-checks --package aitp

# The curated `aitp` surface (RS1.5, RS-RC1). `public-api` regenerates
# crates/aitp/public-api.{stable,experimental}.txt after an intended
# change; `public-api-check` fails on drift (CI runs it). cargo-public-api
# reads rustdoc JSON, so it needs the pinned nightly below.
PUBLIC_API_NIGHTLY ?= nightly-2026-05-05
export PUBLIC_API_NIGHTLY
public-api:
	python3 scripts/public-api.py generate

public-api-check:
	@command -v cargo-public-api >/dev/null || { echo "cargo-public-api missing: cargo install --locked cargo-public-api@0.52.0"; exit 1; }
	python3 scripts/public-api.py check

# docs/api-classification.md: the class of every public struct and enum
# in the stable surface (RS-RC3). `api-classification` regenerates the
# table, keeping its reasons; `api-classification-check` fails on an
# unclassified type, a wrong class or an exhaustive type with no reason
# (CI runs it). Needs the same pinned nightly as public-api.
api-classification:
	python3 scripts/api-classification.py generate

api-classification-check:
	python3 scripts/api-classification.py check

# No type from a pre-1.0 crate in the stable surface (RS-RC5): a 0.x
# dependency can break in any minor release and would force a breaking
# aitp release. Reads the committed public-api.stable.txt.
stable-deps-check:
	python3 scripts/check-stable-deps.py

# No Draft or Proposed mechanism (renewal, Session Trust Bundles, SPIFFE,
# multi-hop delegation) in the stable surface (RS-RC4): those live in
# aitp-experimental. Reads the committed public-api.stable.txt.
stable-experimental-check:
	python3 scripts/check-stable-experimental.py

# The bindings' API snapshots (bindings/aitp-py/api.txt from aitp.pyi,
# bindings/aitp-node/api.txt from index.d.ts), their semver gate. Run
# `make binding-api` after a binding signature change and review the diff.
# bindings.yml and the release workflows also check that the built default
# artifact exports exactly its snapshot.
binding-api:
	python3 scripts/binding-api.py generate

binding-api-check:
	python3 scripts/binding-api.py check

# Enforce lockstep versioning: every published crate inherits the
# workspace version and every inter-crate pin matches it. Guards against a
# hand-edit drifting one crate out of the shared version. CI runs this too.
check-versions:
	./scripts/check-versions.sh

# Rewrite both bindings' manifests (Cargo.toml, package.json, pyproject.toml,
# and each's Cargo.lock path-package pins) to the current workspace version.
# The writer counterpart to `check-versions` above — run this, then
# `check-versions` should pass. release-plz.yml runs this automatically
# against its own release PR branch; use it locally after a manual version
# bump or if `check-versions` fails on binding drift.
sync-versions:
	./scripts/sync-binding-versions.sh

# Mirrors the ci.yml coverage job: same exclude list (kept in sync with
# the COVERAGE_EXCLUDE_CRATES env there) and the explicit adapter build
# the runner integration tests need.
coverage:
	@command -v cargo-tarpaulin >/dev/null || { echo "cargo-tarpaulin missing: (cd /tmp && cargo install --locked cargo-tarpaulin)"; exit 1; }
	cargo build -p aitp-conformance
	cargo tarpaulin --workspace --all-features --skip-clean --timeout 180 \
		--exclude mint-signed-examples --exclude mint-conformance-fixtures \
		--exclude aitp-example-two-agents --exclude aitp-cli \
		--out Stdout

# Verify the vendored JSON Schemas match the spec repo (sibling clone or
# AITP_SPEC=/path). Re-runs the sync and fails if it changes anything.
schemas-check:
	./scripts/sync-schemas.sh
	@git diff --quiet -- tests/schemas/ || { echo "vendored schemas drift from the spec repo — review 'git diff tests/schemas/'"; exit 1; }

# Documentation drift guard: relative links + anchors, RFC-AITP-NNNN §x.y
# citations against the PINNED spec (sibling clone or AITP_SPEC=/path;
# skipped with a notice when absent), protected inbound anchors, banned
# stale strings, MDX hazards. Deliberately NOT part of `ci` below, which
# stays hermetic; CI runs it as the non-required `docs-check` job.
docs-check:
	python3 scripts/check-docs.py

# Everything a PR gates on that can run locally without extra repos.
# (schemas-check needs a spec-repo clone; msrv/semver/coverage need
# their cargo-* tools — run those separately.)
ci: check-versions test doc deny audit
	@echo "== local CI gauntlet passed =="

clean:
	cargo clean
