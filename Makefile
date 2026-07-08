.PHONY: demo demo-build test interop fmt clippy doc clean \
        deny audit msrv semver coverage schemas-check ci

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

semver:
	@command -v cargo-semver-checks >/dev/null || { echo "cargo-semver-checks missing: cargo install --locked cargo-semver-checks"; exit 1; }
	cargo semver-checks

# Mirrors the ci.yml coverage job: same exclude list (kept in sync with
# the COVERAGE_EXCLUDE_CRATES env there) and the explicit adapter build
# the runner integration tests need.
coverage:
	@command -v cargo-tarpaulin >/dev/null || { echo "cargo-tarpaulin missing: (cd /tmp && cargo install --locked cargo-tarpaulin)"; exit 1; }
	cargo build -p aitp-rs-adapter
	cargo tarpaulin --workspace --all-features --skip-clean --timeout 180 \
		--exclude mint-signed-examples --exclude mint-conformance-fixtures \
		--exclude aitp-example-two-agents --exclude aitp-cli \
		--out Stdout

# Verify the vendored JSON Schemas match the spec repo (sibling clone or
# AITP_SPEC=/path). Re-runs the sync and fails if it changes anything.
schemas-check:
	./scripts/sync-schemas.sh
	@git diff --quiet -- tests/schemas/ || { echo "vendored schemas drift from the spec repo — review 'git diff tests/schemas/'"; exit 1; }

# Everything a PR gates on that can run locally without extra repos.
# (schemas-check needs a spec-repo clone; msrv/semver/coverage need
# their cargo-* tools — run those separately.)
ci: test doc deny audit
	@echo "== local CI gauntlet passed =="

clean:
	cargo clean
