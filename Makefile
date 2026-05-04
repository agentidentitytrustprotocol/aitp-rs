.PHONY: demo demo-build test fmt clippy doc clean

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

fmt:
	cargo fmt --all

clippy:
	cargo clippy --workspace --all-targets --all-features -- -D warnings

doc:
	RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features

clean:
	cargo clean
