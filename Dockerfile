# Reference container image for aitp-rs.
#
# aitp-rs is a *library*, not a deployable service — so this image builds
# and runs the two-agent demo (the repo's runnable artifact): a full
# four-message mutual handshake plus a capability invocation, both agents
# in one container over loopback. Use it to try AITP (`docker run`) and as
# a build template for embedding the library in your own service.
#
#   docker build -t aitp-demo .
#   docker run --rm aitp-demo
#
# For a real deployment you embed the library in your own binary and
# terminate TLS (the client enforces HTTPS for any non-localhost peer);
# see docs/deployment.md and docs/key-management.md.

# ---- build stage ----
FROM rust:1.89-bookworm AS build
WORKDIR /src
# Copy the whole workspace (the demo depends on the path-linked crates).
COPY . .
# Build only the demo package in release mode.
RUN cargo build --release -p aitp-example-two-agents \
    --bin agent-a --bin agent-b

# ---- runtime stage ----
FROM debian:bookworm-slim AS runtime
# Run as a non-root user.
RUN useradd --system --uid 10001 --home-dir /app aitp
WORKDIR /app
COPY --from=build /src/target/release/agent-a /usr/local/bin/agent-a
COPY --from=build /src/target/release/agent-b /usr/local/bin/agent-b
COPY examples/two-agents/docker-entrypoint.sh /usr/local/bin/aitp-demo
RUN chmod +x /usr/local/bin/aitp-demo
USER aitp
# The demo is self-contained over loopback and prints the handshake
# transcript, then exits 0.
ENTRYPOINT ["/usr/local/bin/aitp-demo"]
