# The public AITP interop peer: `aitp serve --interop`
# (docs/interop-peer.md). Build from the repository root:
#
#   docker build -f deploy/interop-peer/Dockerfile -t aitp-interop-peer .
#   docker run --rm -p 8080:8080 -e AITP_PEER_KEY="$(aitp keygen)" aitp-interop-peer
#
# Configuration is all environment (see deploy/interop-peer/env.example).
# The container speaks plain HTTP on $PORT (default 8080); TLS is
# terminated at the platform edge.

# ---- build stage ----
# Not below the workspace `rust-version` (scripts/check-docker-rust.sh).
FROM rust:1.90-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p aitp-cli --features serve --bin aitp

# ---- runtime stage ----
FROM debian:bookworm-slim AS runtime
RUN useradd --system --uid 10001 --home-dir /app aitp
WORKDIR /app
COPY --from=build /src/target/release/aitp /usr/local/bin/aitp
USER aitp
ENV PORT=8080
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/aitp", "serve", "--interop"]
