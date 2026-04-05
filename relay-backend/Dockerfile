# relay-backend Dockerfile
# Multi-stage build: compile with Rust toolchain, run on minimal Debian.
#
# Build from workspace root:
#   docker build -f relay-backend/Dockerfile -t relay-backend .
#
# Run:
#   docker run -p 80:80 \
#     -e REDIS_HOSTNAME=redis:6379 \
#     -e RELAY_DATA_FILE=/data/relays.json \
#     relay-backend

# -------------------------------------------------------
# Stage 1: Build
# -------------------------------------------------------
FROM rust:1.85-bookworm AS builder

WORKDIR /build

# Copy workspace-level files first (better layer caching)
COPY Cargo.toml Cargo.lock ./

# Copy only the crates needed for relay-backend
COPY relay-xdp-common/ relay-xdp-common/
COPY relay-backend/ relay-backend/

# Create stub crates for workspace members we don't need to build,
# so Cargo.toml workspace resolution succeeds.
RUN mkdir -p relay-xdp/src xtask/src && \
    echo 'fn main() {}' > relay-xdp/src/main.rs && \
    echo '' > relay-xdp/src/lib.rs && \
    echo 'fn main() {}' > xtask/src/main.rs
COPY relay-xdp/Cargo.toml relay-xdp/Cargo.toml
COPY xtask/Cargo.toml xtask/Cargo.toml

# Build release binary
RUN cargo build --release -p relay-backend

# -------------------------------------------------------
# Stage 2: Runtime
# -------------------------------------------------------
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/relay-backend /usr/local/bin/relay-backend

# Default HTTP port (configurable via HTTP_PORT env var)
EXPOSE 80

ENTRYPOINT ["relay-backend"]

