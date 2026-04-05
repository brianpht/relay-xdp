# relay-xdp Dockerfile
# Three-stage build:
#   1. Build eBPF program (nightly toolchain + bpf-linker)
#   2. Build userspace binary (stable toolchain)
#   3. Minimal runtime image
#
# Build from workspace root:
#   docker build -f relay-xdp/Dockerfile -t relay-xdp .
#
# Run (requires privileged mode for eBPF + XDP):
#   docker run --privileged --net=host \
#     -e RELAY_PUBLIC_ADDRESS=10.0.0.1 \
#     -e RELAY_PORT=40000 \
#     -e RELAY_NAME=my-relay \
#     -e RELAY_BACKEND_URL=http://backend:80 \
#     relay-xdp
#
# Requirements:
#   - Host kernel 6.5+ with relay_module.ko loaded
#   - --privileged or CAP_NET_ADMIN + CAP_BPF + CAP_SYS_ADMIN
#   - --net=host (XDP attaches to host NIC)

# -------------------------------------------------------
# Stage 1: Build eBPF program (nightly)
# -------------------------------------------------------
FROM rust:nightly-bookworm AS ebpf-builder

RUN rustup component add rust-src

# Install bpf-linker (required for eBPF target)
RUN cargo install bpf-linker

WORKDIR /build

# Copy only crates needed for eBPF build
COPY relay-xdp-common/ relay-xdp-common/
COPY relay-xdp-ebpf/ relay-xdp-ebpf/

WORKDIR /build/relay-xdp-ebpf

RUN cargo +nightly build \
    --target bpfel-unknown-none \
    -Z build-std=core \
    --release

# -------------------------------------------------------
# Stage 2: Build userspace binary (stable)
# -------------------------------------------------------
FROM rust:1.85-bookworm AS builder

WORKDIR /build

# Copy workspace-level files
COPY Cargo.toml Cargo.lock ./

# Copy crates needed for relay-xdp
COPY relay-xdp-common/ relay-xdp-common/
COPY relay-xdp/ relay-xdp/

# Stub crates for workspace resolution
RUN mkdir -p relay-backend/src xtask/src && \
    echo 'fn main() {}' > relay-backend/src/main.rs && \
    echo '' > relay-backend/src/lib.rs && \
    echo 'fn main() {}' > xtask/src/main.rs
COPY relay-backend/Cargo.toml relay-backend/Cargo.toml
COPY xtask/Cargo.toml xtask/Cargo.toml

# Copy compiled eBPF binary from stage 1
COPY --from=ebpf-builder \
    /build/relay-xdp-ebpf/target/bpfel-unknown-none/release/relay-xdp-ebpf \
    /build/relay_xdp_rust.o

# Build release binary
RUN cargo build --release -p relay-xdp

# -------------------------------------------------------
# Stage 3: Runtime
# -------------------------------------------------------
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        libelf1 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/relay-xdp /usr/local/bin/relay-xdp
COPY --from=ebpf-builder \
    /build/relay-xdp-ebpf/target/bpfel-unknown-none/release/relay-xdp-ebpf \
    /opt/relay/relay_xdp_rust.o

# relay-xdp requires:
#   --privileged or CAP_NET_ADMIN + CAP_BPF + CAP_SYS_ADMIN
#   Host kernel 6.5+ with relay_module.ko loaded
#   --net=host for XDP attachment

ENTRYPOINT ["relay-xdp"]

