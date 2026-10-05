# syntax=docker/dockerfile:1
# Multi-arch production image for globalping-probe (supports linux/amd64 + linux/arm64).
#
# Build a multi-arch manifest and push to a registry:
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     -t <registry>/globalping-probe:latest --push .
#
# Build for the local platform only (no push):
#   docker buildx build --load -t globalping-probe:dev .

# ── Stage 1: dependency cache ─────────────────────────────────────────────────
# Pre-build all crate dependencies so that rebuilds triggered by source-only
# changes don't re-download/re-compile the entire dependency tree.
FROM rust:1.99.0-slim-bookworm AS deps

RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy manifests only (.cargo/config.toml is a local Windows dev artifact, not needed in container)
COPY Cargo.toml Cargo.lock ./

# Stub out src so we can compile deps without the real source
RUN mkdir -p src tests/integration \
 && echo 'fn main() {}' > src/main.rs \
 && echo '' > tests/integration/mod.rs

# Build dependencies only (will be cached unless Cargo.toml/Cargo.lock change)
RUN cargo build --release \
 && rm -rf src tests

# ── Stage 2: compile the probe ────────────────────────────────────────────────
FROM deps AS builder

COPY src ./src
COPY tests ./tests

# Touch main.rs so cargo knows it changed (avoids stale-artifact issues)
RUN touch src/main.rs

RUN cargo build --release

# ── Stage 3: minimal runtime image ───────────────────────────────────────────
FROM debian:bookworm-slim

# Runtime tools the probe shells out to at measurement time:
#   curl        – HTTP measurements
#   openssl     – TLS cert enrichment (enrich_tls: s_client + x509)
#   dnsutils    – dig, for DNS pre-resolution
#   iputils-ping – ping measurements
#   traceroute  – traceroute measurements
#   mtr-tiny    – MTR measurements
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        openssl \
        ca-certificates \
        dnsutils \
        iproute2 \
        iputils-ping \
        traceroute \
        mtr-tiny \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/globalping-probe /usr/local/bin/globalping-probe

# Allow the probe to send ICMP without running as root (ping)
RUN setcap cap_net_raw+ep /usr/bin/ping

ENTRYPOINT ["globalping-probe"]
