# syntax=docker/dockerfile:1
# Multi-arch production image for globalping-probe (supports linux/amd64 + linux/arm64).
#
# Build a multi-arch manifest and push to a registry:
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     -t <registry>/globalping-probe:latest --push .
#
# Build for the local platform only (no push):
#   docker buildx build --load -t globalping-probe:dev .

# ── Builder: rustup uses the repository's native toolchain manifest ─────────
FROM rust:1.100.0-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake clang libclang-dev ninja-build \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY wit ./wit
COPY src ./src
COPY tests ./tests
RUN cargo build --locked --release --bin globalping-probe

# ── Runtime: minimal runtime image ───────────────────────────────────────────
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
        libcap2-bin \
        traceroute \
        mtr-tiny \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/globalping-probe /usr/local/bin/globalping-probe

# Allow the probe to send ICMP without running as root (ping)
RUN setcap cap_net_raw+ep /usr/bin/ping

ENTRYPOINT ["globalping-probe"]
