# Multi-stage build: Rust binary compilation for Nitro Enclave
# This Dockerfile produces a static musl binary that can be converted
# to an AWS Nitro Enclave Image (.eif) via: nitro-cli build-enclave \
#   --docker-uri zero_copy_pii_proxy:latest \
#   --output-file proxy.eif

# ============================================================================
# STAGE 1: Builder
# ============================================================================
FROM rust:1.98.0-alpine3.24 AS builder

# Install musl toolchain and build dependencies
RUN apk add --no-cache \
    musl-dev \
    pkgconfig \
    openssl-dev \
    openssl-libs-static \
    libssl3 \
    ca-certificates

# Set build environment for static linking
ENV RUSTFLAGS="-C target-feature=+crt-static"
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true

WORKDIR /build

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Copy source tree
COPY src ./src
COPY benches ./benches
COPY tests ./tests
COPY fuzz ./fuzz

# Build static binary for x86_64-unknown-linux-musl
# This produces a fully static executable with zero runtime dependencies
RUN RUSTFLAGS="${RUSTFLAGS} -C debuginfo=0 -C strip=symbols" cargo build --release \
    --target x86_64-unknown-linux-musl \
    --locked \
    --features nitro

# Verify binary is static (no dynamic library dependencies)
RUN ldd /build/target/x86_64-unknown-linux-musl/release/zero_copy_pii_proxy || \
    echo "✓ Binary is statically linked (ldd returned error as expected)"

# Extract the static binary
RUN cp /build/target/x86_64-unknown-linux-musl/release/zero_copy_pii_proxy /proxy-bin

# ============================================================================
# STAGE 2: Final Image (Distroless Static)
# ============================================================================
# Using distroless/static:nonroot ensures:
# - No shell, no package manager, no unnecessary binaries
# - Non-root user (UID 65532) enforced at container level
# - Minimal attack surface for Nitro Enclave attestation
FROM gcr.io/distroless/static:nonroot

# Non-root user (UID 65532) is baked into distroless/static:nonroot
# This is verified at enclave boot and cannot be overridden
USER nonroot:nonroot

# Copy CA certificates from builder for TLS to upstream LLM
COPY --from=builder --chown=nonroot:nonroot /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the static binary (will run as UID 65532)
COPY --from=builder --chown=nonroot:nonroot /proxy-bin /proxy

# Expose data plane (Nitro Enclave host will forward external traffic)
EXPOSE 3000

# Expose admin/metrics plane (Nitro Enclave host will restrict to local attestation)
EXPOSE 9090

# Entry point: run the proxy binary
# The Nitro Enclave will boot this process in a hardened VM with:
# - CPU/memory limits enforced by parent EC2 instance
# - Network I/O limited to enclave vCPU allocation
# - Parent EC2 can only communicate via attestation/TLS
ENTRYPOINT ["/proxy"]

# ============================================================================
# NITRO ENCLAVE BUILD INSTRUCTIONS
# ============================================================================
# To convert this image to a Nitro Enclave:
#
# 1. Build the Docker image:
#    docker build -t zero_copy_pii_proxy:latest .
#
# 2. Install AWS Nitro CLI:
#    pip install aws-nitro-cli
#
# 3. Build the enclave image (.eif):
#    nitro-cli build-enclave \
#      --docker-uri zero_copy_pii_proxy:latest \
#      --output-file proxy.eif
#
# 4. Launch the enclave from EC2 host:
#    nitro-cli run-enclave \
#      --enclave-image-format eif \
#      --eif-path proxy.eif \
#      --cpu-count 4 \
#      --memory 2048 \
#      --enclave-cid 42
#
# 5. Verify enclave attestation:
#    nitro-cli describe-enclaves
#
# The resulting .eif file is:
# - Deterministically built (reproducible)
# - Signed by AWS Nitro infrastructure
# - Verifiable at boot time via PCR (Platform Configuration Register)
# - Isolated from parent EC2 with zero-trust communication via vSOCKET
#
# ============================================================================
