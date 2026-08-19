# Stage 1: builder
FROM rust:1.77-alpine AS builder

# Install packages needed for musl static linking
RUN apk add --no-cache musl-dev build-base curl git

WORKDIR /usr/src/app

# Copy manifests first to leverage Docker layer caching
COPY Cargo.toml Cargo.lock ./

# Copy the rest of the source
COPY . .

# Add MUSL target and build a static binary
RUN rustup target add x86_64-unknown-linux-musl \
    && export RUSTFLAGS="-C target-feature=+crt-static" \
    && cargo build --release --workspace --target x86_64-unknown-linux-musl

# Stage 2: runtime
FROM gcr.io/distroless/static-debian12:nonroot

# Copy the statically linked binary from the builder stage
COPY --from=builder /usr/src/app/target/x86_64-unknown-linux-musl/release/zero_copy_pii_proxy /usr/local/bin/zero_copy_pii_proxy

EXPOSE 8080 9090

ENTRYPOINT ["/usr/local/bin/zero_copy_pii_proxy"]
