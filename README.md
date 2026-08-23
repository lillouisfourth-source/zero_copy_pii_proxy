# zero_copy_pii_proxy — Operational Runbook

This repository implements a small proxy that masks PII from streaming LLM responses and forwards them to clients with an SSE-friendly implementation and strong production guardrails.

Table of Contents
- Architecture
- Local Development
- Observability & Load Testing
- Production Packaging
- Troubleshooting


## Architecture

- Axum 0.8 (server): The application uses axum for routing and middleware. The server is run using axum::serve with a tokio::net::TcpListener for predictable socket binding and graceful shutdown handling.

- Aho-Corasick zero-copy PII masking: PII detection and redaction are implemented using the aho-corasick crate in a zero-copy style via slices and streaming-aware buffers. This enables low-allocation, high-throughput masking suitable for streaming SSE workloads.

- Distroless Docker packaging: The project is packaged with a multi-stage Docker build that compiles a static musl binary and runs it on Google's distroless static image. This minimizes image size and attack surface in production.


## Local Development

Requirements
- Rust toolchain (stable)
- Cargo
- Docker (for building/runtime)
- Node.js (optional, for running the mock upstream locally)
- k6 (optional, for load testing)

Common commands

- Run the proxy locally (binds to PROXY_PORT env or default 3000):

```bash
cargo run --manifest-path Cargo.toml --release
```

Set `ALLOWED_ORIGINS` to a comma-separated origin allowlist. If it is unset, all cross-origin requests are rejected.

- Run tests:

```bash
cargo test --workspace
```

- Run clippy and fail on warnings:

```bash
cargo clippy --workspace -- -D warnings
```


## Observability & Load Testing

A docker-compose stack is provided to quickly run the mock upstream server, the proxy (built from the `Dockerfile`), Prometheus, and Grafana.

Start the observability stack with Prometheus and Grafana automatically:

```bash
# Build images and start services in detached mode
docker-compose up -d --build
```

Compose requires `proxy-auth.txt` with one valid token per line and a `PROXY_PRIVATE_KEY` environment variable containing a 32-byte hex or base64 seed.

- Mock upstream (Mock SSE generator): http://localhost:8081
- Proxy: http://localhost:3000/
- Internal health and metrics: http://localhost:9090/health and http://localhost:9090/metrics
- Prometheus UI: http://localhost:9091 (scraped proxy metrics)
- Grafana UI: http://localhost:3001 (anonymous access enabled)

Run the k6 load test to exercise 100 concurrent SSE streams for 30s:

```bash
k6 run tests/redteam/load_test.js
```

The proxy endpoint is port `3000`; health and Prometheus metrics are internal-only on port `9090`.

Open Prometheus at http://localhost:9091 and Grafana at http://localhost:3001 to monitor the metrics in real-time. Useful metrics:

- `active_sse_streams` (gauge) — tracked by a drop guard to ensure streams are decremented on task completion/drop
- `proxy_requests_total` (counter) — total proxied requests

The red-team fixtures and k6 scenarios live under `tests/redteam/`.


## Production Packaging

The included `Dockerfile` is a multi-stage build that:
1. Uses `rust:1.98.0-alpine3.24` to compile a statically-linked `x86_64-unknown-linux-musl` binary.
2. Uses `gcr.io/distroless/static-debian12:nonroot` as the runtime image and copies the statically-linked binary into it.

Build locally (for testing):

```bash
docker build -t zero-copy-pii-proxy:latest .
```

Run the container:

```bash
docker run -e PROXY_AUTH_FILE=/run/secrets/proxy-auth -e PROXY_PRIVATE_KEY=<32-byte-seed> -p 3000:3000 -p 9090:9090 zero-copy-pii-proxy:latest
```

Notes:
- Ensure CI builds the musl binary in a Linux environment or use a dedicated cross-builder/CI runner that supports musl.


## Troubleshooting

- Build failures when targeting musl: verify that native dependencies support musl or use a glibc-based base image instead. Consider building in CI with a preinstalled `musl-tools` toolchain.

- Docker image is large or fails to run: ensure the binary is statically linked (check `ldd` on the binary in the builder stage), and that the distroless image has required files (certificates are baked into the binary via the system TLS stack; if TLS fails, consider adding CA certs at runtime).

- Metrics not visible in Prometheus: confirm `prometheus.yml` points to `proxy:9090` and query `/metrics` on the internal listener.


## Contact
For operational questions, reach out to the engineering team owning the proxy.
