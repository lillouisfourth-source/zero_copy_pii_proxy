# Zero-Copy PII Proxy: Technical Diligence Brief

## Executive Summary

The Zero-Copy PII Proxy is an asynchronous Rust/Axum edge service for authenticated, streaming LLM responses. It combines direct inbound request-body streaming, pooled Reqwest connections, bounded outbound backpressure, UTF-8-safe PII redaction, upstream idle timeouts, downstream disconnect cancellation, Prometheus metrics, Trivy enforcement, SBOM generation, and GitOps packaging.

## Data Path

1. Axum accepts `POST /v1/chat/completions` on port 3000.
2. `AppState` supplies one pooled `reqwest::Client`, the `PiiVault`, credentials, upstream URL, CORS policy, and metrics handle.
3. Authentication compares bearer-token bytes with `subtle::ConstantTimeEq`.
4. `DefaultBodyLimit::max(MAX_BODY_SIZE)` enforces the single 2 MiB inbound limit.
5. `Body::into_data_stream()` is wrapped directly in `reqwest::Body`; the complete inbound request is not materialized with `to_bytes`.
6. The upstream response is consumed as a byte stream.
7. Every upstream read has a 15-second idle timeout.
8. `StreamRedactor` preserves incomplete UTF-8 and split PII prefixes in bounded `BytesMut` state.
9. Results are sent through a 32-chunk bounded Tokio channel using `send().await`.
10. The downstream body consumes the channel through `ReceiverStream`.

## Memory Safety

The inbound path streams request bytes directly to the upstream client and is constrained by a single 2 MiB body limit. The outbound path uses a bounded 32-chunk channel. When a downstream reader is slow, `send().await` blocks before additional upstream reads occur, propagating backpressure instead of accumulating unbounded output in RAM.

The redaction buffer has a default 64 KiB capacity. Oversized valid chunks are processed incrementally; malformed UTF-8 is rejected. A process-wide semaphore caps live upstream streams at 1,000.

## Persistent Pooling

One Reqwest client is built during process startup with:

```rust
pool_idle_timeout(Duration::from_secs(90))
tcp_keepalive(Duration::from_secs(30))
```

The client is shared through `AppState`, reducing repeated TCP/TLS handshakes and enabling connection reuse across requests.

## Security Posture

- Bearer API keys use constant-time byte comparison.
- `ALLOWED_ORIGINS` is an exact comma-separated allowlist.
- Unset origin allowlists reject browser-originated cross-origin requests.
- PII matching uses Aho-Corasick without PII-bearing metric labels.
- Trivy SARIF fails CI on HIGH or CRITICAL findings.
- CycloneDX SBOM output is uploaded as a build artifact.
- Runtime packaging uses a static non-root distroless image.
- Kubernetes credentials are injected through Secret references.

## Resilience Controls

- 120-second upstream request-establishment timeout.
- 15-second per-read idle timeout.
- Downstream receiver failure immediately drops the upstream stream.
- 1,000-permit upstream semaphore.
- 32-chunk bounded outbound queue.
- UTF-8 fragment preservation.
- Split-PII overlap preservation.

## Observability

Prometheus metrics are served at `/metrics` on port 3000:

- `proxy_requests_total`
- `active_sse_streams`
- `pii_redactions_total`

The Compose stack provisions Prometheus and Grafana automatically. Grafana loads the `Zero-Copy PII Proxy` dashboard with panels for request rate, active SSE streams, and PII redaction rate.

## CI and Supply Chain

CI runs formatting, Clippy with warnings denied, the complete Rust workspace tests, a Docker build, a Docker-networked k6 load test, a strict Trivy scan, CycloneDX SBOM generation, and artifact upload. The k6 test targets the proxy by Docker service name rather than `localhost`.

## GitOps Packaging

The Helm chart at `charts/zero-copy-pii-proxy` parameterizes:

- Image repository and tag.
- Replica count.
- Service type and port.
- Resource requests and limits.
- Probe timing.
- `UPSTREAM_API_URL`.
- `ALLOWED_ORIGINS`.
- `PROXY_API_KEY`.

The chart renders Deployment, Service, ConfigMap, and Secret resources.

## Verified Evidence

The project has passed:

- Rust formatting, Clippy, unit, integration, and fragmentation tests.
- UTF-8 and split-PII tests.
- 150 KiB payload byte-integrity tests.
- 15-second upstream idle-timeout tests.
- Downstream disconnect cancellation tests.
- 5,000-VU concurrency tests with a 1,000-upstream-stream cap.
- Docker build and strict Trivy CI.

## Remaining Production Decisions

The production operator should provide real image registries, secret management, TLS ingress, HPA/PDB policies, NetworkPolicies, byte-budgeted queueing if chunk sizes are untrusted, request correlation IDs, and explicit metrics for timeout, disconnect, semaphore wait, and backpressure events.
