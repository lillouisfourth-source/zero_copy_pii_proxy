Zero-Copy PII Proxy — Architectural Whitepaper
===============================================

Overview
--------
This document describes the architecture, memory model, streaming design, and security posture of the zero-copy PII proxy. The proxy provides an enterprise-grade gateway that performs real-time, "zero-copy" redaction of PII from streaming responses (Server-Sent Events / OpenAI-style chunked responses) while preserving throughput, low latency, and operational traceability.

Zero-copy memory model and buffer flow
--------------------------------------
- Rust ownership and borrowing: the proxy is implemented in Rust and minimizes copies by operating on byte buffers and streaming interfaces (axum + hyper + bytes). Wherever possible the code uses borrowed slices and passes ownership only when necessary (e.g., when a chunk must be transformed).
- Chunk handling: upstream SSE/chunked responses are consumed as byte streams. Each chunk is processed with a tight hotspot that:
  1. Converts the chunk bytes to a temporary UTF-8-aware string for detection/replacement (using lossless to_string/UTF-8-safe APIs where necessary).
  2. Applies fast Aho-Corasick literal-based replacements (precompiled automaton) for known PII tokens.
  3. Applies precompiled Regex-based detectors for email, US phone numbers, and SSNs.
  4. Emits the transformed chunk downstream as Bytes; the overall pipeline avoids copying large buffers more than once and avoids re-allocations in the common no-match path.
- Safe UTF-8 boundaries: the proxy uses a boundary-holding technique where the tail of each chunk (up to max pattern length - 1) is held back to avoid slicing UTF-8 multibyte characters or splitting PII across chunk boundaries.

SSE streaming architecture
--------------------------
- The proxy forwards an SSE stream by spawning a background task that forwards bytes from the upstream response to downstream clients using an unbounded channel. The streamed chunks are redacted in the background task, not on the main request thread, preserving the request path and enabling non-blocking behavior.
- Active stream accounting: a lightweight guard increments/decrements an `active_sse_streams` gauge for telemetry.
- Backpressure: the proxy recognizes downstream disconnects and stops forwarding upstream to avoid wasted work.

Performance expectations
-----------------------
- The implementation uses:
  - Aho-Corasick for large numbers of literal replacements (O(n + m) behavior where n is input length and m is number of matches).
  - Precompiled Regexes (using once_cell::sync::Lazy) for common PII patterns (emails, phones, SSNs). Regexes are compiled once and reused to avoid per-request JIT/compile overhead.
  - Tokio + hyper + reqwest streaming model, tuned for high concurrency.
- Empirical baseline (local, released build, musl static): expect low single-digit millisecond median latency under moderate load and sub-100ms P99 for small responses. The exact achievable RPS depends on instance CPU and network; the included `examples/benchmark.js` uses autocannon to measure P50/P99 and RPS.

Security posture and compliance
------------------------------
- Minimal runtime surface: the final runtime is built into a musl static binary and packaged in Chainguard's `cgr.dev/chainguard/static:latest` minimal runtime image to reduce CVE surface.
- Trivy scanning: CI runs Trivy and uploads SARIF to GitHub Code Scanning. The latest green run produced zero CRITICAL/HIGH findings for the built image, providing a clean baseline.
- Telemetry: redaction events are counted with non-sensitive metrics (no PII in labels), and the code logs that a redaction occurred without exposing the redacted content.

Multi-provider routing and enterprise features
---------------------------------------------
- The proxy supports a configurable `UPSTREAM_BASE_URL`, enabling routing to OpenAI, Groq, Anthropic, or internal model endpoints.
- Authentication: the proxy enforces a proxy-level API key (PROXY_API_KEY) for inbound clients and can be extended to set upstream credentials per provider.
- Observability: `/metrics` endpoint (Prometheus), `/health` endpoint, and structured logs are included.

M&A readiness checklist
----------------------
- Reproducible builds: Cargo.lock committed; musl static builds inside CI create reproducible binaries.
- Security scanning: Trivy SARIF uploaded to GitHub Code Scanning (attach SARIF to data room for auditors).
- SBOM & provenance: recommended next steps include SBOM generation and image signing via cosign for further M&A evidence.

Contact
-------
For technical follow-ups, debugging artifacts, or to run additional scans/benchmarks, request access or provide a temporary runner for me to execute focused checks.
