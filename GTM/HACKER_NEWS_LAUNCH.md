Show HN: Zero-Copy PII Proxy — Enterprise-grade GenAI data protection (Rust, zero-copy, Chainguard)

TL;DR

We built a drop-in, OpenAI-compatible reverse proxy that strips and redacts PII from requests and streaming responses at the VPC boundary. It's written in Rust for performance, uses zero-copy streaming masking with aho-corasick and SIMD-friendly patterns, and ships in a Chainguard static runtime for a hardened zero-CVE image.

Why this matters

- Companies are deploying LLMs quickly but lack consistent controls to prevent regulated data from leaving the VPC.
- A single prompt or streaming response can leak customer or employee PII, causing compliance and legal risk.
- Our proxy enforces privacy at the network edge while preserving the exact OpenAI-compatible API surface, so apps need only change the baseURL.

What is it

- A lightweight HTTP reverse proxy that proxies OpenAI-compatible endpoints (including streaming SSE paths) and performs content-aware, streaming-safe redaction.
- Implemented in Rust with zero-copy buffers so masking happens with minimal allocations and about ~1.2ms median processing overhead in common chat workloads.
- PII detection uses aho-corasick with precompiled patterns and a streaming-aware state machine so it works on chunked SSE and long-lived connections.
- Built with a multi-stage Dockerfile producing a statically-linked binary and running it in a Chainguard static image to minimize runtime OS CVEs.

Key technical highlights

- Language: Rust (async/tokio + axum)
- Zero-copy streaming: slice-based buffers and in-place redaction where possible to avoid copies
- Pattern engine: aho-corasick with optimized pattern sets for names, SSNs, phone numbers, email, API keys
- SIMD-friendly data paths: small hot loops structured to auto-vectorize on modern CPUs
- Observability: Prometheus metrics + Grafana dashboards included, plus k6 streaming benchmarks
- CI/Release: GitHub Actions building, GHCR publishing, and SARIF uploads to GitHub Security for enterprise review

How to try it (dev)

1) Run locally using Docker Compose (provided):

   docker compose up -d --build

2) Point your OpenAI SDK to the proxy by changing only the baseURL:

   // examples/openai_demo.js shows the exact snippet

Why this is interesting to hackers and infra folks

- The zero-copy approach for SSE masking is an uncommon but powerful pattern for streaming LLM traffic.
- The project shows a realistic production path: musl static build, hardened runtime image, CI, and SARIF-based security visibility.
- Performance-oriented Rust masking + real-world deployability (GHCR + Fly/edge-friendly image) means this is easy to evaluate at scale.

Links

- Repo: https://github.com/lillouisfourth-source/zero_copy_pii_proxy
- Demo: examples/openai_demo.js

If you want benchmarks, config notes, or a short video walkthrough, drop a comment and I'll post details and perf numbers.
