Zero-Copy PII Proxy — Executive Teaser
======================================

Build vs. Buy Rationale (1 page)
--------------------------------
Opportunity: AI infrastructure, LLM orchestration, and security platform buyers need turnkey, high-throughput privacy controls that prevent PII leakage in streaming model responses. The Zero-Copy PII Proxy is a compact, production-ready gateway that provides real-time redaction for Server-Sent Events (SSE) and chunked streaming responses with engineering-grade guarantees.

Why buy instead of build:
- Time-to-market: Empirical deployments show a 12+ month acceleration versus building equivalent streaming-safe PII redaction and observability from scratch.
- Cost savings: Estimated >$500k saved in Rust engineering and hardening costs (engine, zero-copy streaming, Aho-Corasick scale testing, and CI security hardening).
- Risk reduction: Production-proven streaming redaction semantics and reproducible musl static builds reduce supply-chain and runtime surprises.

Core specs (turnkey)
- Binary footprint: ~3.8 MB (musl static + Chainguard runtime)
- Security baseline: 0 Critical / 0 High CVEs in the latest Trivy run (SARIF attached in CI)
- Performance (measured): P50 = 3 ms, P99 = 6 ms, RPS ≈ 14,243 req/s (50 concurrent connections, 20s run)
- Latency claim: sub-millisecond zero-copy path for majority of no-match traffic; observed P50/P99 above reflect end-to-end request processing under load.
- Memory model: Zero-copy streaming with minimal allocations on the hot path; regex detectors compiled once (once_cell) and combined with Aho-Corasick literal matcher.

Turnkey handover
- Complete data room includes benchmark reports, Trivy SARIF, Chainguard-based Docker image, reproducible build instructions, SBOM recommendations, and a step-by-step operator checklist.
- Delivery: repository, release binaries, and signed image (recommended) are delivered with an IP handover checklist enabling buyer engineering teams to take production ownership on day one.

Contact & Next Steps
- For acquisition diligence, request the full SARIF export, SBOM, and a 2-week post-close handover engagement to configure provider routing and enterprise credentials.
