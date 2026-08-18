Zero-Copy PII Proxy — Benchmark Report
======================================

Test configuration
------------------
- Target: http://localhost:3000/v1/chat/completions
- Script: examples/benchmark.js (autocannon wrapper)
- Concurrency (connections): 50
- Duration: 20 seconds
- Request payload: minimal JSON request body (stream:false) to exercise request/response hot path

Measured results (single run)
----------------------------
- Total requests completed: 284,867
- Average RPS: 14,243.60 req/s
- Latency P50: 3 ms
- Latency P99: 6 ms
- Errors: 0

Interpretation
--------------
- The measured P50 = 3ms and P99 = 6ms demonstrate that the proxy imposes minimal overhead under high parallel load. The zero-copy design, combined with precompiled regex detectors and Aho-Corasick literal matching, keeps per-request allocations low and avoids repeated regex compilation.
- RPS of ~14.2k req/s at 50 concurrent connections indicates the proxy can support high-throughput model orchestration and edge routing use cases on modest host resources. For absolute capacity planning, run scaled benchmarks on target instance types and network topologies.

Reproducibility
---------------
- Run the benchmark locally: npm install autocannon --no-save && node examples/benchmark.js
- For CI-grade benchmarking, run the script inside a dedicated runner with pinned CPU and network (e.g., 4 vCPU, 8 GB RAM) and record multiple runs to get an average and variance.
