IP Handover Checklist — Zero-Copy PII Proxy
=============================================

Purpose
-------
This checklist provides buyer engineers a step-by-step guide to take repo ownership, rebuild release binaries, add patterns, and deploy edge instances on day one.

Prerequisites
-------------
- Access to the repo and CI artifacts (SARIF, SBOM, release binaries)
- Linux or Windows machine with Rust toolchain installed for local builds (rustup + cargo)
- Docker for image builds (optional if using Chainguard static runtime)

Day-1 operator steps
--------------------
1. Clone the repo and check out master:
   git clone https://github.com/<org>/zero_copy_pii_proxy.git
   cd zero_copy_pii_proxy

2. Build a release binary (Linux musl static):
   rustup target add x86_64-unknown-linux-musl
   export RUSTFLAGS="-C target-feature=+crt-static"
   cargo build --release --target x86_64-unknown-linux-musl
   # Output binary: target/x86_64-unknown-linux-musl/release/zero_copy_pii_proxy

3. Build container image (optional):
   docker build -t zero-copy-pii-proxy:latest .

4. Run locally for smoke test (Linux example):
   ./target/release/zero_copy_pii_proxy &
   # or inside the image: docker run --rm -p 3000:3000 zero-copy-pii-proxy:latest

5. Add custom regex PII patterns to PiiVault:
   - File: src/engine.rs
   - Edit to add or refine regexes near the precompiled detectors (EMAIL_RE, PHONE_RE, SSN_RE). Use once_cell::sync::Lazy or add additional compiled Regexes.
   - For literal patterns, update the Aho-Corasick list used by PiiVault (the automaton is constructed from the configured literal patterns).
   - Rebuild after changes: cargo build --release

6. Configuration and environment variables:
   - PROXY_API_KEY: set to enforce ingress access
   - UPSTREAM_BASE_URL: provider or mock upstream
   - METRICS_PORT / PROMETHEUS options: adjust as needed

7. Deploying to edge (example):
   - Build and push signed image to registry (cosign sign recommended)
   - Deploy to edge provider using container image runtime or run the static binary on the host

8. Observability and monitoring:
   - Metrics: /metrics endpoint exposed
   - Health: /health
   - Logs: use structured logging and do not log PII content

9. Post-handover validation
   - Run the benchmark: npm install autocannon --no-save && node examples/benchmark.js and compare P50/P99/RPS to the data room report
   - Run Trivy scan on the newly built image and compare SARIF to previous run

Contacts
--------
- For technical questions during handover, contact the original engineering lead and request a 2-week support window post-close to migrate provider credentials and finalize production settings.
