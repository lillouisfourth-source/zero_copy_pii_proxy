Security & Compliance Report — Zero-Copy PII Proxy
===================================================

Runtime & build chain
---------------------
- Build target: x86_64-unknown-linux-musl (static linking) using `cargo build --release --target x86_64-unknown-linux-musl` with RUSTFLAGS="-C target-feature=+crt-static".
- Runtime image: Chainguard static minimal runtime (cgr.dev/chainguard/static:latest) for minimal attack surface and reproducible runtime behavior.

Vulnerability scanning
----------------------
- Scanner: Trivy (CI-run via aquasecurity/trivy-action@v0.35.0)
- Trivy binary version used in CI: v0.69.3 (note: newer versions exist; recommend upgrading scanner periodically)
- Scan type: image (OS + language libraries), output: SARIF (trivy-results.sarif), uploaded to GitHub Code Scanning.
- CI outcome (latest run): 0 Critical / 0 High vulnerabilities reported in the SARIF for the configured severity filter (CRITICAL,HIGH). The SARIF file is attached to the CI run and uploaded to Code Scanning.

Memory safety and language benefits
----------------------------------
- Implementation language: Rust (2021 edition). Rust's ownership and borrow-checker provide strong compile-time memory safety guarantees, preventing common classes of memory errors (use-after-free, double-free, many buffer overrun scenarios).
- The hot-path redaction logic is implemented with careful ownership to avoid copies where possible; precompiled regexes (once_cell) and an Aho-Corasick automaton protect runtime performance while keeping the code auditable.

Recommended compliance artifacts for buyers
------------------------------------------
- Provide Trivy SARIF (already uploaded to Code Scanning)
- Generate and include SBOM (CycloneDX or SPDX) for binaries and container images
- Sign released images with cosign and include provenance metadata (recommended next step)
- Periodic re-scan of images and dependencies using an automated workflow (weekly/after-dependency changes)

Operational notes
-----------------
- No sensitive data is logged; redaction events are emitted as counters only (pii_redactions_total) and logs indicate redaction without exposing redacted content.
- For extra assurance, run stage-level fuzzing and dynamic tests against the redaction logic on live streaming inputs.
