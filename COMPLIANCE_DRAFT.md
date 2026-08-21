# Enterprise Compliance and Architecture Draft

## Scope

This document summarizes the security and reliability controls implemented in the zero-copy PII proxy. It is an architectural draft for enterprise review and should be read together with the source, tests, deployment manifests, and CI records.

## Zero-Copy `Bytes::slice()` Redaction

The streaming redaction engine receives owned `bytes::Bytes` frames and emits ordered output segments. Non-PII ranges are represented with `Bytes::slice()`, preserving the original allocation through reference counting instead of copying passing data. Redactions use one shared immutable `[REDACTED]` byte allocation. Only bounded cross-frame state, such as an incomplete UTF-8 sequence or a possible split-pattern suffix, is retained and copied.

Every segment owns its data and therefore satisfies asynchronous `'static` stream ownership requirements. UTF-8 boundaries are validated before emission, and split-PII state is held until the engine can prove that a prefix is safe to release. The existing unit and fragmentation tests exercise arbitrary UTF-8 and PII boundaries.

## Byte-Budget Semaphore Queue

The downstream queue combines a bounded Tokio channel with an exact byte semaphore. A segment acquires permits equal to its output byte length before enqueueing. The permit is stored with the segment and remains held while queued and while the most recently delivered body frame is in flight. It is released when the next frame is polled or when cancellation/drop destroys the segment or body.

Segments larger than the configured budget are divided into `Bytes::slice()` views before reservation, so a malicious individual frame cannot wait forever or exceed the memory bound. The invariant is:

`queued bytes + in-flight bytes <= configured byte budget`

Receiver cancellation, producer cancellation, and body drop all release owned permits through normal Rust ownership and drop semantics. This bounds response buffering by bytes rather than by an approximate chunk count and prevents queue-driven memory exhaustion.

## BLAKE3 Tracing Receipts

The producer creates a `blake3::Hasher` and updates it incrementally with every post-redaction output segment immediately before queueing. The raw pre-redaction stream is not hashed by default. No complete response is retained solely for receipt generation.

A receipt is finalized and logged only after the upstream stream reaches graceful EOF and the final redaction flush succeeds. Timeout, transport failure, downstream cancellation, or another early termination does not produce a successful-completion receipt. The producer future is instrumented with the request's current tracing span, preserving `x-request-id` correlation for audit events:

`Redaction stream completed successfully` with `redaction_receipt=<BLAKE3 digest>`

Receipts are emitted to tracing rather than Prometheus labels, avoiding unbounded metric cardinality.

## Immutable Toolchain and CI Pinning

GitHub Actions in the CI workflow are pinned to the exact 40-character commit SHA resolved from their release tags. Original release tags are retained as comments for reviewability. The Rust CI action selects the explicit tested Rust version rather than a floating stable channel.

Docker and service images are pinned by registry manifest digest using `name:tag@sha256:<digest>` where tags are retained for human readability. This includes the Rust builder and distroless runtime images, the CI Node and k6 test images, and the Compose Prometheus and Grafana services. Runner operating-system labels remain normal GitHub-hosted labels because they are workflow scheduling labels, not mutable action references.

These controls prevent tag movement or upstream replacement from silently changing the build inputs. Combined with lockfiles, vulnerability scanning, SBOM generation, reproducible build inputs, and the tested workflow, they provide a verifiable supply-chain baseline for enterprise audit.

## Verification Status

The local workspace passed formatting, warning-denied linting, workspace tests, and `cargo check`. Remote CI verification is tracked by the GitHub Actions workflow for the pushed commit. This draft is intentionally high-level; exact digests, commit SHAs, test results, and source-level evidence remain available in repository history and CI artifacts.
