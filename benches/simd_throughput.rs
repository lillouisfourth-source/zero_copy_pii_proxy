use bytes::{Bytes, BytesMut};
use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use std::hint::black_box;
use zero_copy_pii_proxy::engine::{OutputSegment, PiiVault, StreamRedactor};

const PAYLOAD_BYTES: usize = 10_000_000;
const CHUNK_BYTES: usize = 64 * 1024;

fn build_payload() -> Bytes {
    let fragments = [
        b"customer=alice@example.com; ".as_slice(),
        b"password=correct-horse-battery-staple; ".as_slice(),
        b"ssn=123-45-6789; ".as_slice(),
        "region=東京; status=active; ".as_bytes(),
        b"token-abc123; user_42; ".as_slice(),
    ];
    let mut payload = BytesMut::with_capacity(PAYLOAD_BYTES);
    while payload.len() < PAYLOAD_BYTES {
        for fragment in fragments {
            let remaining = PAYLOAD_BYTES - payload.len();
            if fragment.len() > remaining {
                break;
            }
            payload.extend_from_slice(fragment);
        }
    }
    if payload.len() < PAYLOAD_BYTES {
        payload.resize(PAYLOAD_BYTES, b'x');
    }
    payload.freeze()
}

fn build_chunks(payload: &Bytes) -> Vec<Bytes> {
    (0..payload.len())
        .step_by(CHUNK_BYTES)
        .map(|start| payload.slice(start..(start + CHUNK_BYTES).min(payload.len())))
        .collect()
}

fn benchmark_stream_redaction(c: &mut Criterion) {
    let vault = PiiVault::new(
        &[
            "password",
            "email@example.com",
            "ssn-123-45-6789",
            "token-abc123",
            "user_42",
        ],
        &[
            "[REDACTED]",
            "[REDACTED]",
            "[REDACTED]",
            "[REDACTED]",
            "[REDACTED]",
        ],
    );
    let payload = build_payload();
    let chunks = build_chunks(&payload);
    let mut group = c.benchmark_group("simd_throughput");
    group.throughput(Throughput::Bytes(10_000_000));
    group.bench_function("stream_redactor_64k_chunks", |bencher| {
        bencher.iter(|| {
            let mut redactor = StreamRedactor::new(&vault);
            let mut output_bytes = 0usize;
            for chunk in &chunks {
                for segment in redactor.push(chunk.clone()).expect("valid benchmark input") {
                    output_bytes += match segment {
                        OutputSegment::Input(bytes) | OutputSegment::Replacement(bytes) => {
                            bytes.len()
                        }
                    };
                }
            }
            for segment in redactor.finish().expect("valid benchmark input") {
                output_bytes += match segment {
                    OutputSegment::Input(bytes) | OutputSegment::Replacement(bytes) => bytes.len(),
                };
            }
            black_box(output_bytes);
        });
    });
    group.finish();
}

criterion_group!(benches, benchmark_stream_redaction);
criterion_main!(benches);
