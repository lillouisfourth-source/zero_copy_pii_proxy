#![no_main]

use libfuzzer_sys::fuzz_target;
use bytes::Bytes;
use ed25519_dalek::SigningKey;
use zero_copy_pii_proxy::{DoneDetector, StreamEvent};
use zero_copy_pii_proxy::engine::{PiiVault, StreamRedactor};

fuzz_target!(|data: &[u8]| {
    let vault = PiiVault::new(
        &["password", "secret", "data: [DONE]"],
        &["[REDACTED]", "[REDACTED]", "[REDACTED]"],
    );
    let mut redactor = StreamRedactor::with_max_capacity(&vault, 64 * 1024);
    let key = SigningKey::from_bytes(&[3u8; 32]);

    for byte in data {
        if let Ok(outputs) = redactor.push(Bytes::copy_from_slice(std::slice::from_ref(byte))) {
            for output in outputs {
                let bytes = match output {
                    zero_copy_pii_proxy::engine::OutputSegment::Input(bytes)
                    | zero_copy_pii_proxy::engine::OutputSegment::Replacement(bytes) => bytes,
                };
                assert!(!bytes.is_empty());
            }
        }
    }
    if let Ok(outputs) = redactor.finish() {
        for output in outputs {
            let bytes = match output {
                zero_copy_pii_proxy::engine::OutputSegment::Input(bytes)
                | zero_copy_pii_proxy::engine::OutputSegment::Replacement(bytes) => bytes,
            };
            assert!(!bytes.is_empty());
        }
    }
    let mut marker_detector = DoneDetector::default();
    let mut marker_hasher = blake3::Hasher::new();
    let mut marker_events = marker_detector.inspect(
        Bytes::copy_from_slice(data),
        &key,
        &mut marker_hasher,
    );
    marker_events.extend(marker_detector.inspect(
        Bytes::from_static(zero_copy_pii_proxy::SSE_DONE_MARKER),
        &key,
        &mut marker_hasher,
    ));
    marker_events.extend(marker_detector.finish(&mut marker_hasher));

    let audits = marker_events.iter().filter(|event| matches!(event, StreamEvent::AuditReceipt(_))).count();
    let dones = marker_events.iter().filter(|event| matches!(event, StreamEvent::DoneMarker(_))).count();
    assert!(audits <= 1);
    assert!(dones <= 1);
    if dones == 1 {
        assert_eq!(audits, 1);
        let audit_index = marker_events.iter().position(|event| matches!(event, StreamEvent::AuditReceipt(_))).unwrap();
        let done_index = marker_events.iter().position(|event| matches!(event, StreamEvent::DoneMarker(_))).unwrap();
        assert!(audit_index < done_index);
    }
});
