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
    let mut detector = DoneDetector::default();
    let key = SigningKey::from_bytes(&[3u8; 32]);
    let mut hasher = blake3::Hasher::new();

    for byte in data {
        if let Ok(outputs) = redactor.push(Bytes::copy_from_slice(std::slice::from_ref(byte))) {
            for output in outputs {
                let bytes = match output {
                    zero_copy_pii_proxy::engine::OutputSegment::Input(bytes)
                    | zero_copy_pii_proxy::engine::OutputSegment::Replacement(bytes) => bytes,
                };
                for event in detector.inspect(bytes, &key, &mut hasher) {
                    match event {
                        StreamEvent::Data(bytes)
                        | StreamEvent::AuditReceipt(bytes)
                        | StreamEvent::DoneMarker(bytes) => assert!(!bytes.is_empty()),
                    }
                }
            }
        }
    }
    let _ = redactor.finish();
    let _ = detector.finish(&mut hasher);
});
