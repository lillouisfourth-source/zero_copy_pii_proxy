use bytes::Bytes;
use zero_copy_pii_proxy::engine::{OutputSegment, PiiVault, StreamRedactionError, StreamRedactor};

fn segment_bytes(segment: OutputSegment) -> Vec<u8> {
    match segment {
        OutputSegment::Input(bytes) | OutputSegment::Replacement(bytes) => bytes.to_vec(),
    }
}

#[test]
fn fragmented_utf8_and_pii_are_reconstructed_without_dropped_bytes() {
    let vault = PiiVault::new(&["test@example.com"], &["[REDACTED]"]);
    let mut redactor = StreamRedactor::with_max_capacity(&vault, 1024);
    let input =
        "data: {\"choices\":[{\"delta\":{\"content\":\"Hello 🚀, email: test@example.com\"}}]}\n\n";
    let expected =
        "data: {\"choices\":[{\"delta\":{\"content\":\"Hello 🚀, email: [REDACTED]\"}}]}\n\n";
    let mut output = Vec::new();

    for byte in input.as_bytes() {
        let chunks = redactor
            .push(Bytes::copy_from_slice(std::slice::from_ref(byte)))
            .unwrap();
        output.extend(chunks.into_iter().flat_map(segment_bytes));
    }
    output.extend(
        redactor
            .finish()
            .unwrap()
            .into_iter()
            .flat_map(segment_bytes),
    );

    let output_text = String::from_utf8(output.clone()).expect("output must remain valid UTF-8");
    assert_eq!(output_text, expected);
    assert_eq!(output, expected.as_bytes());
    assert!(!output_text.contains("test@example.com"));
}

#[test]
fn fragmented_buffer_has_a_hard_capacity_limit() {
    let vault = PiiVault::new(&["sensitive"], &["[REDACTED]"]);
    let mut redactor = StreamRedactor::with_max_capacity(&vault, 8);

    let error = redactor.push(Bytes::from_static(b"123456789")).unwrap_err();

    assert_eq!(error, StreamRedactionError::BufferLimitExceeded);
}
