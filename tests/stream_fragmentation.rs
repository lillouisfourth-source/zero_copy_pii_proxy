use zero_copy_pii_proxy::engine::{PiiVault, StreamRedactionError, StreamRedactor};

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
        let chunks = redactor.push(std::slice::from_ref(byte)).unwrap();
        output.extend(chunks.into_iter().flat_map(|chunk| chunk.to_vec()));
    }
    output.extend(
        redactor
            .finish()
            .unwrap()
            .into_iter()
            .flat_map(|chunk| chunk.to_vec()),
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

    let error = redactor.push(b"123456789").unwrap_err();

    assert_eq!(error, StreamRedactionError::BufferLimitExceeded);
}
