use bytes::Bytes;
use http_body::Body;
use proptest::prelude::*;
use tokio::time::{timeout, Duration};
use zero_copy_pii_proxy::budget_queue::{
    byte_budget_in_use, channel, BudgetedBody, BudgetedSegment, ByteBudget,
};
use zero_copy_pii_proxy::engine::{OutputSegment, PiiVault, StreamRedactor};

fn utf8_noise_strategy() -> impl Strategy<Value = String> {
    prop::collection::vec(
        prop_oneof![
            Just('a'),
            Just('é'),
            Just('ß'),
            Just('中'),
            Just('🚀'),
            Just('🙂'),
            Just('Ω'),
            Just('ß'),
            Just('µ'),
            Just('1'),
            Just(' '),
        ],
        0..24,
    )
    .prop_map(|chars| chars.into_iter().collect())
}

fn pii_fragment_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("password".to_string()),
        Just("secret".to_string()),
        Just("email@example.com".to_string()),
        Just("ssn-123-45-6789".to_string()),
        Just("token-abc123".to_string()),
        Just("user_42".to_string()),
    ]
}

fn stream_equivalence_input_strategy() -> impl Strategy<Value = String> {
    prop::collection::vec(
        prop_oneof![
            pii_fragment_strategy(),
            utf8_noise_strategy(),
            Just("-".to_string()),
            Just("::".to_string()),
            Just("\n".to_string()),
        ],
        1..48,
    )
    .prop_map(|parts| parts.concat())
}

proptest! {
    #[test]
    fn proof_stream_fragmentation_equivalence(input in stream_equivalence_input_strategy()) {
        let vault = PiiVault::new(
            &["password", "secret", "email@example.com", "ssn-123-45-6789", "token-abc123", "user_42"],
            &["[REDACTED]", "[REDACTED]", "[REDACTED]", "[REDACTED]", "[REDACTED]", "[REDACTED]"],
        );

        let unfragmented = {
            let mut redactor = StreamRedactor::new(&vault);
            let mut output = redactor.push(Bytes::copy_from_slice(input.as_bytes())).unwrap();
            output.extend(redactor.finish().unwrap());
            output
                .into_iter()
                .flat_map(|segment| match segment {
                    OutputSegment::Input(bytes) | OutputSegment::Replacement(bytes) => bytes.to_vec(),
                })
                .collect::<Vec<_>>()
        };

        let chunk_sizes = (1..=7usize)
            .cycle()
            .take(input.len().max(1))
            .collect::<Vec<_>>();

        let mut fragmented = Vec::new();
        let mut cursor = 0usize;
        let mut redactor = StreamRedactor::new(&vault);
        for size in chunk_sizes {
            if cursor >= input.len() {
                break;
            }
            let end = (cursor + size).min(input.len());
            let chunk = &input.as_bytes()[cursor..end];
            fragmented.extend(redactor.push(Bytes::copy_from_slice(chunk)).unwrap());
            cursor = end;
        }
        fragmented.extend(redactor.finish().unwrap());

        let fragmented_bytes = fragmented
            .into_iter()
            .flat_map(|segment| match segment {
                OutputSegment::Input(bytes) | OutputSegment::Replacement(bytes) => bytes.to_vec(),
            })
            .collect::<Vec<_>>();

        prop_assert_eq!(fragmented_bytes, unfragmented);
    }
}

#[tokio::test]
async fn idle_completion_releases_all_application_byte_budget() {
    let budget = ByteBudget::new(1024);
    let (sender, receiver) = channel(1);
    let segment = BudgetedSegment::reserve(&budget, Bytes::from_static(b"complete stream"))
        .await
        .expect("segment reservation");
    sender.send(segment).await.expect("queue segment");
    drop(sender);

    let mut body = BudgetedBody::new(receiver);
    let first = futures::future::poll_fn(|cx| std::pin::Pin::new(&mut body).poll_frame(cx))
        .await
        .expect("stream frame")
        .expect("successful stream frame");
    assert_eq!(
        first.into_data().expect("data frame"),
        Bytes::from_static(b"complete stream")
    );
    let end = futures::future::poll_fn(|cx| std::pin::Pin::new(&mut body).poll_frame(cx)).await;
    assert!(end.is_none());
    drop(body);
    assert_eq!(byte_budget_in_use(), 0);
}

#[tokio::test]
async fn downstream_receiver_closure_is_observable_without_delay() {
    let (sender, receiver) = channel(1);
    drop(receiver);
    timeout(Duration::from_millis(100), sender.closed())
        .await
        .expect("receiver closure should be immediate");
}
