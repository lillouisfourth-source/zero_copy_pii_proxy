use bytes::Bytes;
use http_body::Body;
use tokio::time::{timeout, Duration};
use zero_copy_pii_proxy::budget_queue::{
    byte_budget_in_use, channel, BudgetedBody, BudgetedSegment, ByteBudget,
};

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
