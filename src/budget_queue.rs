use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use std::{
    convert::Infallible,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};

#[derive(Clone)]
pub struct ByteBudget {
    semaphore: Arc<Semaphore>,
    capacity: usize,
}

impl ByteBudget {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "byte budget must be non-zero");
        Self {
            semaphore: Arc::new(Semaphore::new(capacity)),
            capacity,
        }
    }

    pub fn from_shared(semaphore: Arc<Semaphore>, capacity: usize) -> Self {
        assert!(capacity > 0, "byte budget must be non-zero");
        Self {
            semaphore,
            capacity,
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn available(&self) -> usize {
        self.semaphore.available_permits()
    }

    pub async fn reserve(&self, bytes: usize) -> Option<OwnedSemaphorePermit> {
        if bytes == 0 || bytes > self.capacity || bytes > u32::MAX as usize {
            return None;
        }
        self.semaphore
            .clone()
            .acquire_many_owned(bytes as u32)
            .await
            .ok()
    }
}

pub struct BudgetedSegment {
    pub bytes: Bytes,
    permit: OwnedSemaphorePermit,
}

impl BudgetedSegment {
    pub async fn reserve(budget: &ByteBudget, bytes: Bytes) -> Option<Self> {
        let permit = budget.reserve(bytes.len()).await?;
        Some(Self { bytes, permit })
    }

    pub fn permit_count(&self) -> usize {
        self.permit.num_permits()
    }
}

pub type SegmentSender = mpsc::Sender<BudgetedSegment>;
pub type SegmentReceiver = mpsc::Receiver<BudgetedSegment>;

pub fn channel(items: usize) -> (SegmentSender, SegmentReceiver) {
    assert!(items > 0, "queue item capacity must be non-zero");
    mpsc::channel(items)
}

pub async fn enqueue(
    sender: &SegmentSender,
    budget: &ByteBudget,
    bytes: Bytes,
) -> Result<(), mpsc::error::SendError<BudgetedSegment>> {
    if bytes.is_empty() {
        return Ok(());
    }
    let segment_size = budget.capacity();
    for start in (0..bytes.len()).step_by(segment_size) {
        let end = (start + segment_size).min(bytes.len());
        let segment = BudgetedSegment::reserve(budget, bytes.slice(start..end))
            .await
            .expect("segment is split to fit the byte budget");
        sender.send(segment).await?;
    }
    Ok(())
}

pub struct BudgetedBody {
    receiver: SegmentReceiver,
    in_flight: Option<BudgetedSegment>,
    ended: bool,
}

impl BudgetedBody {
    pub fn new(receiver: SegmentReceiver) -> Self {
        Self {
            receiver,
            in_flight: None,
            ended: false,
        }
    }
}

impl Body for BudgetedBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.ended {
            return Poll::Ready(None);
        }
        self.in_flight = None;
        match self.receiver.poll_recv(cx) {
            Poll::Ready(Some(segment)) => {
                let bytes = segment.bytes.clone();
                self.in_flight = Some(segment);
                Poll::Ready(Some(Ok(Frame::data(bytes))))
            }
            Poll::Ready(None) => {
                self.ended = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.ended
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{timeout, Duration};

    #[tokio::test]
    async fn oversized_segment_is_sliced_to_fit_without_deadlock() {
        let budget = ByteBudget::new(4);
        let (sender, mut receiver) = channel(4);
        let source = Bytes::from_static(b"abcdefghij");
        let enqueue_task = tokio::spawn({
            let sender = sender.clone();
            let budget = budget.clone();
            async move { enqueue(&sender, &budget, source).await }
        });
        drop(sender);

        let mut output = Vec::new();
        while let Some(segment) = receiver.recv().await {
            assert!(segment.permit_count() <= budget.capacity());
            output.extend_from_slice(&segment.bytes);
        }
        timeout(Duration::from_millis(100), enqueue_task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(output, b"abcdefghij");
        assert_eq!(budget.available(), budget.capacity());
    }

    #[tokio::test]
    async fn dropped_receiver_releases_unsent_permit() {
        let budget = ByteBudget::new(8);
        let (sender, receiver) = channel(1);
        let segment = BudgetedSegment::reserve(&budget, Bytes::from_static(b"1234"))
            .await
            .unwrap();
        drop(receiver);
        assert!(sender.send(segment).await.is_err());
        assert_eq!(budget.available(), 8);
    }

    #[tokio::test]
    async fn dropped_body_releases_in_flight_permit() {
        let budget = ByteBudget::new(8);
        let (sender, receiver) = channel(1);
        let segment = BudgetedSegment::reserve(&budget, Bytes::from_static(b"1234"))
            .await
            .unwrap();
        sender.send(segment).await.unwrap();
        let mut body = BudgetedBody::new(receiver);
        futures::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(budget.available(), 4);
        drop(body);
        assert_eq!(budget.available(), 8);
    }

    #[tokio::test]
    async fn oversized_reservation_returns_without_waiting() {
        let budget = ByteBudget::new(4);
        assert!(timeout(Duration::from_millis(100), budget.reserve(5))
            .await
            .unwrap()
            .is_none());
    }
}
