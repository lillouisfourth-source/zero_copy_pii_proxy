use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use std::{
    convert::Infallible,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll},
};

static PROXY_BYTE_BUDGET_IN_USE: AtomicUsize = AtomicUsize::new(0);
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};

pub const GLOBAL_MEMORY_CHUNK: usize = 64 * 1024;
pub const DEFAULT_GLOBAL_MEMORY_BUDGET: usize = 256 * 1024 * 1024;

#[derive(Clone)]
pub struct ByteBudget {
    semaphore: Arc<Semaphore>,
    global_memory: Arc<Semaphore>,
    capacity: usize,
}

impl ByteBudget {
    pub fn new(capacity: usize) -> Self {
        Self::from_global_shared(
            Arc::new(Semaphore::new(DEFAULT_GLOBAL_MEMORY_BUDGET)),
            capacity,
        )
    }

    pub fn from_global_shared(global_memory: Arc<Semaphore>, capacity: usize) -> Self {
        assert!(capacity > 0, "byte budget must be non-zero");
        Self {
            semaphore: Arc::new(Semaphore::new(capacity)),
            global_memory,
            capacity,
        }
    }

    pub fn from_shared(semaphore: Arc<Semaphore>, capacity: usize) -> Self {
        assert!(capacity > 0, "byte budget must be non-zero");
        Self {
            semaphore,
            global_memory: Arc::new(Semaphore::new(DEFAULT_GLOBAL_MEMORY_BUDGET)),
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
            metrics::increment_counter!("proxy_dropped_streams_capacity");
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
    _global_permit: OwnedSemaphorePermit,
    _local_permit: OwnedSemaphorePermit,
}

fn record_budget_in_use(delta: isize) {
    let current = if delta.is_positive() {
        PROXY_BYTE_BUDGET_IN_USE.fetch_add(delta as usize, Ordering::Relaxed) + delta as usize
    } else {
        PROXY_BYTE_BUDGET_IN_USE.fetch_sub(delta.unsigned_abs(), Ordering::Relaxed)
            - delta.unsigned_abs()
    };
    metrics::gauge!("proxy_byte_budget_in_use", current as f64);
}

impl BudgetedSegment {
    pub async fn reserve(budget: &ByteBudget, bytes: Bytes) -> Option<Self> {
        let global_bytes = bytes
            .len()
            .div_ceil(GLOBAL_MEMORY_CHUNK)
            .checked_mul(GLOBAL_MEMORY_CHUNK)?;
        let global_permit = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            budget
                .global_memory
                .clone()
                .acquire_many_owned(global_bytes.try_into().ok()?),
        )
        .await
        .ok()?
        .ok()?;
        let local_permit = budget.reserve(bytes.len()).await?;
        record_budget_in_use(bytes.len() as isize);
        Some(Self {
            bytes,
            _global_permit: global_permit,
            _local_permit: local_permit,
        })
    }

    pub fn permit_count(&self) -> usize {
        self._local_permit.num_permits()
    }
}

impl Drop for BudgetedSegment {
    fn drop(&mut self) {
        record_budget_in_use(-(self._local_permit.num_permits() as isize));
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
) -> Result<(), EnqueueError> {
    if bytes.is_empty() {
        return Ok(());
    }
    let segment_size = budget.capacity();
    for start in (0..bytes.len()).step_by(segment_size) {
        let end = (start + segment_size).min(bytes.len());
        let segment = BudgetedSegment::reserve(budget, bytes.slice(start..end))
            .await
            .ok_or(EnqueueError::Capacity)?;
        sender.send(segment).await?;
    }
    Ok(())
}

#[derive(Debug)]
pub enum EnqueueError {
    Capacity,
    Closed(mpsc::error::SendError<BudgetedSegment>),
}

impl From<mpsc::error::SendError<BudgetedSegment>> for EnqueueError {
    fn from(error: mpsc::error::SendError<BudgetedSegment>) -> Self {
        Self::Closed(error)
    }
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
