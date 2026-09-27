use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UpstreamLimits {
    pub max_active: usize,
    pub max_pending: usize,
    pub max_queue: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateRefusal {
    QueueFull,
    QueueTimeout,
}

pub struct BackendGate {
    permits: Arc<Semaphore>,
    waiting: AtomicUsize,
}

struct Waiting<'a>(&'a AtomicUsize);

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl BackendGate {
    pub fn new(max_active: usize) -> Self {
        BackendGate {
            permits: Arc::new(Semaphore::new(max_active)),
            waiting: AtomicUsize::new(0),
        }
    }

    pub fn waiting(&self) -> usize {
        self.waiting.load(Ordering::SeqCst)
    }

    pub async fn enter(
        &self,
        max_pending: usize,
        max_wait: Duration,
    ) -> Result<(OwnedSemaphorePermit, Duration), GateRefusal> {
        if let Ok(permit) = Arc::clone(&self.permits).try_acquire_owned() {
            return Ok((permit, Duration::ZERO));
        }
        if self.waiting.fetch_add(1, Ordering::SeqCst) >= max_pending {
            self.waiting.fetch_sub(1, Ordering::SeqCst);
            return Err(GateRefusal::QueueFull);
        }
        let _waiting = Waiting(&self.waiting);
        let started = tokio::time::Instant::now();
        match tokio::time::timeout(max_wait, Arc::clone(&self.permits).acquire_owned()).await {
            Ok(Ok(permit)) => Ok((permit, started.elapsed())),
            _ => Err(GateRefusal::QueueTimeout),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_free_slot_is_taken_without_waiting() {
        let gate = BackendGate::new(1);
        let (_permit, waited) = gate.enter(0, Duration::from_secs(1)).await.unwrap();
        assert_eq!(waited, Duration::ZERO);
    }

    #[tokio::test]
    async fn a_full_gate_with_no_queue_refuses_immediately() {
        let gate = BackendGate::new(1);
        let _held = gate.enter(0, Duration::from_secs(1)).await.unwrap();
        assert_eq!(
            gate.enter(0, Duration::from_secs(5)).await.err(),
            Some(GateRefusal::QueueFull)
        );
        assert_eq!(gate.waiting(), 0);
    }

    #[tokio::test]
    async fn a_queued_request_gives_up_after_the_queue_timeout() {
        let gate = BackendGate::new(1);
        let _held = gate.enter(0, Duration::from_secs(1)).await.unwrap();
        assert_eq!(
            gate.enter(1, Duration::from_millis(200)).await.err(),
            Some(GateRefusal::QueueTimeout)
        );
        assert_eq!(gate.waiting(), 0);
    }

    #[tokio::test]
    async fn a_queued_request_proceeds_when_a_slot_frees_and_the_queue_is_bounded() {
        let gate = Arc::new(BackendGate::new(1));
        let held = gate.enter(0, Duration::from_secs(1)).await.unwrap();
        let waiter = {
            let gate = Arc::clone(&gate);
            tokio::spawn(async move { gate.enter(1, Duration::from_secs(10)).await })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(gate.waiting(), 1);
        assert_eq!(
            gate.enter(1, Duration::from_secs(10)).await.err(),
            Some(GateRefusal::QueueFull),
            "the queue is capped at max_pending"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        drop(held);
        let (_permit, waited) = waiter.await.unwrap().unwrap();
        assert!(waited >= Duration::from_millis(100), "{waited:?}");
        assert_eq!(gate.waiting(), 0);
    }
}
