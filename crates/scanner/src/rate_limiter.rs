use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{Mutex, Semaphore};

#[derive(Clone)]
pub struct ProviderRateLimiter {
    semaphore: Arc<Semaphore>,
    min_interval: Duration,
    last_request: Arc<Mutex<Instant>>,
}

impl ProviderRateLimiter {
    pub fn new(max_concurrent: usize, requests_per_second: u32) -> Self {
        let min_interval = if requests_per_second > 0 {
            Duration::from_millis((1000 / requests_per_second).max(1) as u64)
        } else {
            Duration::from_millis(50)
        };

        Self {
            semaphore: Arc::new(Semaphore::new(max_concurrent.max(1))),
            min_interval,
            last_request: Arc::new(Mutex::new(
                Instant::now()
                    .checked_sub(Duration::from_secs(10))
                    .unwrap_or_else(Instant::now),
            )),
        }
    }

    pub async fn acquire(&self) -> tokio::sync::SemaphorePermit<'_> {
        let permit = self
            .semaphore
            .acquire()
            .await
            .expect("rate limiter semaphore closed");

        let mut last = self.last_request.lock().await;
        let elapsed = last.elapsed();
        if elapsed < self.min_interval {
            tokio::time::sleep(self.min_interval - elapsed).await;
        }
        *last = Instant::now();

        permit
    }
}
