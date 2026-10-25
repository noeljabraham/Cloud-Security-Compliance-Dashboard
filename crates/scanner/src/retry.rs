use crate::{cancellation::CancellationToken, error::ScannerError};
use std::{future::Future, time::Duration};

pub struct RetryPolicy {
    pub max_retries: u32,
    pub base_delay_ms: u64,
    pub max_delay_ms: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_delay_ms: 100,
            max_delay_ms: 2000,
        }
    }
}

pub async fn retry_with_jitter<F, Fut, T>(
    policy: &RetryPolicy,
    cancellation_token: Option<&CancellationToken>,
    mut operation: F,
) -> Result<T, ScannerError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, ScannerError>>,
{
    let mut attempt = 0;

    loop {
        if let Some(token) = cancellation_token {
            if token.is_cancelled() {
                return Err(ScannerError::Cancelled);
            }
        }

        match operation().await {
            Ok(val) => return Ok(val),
            Err(err) => {
                if !err.is_retryable() || attempt >= policy.max_retries {
                    return Err(err);
                }

                attempt += 1;

                let delay_ms = match &err {
                    ScannerError::Throttling {
                        retry_after_ms: Some(ms),
                        ..
                    } => *ms,
                    _ => {
                        let exp = 2u64.saturating_pow(attempt.min(6));
                        let calc_delay = policy.base_delay_ms.saturating_mul(exp);
                        calc_delay.min(policy.max_delay_ms)
                    }
                };

                // Add deterministic jitter (half delay + mod variation) to avoid sync spikes
                let jitter_ms =
                    (delay_ms / 2).saturating_add((attempt as u64 * 37) % (delay_ms / 2 + 1));
                let total_delay = Duration::from_millis(jitter_ms);

                if let Some(token) = cancellation_token {
                    tokio::select! {
                        _ = tokio::time::sleep(total_delay) => {},
                        _ = token.cancelled() => return Err(ScannerError::Cancelled),
                    }
                } else {
                    tokio::time::sleep(total_delay).await;
                }
            }
        }
    }
}
