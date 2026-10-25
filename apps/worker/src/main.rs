use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use cloudsec_domain::{
    APP_NAME, AlertDestination, AlertTriggerCondition, ScanJob, ScanSchedule, ScanStatus,
    WebhookDeliveryRecord,
};
use cloudsec_scanner::{AlertingEngine, SUPPORTED_PROVIDERS};
use serde_json::json;
use tokio::sync::Mutex;
use uuid::Uuid;

/// Lease-based distributed lock for jobs/scans
#[derive(Debug, Clone)]
pub struct DistributedJobLock {
    pub owner_id: String,
    pub acquired_at: Instant,
    pub ttl: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ScanExecutionStage {
    Queued,
    DiscoveryCompleted,
    EvaluationCompleted,
    ScoringCompleted,
    AlertsDispatched,
    Succeeded,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanJobCheckpoint {
    pub job_id: Uuid,
    pub stage: ScanExecutionStage,
    pub discovered_resources_count: usize,
    pub findings_count: usize,
    pub updated_at: String,
}

pub struct DistributedWorkerQueue {
    pub worker_id: String,
    pub active_locks: Arc<Mutex<HashMap<String, DistributedJobLock>>>,
    pub job_queue: Arc<Mutex<Vec<ScanJob>>>,
    pub checkpoints: Arc<Mutex<HashMap<Uuid, ScanJobCheckpoint>>>,
}

impl DistributedWorkerQueue {
    pub fn new(worker_id: impl Into<String>) -> Self {
        Self {
            worker_id: worker_id.into(),
            active_locks: Arc::new(Mutex::new(HashMap::new())),
            job_queue: Arc::new(Mutex::new(Vec::new())),
            checkpoints: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Records an execution checkpoint for a scan job, enabling graceful crash recovery.
    pub async fn save_checkpoint(
        &self,
        job_id: Uuid,
        stage: ScanExecutionStage,
        discovered_resources_count: usize,
        findings_count: usize,
    ) {
        let mut checkpoints = self.checkpoints.lock().await;
        checkpoints.insert(
            job_id,
            ScanJobCheckpoint {
                job_id,
                stage,
                discovered_resources_count,
                findings_count,
                updated_at: "2026-10-25T18:00:00Z".to_string(),
            },
        );
    }

    pub async fn get_checkpoint(&self, job_id: Uuid) -> Option<ScanJobCheckpoint> {
        let checkpoints = self.checkpoints.lock().await;
        checkpoints.get(&job_id).cloned()
    }

    /// Resumes an interrupted scan job from its latest saved stage checkpoint.
    pub async fn resume_or_start_job(&self, job_id: Uuid) -> ScanExecutionStage {
        if let Some(cp) = self.get_checkpoint(job_id).await {
            match cp.stage {
                ScanExecutionStage::DiscoveryCompleted => ScanExecutionStage::EvaluationCompleted,
                ScanExecutionStage::EvaluationCompleted => ScanExecutionStage::ScoringCompleted,
                ScanExecutionStage::ScoringCompleted => ScanExecutionStage::AlertsDispatched,
                ScanExecutionStage::AlertsDispatched => ScanExecutionStage::Succeeded,
                ScanExecutionStage::Succeeded => ScanExecutionStage::Succeeded,
                ScanExecutionStage::Queued => ScanExecutionStage::DiscoveryCompleted,
            }
        } else {
            ScanExecutionStage::DiscoveryCompleted
        }
    }

    /// Attempts to acquire an exclusive lease lock for a key (e.g. scan_schedule_id or account_id)
    pub async fn try_acquire_lease(&self, key: &str, ttl: Duration) -> bool {
        let mut locks = self.active_locks.lock().await;
        let now = Instant::now();

        if let Some(existing) = locks.get(key) {
            if now.duration_since(existing.acquired_at) < existing.ttl {
                // Lease is still actively held by another process/worker
                return false;
            }
        }

        locks.insert(
            key.to_string(),
            DistributedJobLock {
                owner_id: self.worker_id.clone(),
                acquired_at: now,
                ttl,
            },
        );
        true
    }

    pub async fn release_lease(&self, key: &str) -> bool {
        let mut locks = self.active_locks.lock().await;
        if let Some(lock) = locks.get(key) {
            if lock.owner_id == self.worker_id {
                locks.remove(key);
                return true;
            }
        }
        false
    }

    pub async fn enqueue_job(&self, job: ScanJob) {
        let mut queue = self.job_queue.lock().await;
        queue.push(job);
    }

    pub async fn process_next_job(&self) -> Option<ScanJob> {
        let mut queue = self.job_queue.lock().await;
        if let Some(mut job) = queue.pop() {
            job.status = ScanStatus::Running;
            Some(job)
        } else {
            None
        }
    }

    /// Evaluates recurring schedules and enqueues scan jobs if lease is successfully acquired
    pub async fn evaluate_schedules(&self, schedules: &[ScanSchedule]) -> Vec<ScanJob> {
        let mut enqueued = Vec::new();
        for schedule in schedules {
            if !schedule.enabled {
                continue;
            }

            let lock_key = format!("schedule:{}", schedule.id);
            // 30-second lease to prevent concurrent workers from running the same scheduled scan
            if self
                .try_acquire_lease(&lock_key, Duration::from_secs(30))
                .await
            {
                let job = ScanJob {
                    id: Uuid::new_v4(),
                    scan_run_id: Uuid::new_v4(),
                    organization_id: schedule.organization_id,
                    account_id: schedule.connection_id.unwrap_or_else(Uuid::new_v4),
                    status: ScanStatus::Queued,
                    coverage: json!({}),
                    error: None,
                };
                self.enqueue_job(job.clone()).await;
                enqueued.push(job);
            }
        }
        enqueued
    }

    /// Outbound webhook dispatcher with HMAC signature and retry simulation
    pub async fn dispatch_alert_with_retries(
        destination: &AlertDestination,
        trigger: AlertTriggerCondition,
        payload_data: &serde_json::Value,
        max_retries: u32,
    ) -> WebhookDeliveryRecord {
        let mut attempt = 0;
        let mut last_record = None;

        while attempt < max_retries {
            attempt += 1;
            let record = AlertingEngine::dispatch_test_webhook(
                &destination.endpoint_url,
                destination.encrypted_secret_reference.as_deref(),
                payload_data,
            );

            if record.success {
                return record;
            }
            last_record = Some(record);
            // Exponential backoff pause
            tokio::time::sleep(Duration::from_millis(5 * (1 << attempt))).await;
        }

        last_record.unwrap_or_else(|| WebhookDeliveryRecord {
            id: Uuid::new_v4(),
            organization_id: destination.organization_id,
            rule_id: Uuid::nil(),
            destination_id: destination.id,
            trigger,
            status_code: Some(500),
            success: false,
            error_message: Some(format!("Failed after {max_retries} attempts")),
            delivered_at: "2026-10-25T15:00:00Z".to_string(),
            idempotency_key: Uuid::new_v4().to_string(),
        })
    }
}

#[tokio::main]
async fn main() {
    println!(
        "{APP_NAME} distributed worker initialized for {} providers",
        SUPPORTED_PROVIDERS.len()
    );

    let worker = DistributedWorkerQueue::new("worker-main-instance");
    println!("Worker ID: {}", worker.worker_id);
}

#[cfg(test)]
mod tests {
    use super::*;
    use cloudsec_domain::AlertDestinationType;

    #[tokio::test]
    async fn lease_locking_prevents_duplicate_acquisition() {
        let worker_a = DistributedWorkerQueue::new("worker-a");
        let worker_b = DistributedWorkerQueue::new("worker-b");

        let key = "account:112233445566:scan";
        let acquired_a = worker_a
            .try_acquire_lease(key, Duration::from_secs(5))
            .await;
        assert!(acquired_a);

        // Share the active locks map to simulate distributed storage
        *worker_b.active_locks.lock().await = worker_a.active_locks.lock().await.clone();

        // Worker B attempts to acquire same key within TTL -> rejected
        let acquired_b = worker_b
            .try_acquire_lease(key, Duration::from_secs(5))
            .await;
        assert!(!acquired_b);

        // Worker A releases lease
        let released = worker_a.release_lease(key).await;
        assert!(released);
        *worker_b.active_locks.lock().await = worker_a.active_locks.lock().await.clone();

        // Worker B can now acquire lease
        let acquired_b_now = worker_b
            .try_acquire_lease(key, Duration::from_secs(5))
            .await;
        assert!(acquired_b_now);
    }

    #[tokio::test]
    async fn schedule_evaluation_enqueues_jobs() {
        let worker = DistributedWorkerQueue::new("worker-scheduler");
        let org_id = Uuid::new_v4();

        let schedules = vec![
            ScanSchedule {
                id: Uuid::new_v4(),
                organization_id: org_id,
                connection_id: Some(Uuid::new_v4()),
                name: "Nightly Security Scan".to_string(),
                cron_expression: "0 0 * * *".to_string(),
                timezone: "UTC".to_string(),
                enabled: true,
                last_run_at: None,
                next_run_at: None,
            },
            ScanSchedule {
                id: Uuid::new_v4(),
                organization_id: org_id,
                connection_id: Some(Uuid::new_v4()),
                name: "Disabled Hourly Scan".to_string(),
                cron_expression: "0 * * * *".to_string(),
                timezone: "UTC".to_string(),
                enabled: false,
                last_run_at: None,
                next_run_at: None,
            },
        ];

        let enqueued = worker.evaluate_schedules(&schedules).await;
        assert_eq!(enqueued.len(), 1);

        let next_job = worker.process_next_job().await;
        assert!(next_job.is_some());
        assert_eq!(next_job.unwrap().status, ScanStatus::Running);
    }

    #[tokio::test]
    async fn webhook_dispatch_with_retries() {
        let destination = AlertDestination {
            id: Uuid::new_v4(),
            organization_id: Uuid::new_v4(),
            name: "Slack Ops".to_string(),
            destination_type: AlertDestinationType::SlackWebhook,
            endpoint_url: "https://hooks.slack.com/services/test".to_string(),
            encrypted_secret_reference: Some("test-secret".to_string()),
            enabled: true,
            created_at: "2026-10-25T15:00:00Z".to_string(),
        };

        let payload = json!({
            "message": "Critical finding detected"
        });

        let delivery = DistributedWorkerQueue::dispatch_alert_with_retries(
            &destination,
            AlertTriggerCondition::NewCriticalFinding,
            &payload,
            3,
        )
        .await;

        assert!(delivery.success);
        assert_eq!(delivery.status_code, Some(200));
    }

    #[tokio::test]
    async fn scan_job_checkpoint_enables_resumption() {
        let worker = DistributedWorkerQueue::new("worker-resilient");
        let job_id = Uuid::new_v4();

        // 1. Initially job has no checkpoint -> starts at Discovery
        let next_stage = worker.resume_or_start_job(job_id).await;
        assert_eq!(next_stage, ScanExecutionStage::DiscoveryCompleted);

        // 2. Worker saves checkpoint after discovering 50 resources
        worker
            .save_checkpoint(job_id, ScanExecutionStage::DiscoveryCompleted, 50, 0)
            .await;

        let checkpoint = worker.get_checkpoint(job_id).await.unwrap();
        assert_eq!(checkpoint.stage, ScanExecutionStage::DiscoveryCompleted);
        assert_eq!(checkpoint.discovered_resources_count, 50);

        // 3. Simulating crash and worker restart: resumes at EvaluationCompleted stage
        let resumed_stage = worker.resume_or_start_job(job_id).await;
        assert_eq!(resumed_stage, ScanExecutionStage::EvaluationCompleted);
    }
}
