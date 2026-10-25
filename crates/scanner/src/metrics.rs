use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct ScannerMetrics {
    pub scans_started: AtomicU64,
    pub scans_succeeded: AtomicU64,
    pub scans_partial: AtomicU64,
    pub scans_failed: AtomicU64,
    pub scans_cancelled: AtomicU64,
    pub resources_discovered: AtomicU64,
    pub findings_created: AtomicU64,
    pub findings_resolved: AtomicU64,
    pub coverage_gaps_recorded: AtomicU64,
    pub retries_attempted: AtomicU64,
}

#[derive(Debug, Clone, Serialize)]
pub struct MetricsSnapshot {
    pub scans_started: u64,
    pub scans_succeeded: u64,
    pub scans_partial: u64,
    pub scans_failed: u64,
    pub scans_cancelled: u64,
    pub resources_discovered: u64,
    pub findings_created: u64,
    pub findings_resolved: u64,
    pub coverage_gaps_recorded: u64,
    pub retries_attempted: u64,
}

impl ScannerMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            scans_started: self.scans_started.load(Ordering::Relaxed),
            scans_succeeded: self.scans_succeeded.load(Ordering::Relaxed),
            scans_partial: self.scans_partial.load(Ordering::Relaxed),
            scans_failed: self.scans_failed.load(Ordering::Relaxed),
            scans_cancelled: self.scans_cancelled.load(Ordering::Relaxed),
            resources_discovered: self.resources_discovered.load(Ordering::Relaxed),
            findings_created: self.findings_created.load(Ordering::Relaxed),
            findings_resolved: self.findings_resolved.load(Ordering::Relaxed),
            coverage_gaps_recorded: self.coverage_gaps_recorded.load(Ordering::Relaxed),
            retries_attempted: self.retries_attempted.load(Ordering::Relaxed),
        }
    }
}
