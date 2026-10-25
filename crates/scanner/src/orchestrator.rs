use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

use cloudsec_domain::{
    CloudAccount, CloudProvider, CoverageGap, CoverageGapReason, Finding, FindingStatus, Id,
    Resource, ScanJob, ScanRun, ScanStatus, ScoreSnapshot, calculate_compliance_score,
};
use serde_json::json;
use tokio::sync::Semaphore;
use uuid::Uuid;

use crate::{
    cancellation::CancellationToken,
    check::CheckEvaluation,
    error::ScannerError,
    metrics::ScannerMetrics,
    rate_limiter::ProviderRateLimiter,
    registry::ProviderRegistry,
    retry::{RetryPolicy, retry_with_jitter},
    telemetry::StructuredLog,
};

pub struct ScanTarget {
    pub organization_id: Id,
    pub accounts: Vec<CloudAccount>,
    pub regions_by_account: HashMap<Id, Vec<String>>,
    pub services_by_provider: HashMap<CloudProvider, Vec<String>>,
}

pub struct ScanOptions {
    pub max_concurrent_accounts: usize,
    pub max_concurrent_regions: usize,
    pub timeout_per_region: Duration,
    pub retry_policy: RetryPolicy,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            max_concurrent_accounts: 4,
            max_concurrent_regions: 2,
            timeout_per_region: Duration::from_secs(30),
            retry_policy: RetryPolicy::default(),
        }
    }
}

pub struct ScanExecutionResult {
    pub scan_run: ScanRun,
    pub scan_jobs: Vec<ScanJob>,
    pub resources: Vec<Resource>,
    pub findings: Vec<Finding>,
    pub resolved_finding_ids: Vec<Id>,
    pub coverage_gaps: Vec<CoverageGap>,
    pub score_snapshot: ScoreSnapshot,
}

struct AccountScanParams {
    scan_run_id: Id,
    organization_id: Id,
    account: CloudAccount,
    regions: Vec<String>,
    services: Vec<String>,
    max_concurrent_regions: usize,
    timeout_per_region: Duration,
    retry_policy: RetryPolicy,
    rate_limiter: ProviderRateLimiter,
    registry: Arc<ProviderRegistry>,
    metrics: Arc<ScannerMetrics>,
    cancel_token: Option<CancellationToken>,
}

pub struct ScanOrchestrator {
    registry: Arc<ProviderRegistry>,
    metrics: Arc<ScannerMetrics>,
    rate_limiters: HashMap<CloudProvider, ProviderRateLimiter>,
    scanner_version: String,
}

impl ScanOrchestrator {
    pub fn new(registry: Arc<ProviderRegistry>, metrics: Arc<ScannerMetrics>) -> Self {
        let mut rate_limiters = HashMap::new();
        rate_limiters.insert(CloudProvider::Aws, ProviderRateLimiter::new(4, 20));
        rate_limiters.insert(CloudProvider::Azure, ProviderRateLimiter::new(4, 20));
        rate_limiters.insert(CloudProvider::Gcp, ProviderRateLimiter::new(4, 20));

        Self {
            registry,
            metrics,
            rate_limiters,
            scanner_version: "0.1.0".to_string(),
        }
    }

    pub async fn run_scan(
        &self,
        target: ScanTarget,
        existing_open_findings: &[Finding],
        options: ScanOptions,
        cancellation_token: Option<CancellationToken>,
    ) -> ScanExecutionResult {
        let scan_run_id = Uuid::new_v4();
        let trace_id = scan_run_id.to_string();

        self.metrics
            .scans_started
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let log = StructuredLog::new(
            "INFO",
            &trace_id,
            "starting scan run",
            json!({
                "organization_id": target.organization_id,
                "accounts_count": target.accounts.len(),
            }),
        );
        println!("{}", log.to_json_string());

        let account_semaphore = Arc::new(Semaphore::new(options.max_concurrent_accounts.max(1)));
        let mut job_tasks = Vec::new();

        for account in target.accounts {
            let permit = account_semaphore.clone().acquire_owned().await.unwrap();
            let regions = target
                .regions_by_account
                .get(&account.id)
                .cloned()
                .unwrap_or_else(|| vec!["us-east-1".to_string()]);
            let services = target
                .services_by_provider
                .get(&account.provider)
                .cloned()
                .unwrap_or_else(|| vec!["s3".to_string(), "iam".to_string()]);

            let registry = self.registry.clone();
            let metrics = self.metrics.clone();
            let rate_limiter = self
                .rate_limiters
                .get(&account.provider)
                .cloned()
                .unwrap_or_else(|| ProviderRateLimiter::new(2, 10));
            let retry_policy = RetryPolicy {
                max_retries: options.retry_policy.max_retries,
                base_delay_ms: options.retry_policy.base_delay_ms,
                max_delay_ms: options.retry_policy.max_delay_ms,
            };
            let timeout_per_region = options.timeout_per_region;
            let max_concurrent_regions = options.max_concurrent_regions;
            let cancel_token = cancellation_token.clone();
            let org_id = target.organization_id;

            let params = AccountScanParams {
                scan_run_id,
                organization_id: org_id,
                account,
                regions,
                services,
                max_concurrent_regions,
                timeout_per_region,
                retry_policy,
                rate_limiter,
                registry,
                metrics,
                cancel_token,
            };

            let task = tokio::spawn(async move {
                let _permit = permit;
                Self::run_account_scan(params).await
            });

            job_tasks.push(task);
        }

        let mut all_jobs = Vec::new();
        let mut all_resources = Vec::new();
        let mut all_findings = Vec::new();
        let mut all_coverage_gaps = Vec::new();
        let mut covered_checks: HashSet<(String, Id)> = HashSet::new(); // (check_id, resource_id)
        let mut total_evaluations: usize = 0;
        let mut passed_evaluations: usize = 0;

        for task in job_tasks {
            match task.await {
                Ok(job_result) => {
                    all_jobs.push(job_result.job);
                    all_resources.extend(job_result.resources);
                    all_findings.extend(job_result.findings);
                    all_coverage_gaps.extend(job_result.coverage_gaps);
                    covered_checks.extend(job_result.covered_evaluations);
                    total_evaluations += job_result.total_evals;
                    passed_evaluations += job_result.passed_evals;
                }
                Err(join_err) => {
                    let log = StructuredLog::new(
                        "ERROR",
                        &trace_id,
                        "account scan task panicked or failed to join",
                        json!({"error": join_err.to_string()}),
                    );
                    eprintln!("{}", log.to_json_string());
                }
            }
        }

        // Deduplicate resources by deterministic ID
        let mut dedup_resources: Vec<Resource> = Vec::new();
        let mut seen_resource_ids = HashSet::new();
        for r in all_resources {
            if seen_resource_ids.insert(r.id) {
                dedup_resources.push(r);
            }
        }

        // Deduplicate findings by fingerprint
        let mut dedup_findings: Vec<Finding> = Vec::new();
        let mut seen_fingerprints = HashSet::new();
        for f in all_findings {
            if seen_fingerprints.insert(f.fingerprint.clone()) {
                dedup_findings.push(f);
            }
        }

        // Finding resolution logic:
        // A previously open finding is resolved IF AND ONLY IF:
        // 1. The check and resource were cleanly covered in this scan (covered_checks contains (check_id, resource_id)), AND
        // 2. No new open finding with the same check_id and resource_id was generated in this scan.
        let mut resolved_finding_ids = Vec::new();
        let open_finding_keys: HashSet<(String, Id)> = dedup_findings
            .iter()
            .map(|f| (f.check_id.clone(), f.resource_id))
            .collect();

        let is_cancelled = cancellation_token
            .as_ref()
            .map(|t| t.is_cancelled())
            .unwrap_or(false);

        if !is_cancelled {
            for existing in existing_open_findings {
                if existing.status == FindingStatus::Open {
                    let key = (existing.check_id.clone(), existing.resource_id);
                    if covered_checks.contains(&key) && !open_finding_keys.contains(&key) {
                        resolved_finding_ids.push(existing.id);
                        self.metrics
                            .findings_resolved
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            }
        }

        // Overall scan run status determination
        let scan_status = if is_cancelled {
            self.metrics
                .scans_cancelled
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            ScanStatus::Cancelled
        } else if !all_coverage_gaps.is_empty()
            || all_jobs.iter().any(|j| j.status == ScanStatus::Partial)
        {
            self.metrics
                .scans_partial
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            ScanStatus::Partial
        } else if all_jobs.iter().all(|j| j.status == ScanStatus::Failed) && !all_jobs.is_empty() {
            self.metrics
                .scans_failed
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            ScanStatus::Failed
        } else {
            self.metrics
                .scans_succeeded
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            ScanStatus::Succeeded
        };

        self.metrics.resources_discovered.fetch_add(
            dedup_resources.len() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        self.metrics.findings_created.fetch_add(
            dedup_findings.len() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        self.metrics.coverage_gaps_recorded.fetch_add(
            all_coverage_gaps.len() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );

        let score = calculate_compliance_score(total_evaluations, passed_evaluations);

        let scan_run = ScanRun {
            id: scan_run_id,
            organization_id: target.organization_id,
            status: scan_status,
            scanner_version: self.scanner_version.clone(),
            coverage: json!({
                "coverage_gaps_count": all_coverage_gaps.len(),
                "total_evaluations": total_evaluations,
                "passed_evaluations": passed_evaluations,
                "score": score,
            }),
            error: if !all_coverage_gaps.is_empty() {
                Some(format!(
                    "Scan completed with {} coverage gaps",
                    all_coverage_gaps.len()
                ))
            } else {
                None
            },
        };

        let score_snapshot = ScoreSnapshot {
            id: Uuid::new_v4(),
            organization_id: target.organization_id,
            scan_run_id: Some(scan_run_id),
            provider: None,
            account_id: None,
            score,
        };

        let log = StructuredLog::new(
            "INFO",
            &trace_id,
            "scan run completed",
            json!({
                "scan_run_id": scan_run_id,
                "status": scan_status,
                "findings_count": dedup_findings.len(),
                "resolved_count": resolved_finding_ids.len(),
                "coverage_gaps_count": all_coverage_gaps.len(),
                "score": score,
            }),
        );
        println!("{}", log.to_json_string());

        ScanExecutionResult {
            scan_run,
            scan_jobs: all_jobs,
            resources: dedup_resources,
            findings: dedup_findings,
            resolved_finding_ids,
            coverage_gaps: all_coverage_gaps,
            score_snapshot,
        }
    }

    async fn run_account_scan(params: AccountScanParams) -> AccountJobExecutionResult {
        let AccountScanParams {
            scan_run_id,
            organization_id,
            account,
            regions,
            services,
            max_concurrent_regions,
            timeout_per_region,
            retry_policy,
            rate_limiter,
            registry,
            metrics,
            cancel_token,
        } = params;
        let job_id = Uuid::new_v4();
        let provider_client = match registry.get_provider(account.provider) {
            Some(client) => client,
            None => {
                return AccountJobExecutionResult {
                    job: ScanJob {
                        id: job_id,
                        scan_run_id,
                        organization_id,
                        account_id: account.id,
                        status: ScanStatus::Failed,
                        coverage: json!({"error": "No provider client registered"}),
                        error: Some(format!(
                            "Provider {} not registered",
                            account.provider.as_str()
                        )),
                    },
                    resources: Vec::new(),
                    findings: Vec::new(),
                    coverage_gaps: vec![CoverageGap {
                        account_id: account.id,
                        provider: account.provider,
                        region: None,
                        service: "all".to_string(),
                        check_id: None,
                        reason: CoverageGapReason::UnsupportedService,
                        details: "Provider not configured in registry".to_string(),
                    }],
                    covered_evaluations: HashSet::new(),
                    total_evals: 0,
                    passed_evals: 0,
                };
            }
        };

        let region_semaphore = Arc::new(Semaphore::new(max_concurrent_regions.max(1)));
        let mut region_tasks = Vec::new();

        for region in regions {
            let permit = region_semaphore.clone().acquire_owned().await.unwrap();
            let client = provider_client.clone();
            let services = services.clone();
            let rate_limiter = rate_limiter.clone();
            let retry_policy = RetryPolicy {
                max_retries: retry_policy.max_retries,
                base_delay_ms: retry_policy.base_delay_ms,
                max_delay_ms: retry_policy.max_delay_ms,
            };
            let metrics = metrics.clone();
            let cancel_token = cancel_token.clone();
            let account_id = account.id;

            let task = tokio::spawn(async move {
                let _permit = permit;
                let _rate_permit = rate_limiter.acquire().await;

                if let Some(ref token) = cancel_token {
                    if token.is_cancelled() {
                        return Err((region.clone(), ScannerError::Cancelled));
                    }
                }

                let discovery_ctx = crate::provider::DiscoveryContext {
                    organization_id,
                    account_id,
                    region: region.clone(),
                    services: services.clone(),
                    page_size: Some(100),
                    page_token: None,
                };

                let discover_op = || {
                    let ctx = &discovery_ctx;
                    client.discover_resources(ctx)
                };

                let result = tokio::time::timeout(
                    timeout_per_region,
                    retry_with_jitter(&retry_policy, cancel_token.as_ref(), discover_op),
                )
                .await;

                match result {
                    Ok(Ok(discovered)) => Ok((region, discovered)),
                    Ok(Err(err)) => {
                        metrics
                            .retries_attempted
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        Err((region, err))
                    }
                    Err(_) => Err((
                        region.clone(),
                        ScannerError::Timeout(format!("Timeout after {timeout_per_region:?}")),
                    )),
                }
            });

            region_tasks.push(task);
        }

        let mut job_resources = Vec::new();
        let mut job_coverage_gaps = Vec::new();
        let mut failed_regions_count = 0;

        for task in region_tasks {
            match task.await {
                Ok(Ok((_region, discovered_list))) => {
                    for disc in discovered_list {
                        let res = disc.into_resource(organization_id, account.id);
                        job_resources.push(res);
                    }
                }
                Ok(Err((region, scanner_error))) => {
                    failed_regions_count += 1;
                    let gap_reason = scanner_error
                        .to_coverage_gap_reason()
                        .unwrap_or(CoverageGapReason::InternalError);

                    job_coverage_gaps.push(CoverageGap {
                        account_id: account.id,
                        provider: account.provider,
                        region: Some(region),
                        service: "discovery".to_string(),
                        check_id: None,
                        reason: gap_reason,
                        details: scanner_error.to_string(),
                    });
                }
                Err(join_err) => {
                    failed_regions_count += 1;
                    job_coverage_gaps.push(CoverageGap {
                        account_id: account.id,
                        provider: account.provider,
                        region: None,
                        service: "discovery".to_string(),
                        check_id: None,
                        reason: CoverageGapReason::InternalError,
                        details: format!("Region discovery task failed: {join_err}"),
                    });
                }
            }
        }

        // Now evaluate checks against discovered resources
        let checks = registry.get_checks_for_provider(account.provider);
        let mut job_findings = Vec::new();
        let mut covered_evaluations: HashSet<(String, Id)> = HashSet::new();
        let mut total_evals = 0;
        let mut passed_evals = 0;

        for resource in &job_resources {
            for check in &checks {
                let eval = check.evaluate(resource);
                match eval {
                    CheckEvaluation::Passed => {
                        total_evals += 1;
                        passed_evals += 1;
                        covered_evaluations.insert((check.id().to_string(), resource.id));
                    }
                    CheckEvaluation::Failed {
                        severity, evidence, ..
                    } => {
                        total_evals += 1;
                        covered_evaluations.insert((check.id().to_string(), resource.id));
                        let fingerprint = Finding::fingerprint(
                            check.id(),
                            &resource.provider_native_id,
                            &evidence,
                        );

                        job_findings.push(Finding {
                            id: Uuid::new_v4(),
                            organization_id,
                            check_id: check.id().to_string(),
                            resource_id: resource.id,
                            severity,
                            status: FindingStatus::Open,
                            evidence,
                            fingerprint,
                        });
                    }
                    CheckEvaluation::CoverageGap { reason, details } => {
                        job_coverage_gaps.push(CoverageGap {
                            account_id: account.id,
                            provider: account.provider,
                            region: resource.region.clone(),
                            service: check.service().to_string(),
                            check_id: Some(check.id().to_string()),
                            reason,
                            details,
                        });
                    }
                    CheckEvaluation::NotApplicable => {}
                }
            }
        }

        let job_status = if !job_coverage_gaps.is_empty() {
            ScanStatus::Partial
        } else if failed_regions_count > 0 && job_resources.is_empty() {
            ScanStatus::Failed
        } else if failed_regions_count > 0 {
            ScanStatus::Partial
        } else {
            ScanStatus::Succeeded
        };

        AccountJobExecutionResult {
            job: ScanJob {
                id: job_id,
                scan_run_id,
                organization_id,
                account_id: account.id,
                status: job_status,
                coverage: json!({
                    "resources_count": job_resources.len(),
                    "findings_count": job_findings.len(),
                    "coverage_gaps_count": job_coverage_gaps.len(),
                    "total_evaluations": total_evals,
                    "passed_evaluations": passed_evals,
                }),
                error: if !job_coverage_gaps.is_empty() {
                    Some(format!("Job had {} coverage gaps", job_coverage_gaps.len()))
                } else {
                    None
                },
            },
            resources: job_resources,
            findings: job_findings,
            coverage_gaps: job_coverage_gaps,
            covered_evaluations,
            total_evals,
            passed_evals,
        }
    }
}

struct AccountJobExecutionResult {
    job: ScanJob,
    resources: Vec<Resource>,
    findings: Vec<Finding>,
    coverage_gaps: Vec<CoverageGap>,
    covered_evaluations: HashSet<(String, Id)>,
    total_evals: usize,
    passed_evals: usize,
}
