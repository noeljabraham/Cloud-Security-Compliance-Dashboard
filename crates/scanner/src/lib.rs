#![forbid(unsafe_code)]

pub mod alerting;
pub mod aws;
pub mod azure;
pub mod cancellation;
pub mod check;
pub mod compliance;
pub mod cost;
pub mod crypto;
pub mod drift;
pub mod error;
pub mod fake;
pub mod gcp;
pub mod metrics;
pub mod onboarding;
pub mod orchestrator;
pub mod provider;
pub mod rate_limiter;
pub mod registry;
pub mod remediation;
pub mod retry;
pub mod telemetry;

pub const SUPPORTED_PROVIDERS: [&str; 3] = ["aws", "azure", "gcp"];

pub use alerting::AlertingEngine;
pub use aws::{get_all_aws_checks, register_all_aws_checks};
pub use azure::{get_all_azure_checks, register_all_azure_checks};
pub use cancellation::CancellationToken;
pub use check::{AwsS3BlockPublicAccessCheck, Check, CheckEvaluation};
pub use compliance::{
    AssessmentProfile, CheckEvaluationRecord, ComplianceScoringEngine, ComprehensiveScoreReport,
    ControlCoverageReport, ControlCoverageStatus, ControlCoverageSummary, DetailedFrameworkMapping,
    EvaluationOutcome, MappingType, SCORING_FORMULA_VERSION, ScoreBreakdown,
};
pub use cost::{CloudBillingRecord, CostSecurityEngine};
pub use crypto::{EncryptionService, EnvSecretsProvider, SecretsProvider, StaticSecretsProvider};
pub use drift::DriftEngine;
pub use error::ScannerError;
pub use fake::FakeCloudProvider;
pub use gcp::{get_all_gcp_checks, register_all_gcp_checks};
pub use metrics::{MetricsSnapshot, ScannerMetrics};
pub use onboarding::{CloudOnboardingValidator, OnboardingValidationResult};
pub use orchestrator::{ScanExecutionResult, ScanOptions, ScanOrchestrator, ScanTarget};
pub use provider::{
    CloudProviderClient, DiscoveryContext, ProviderCapabilities, ValidationContext,
    ValidationReport,
};
pub use registry::ProviderRegistry;
pub use remediation::{RemediationTemplateEngine, sanitize_input};
pub use retry::{RetryPolicy, retry_with_jitter};
pub use telemetry::{StructuredLog, redact_sensitive_value};

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Arc, time::Duration};

    use cloudsec_domain::{
        CloudAccount, CloudProvider, DiscoveredResource, Finding, FindingStatus, Resource,
        ScanStatus, Severity,
    };
    use serde_json::json;
    use uuid::Uuid;

    use crate::{
        cancellation::CancellationToken,
        check::{AwsS3BlockPublicAccessCheck, Check, CheckEvaluation},
        error::ScannerError,
        fake::FakeCloudProvider,
        metrics::ScannerMetrics,
        orchestrator::{ScanOptions, ScanOrchestrator, ScanTarget},
        registry::ProviderRegistry,
        retry::{RetryPolicy, retry_with_jitter},
        telemetry::{StructuredLog, redact_sensitive_value},
    };

    #[tokio::test]
    async fn aws_s3_block_public_access_check_evaluates_correctly() {
        let check = AwsS3BlockPublicAccessCheck;
        let org_id = Uuid::new_v4();
        let account_id = Uuid::new_v4();

        // 1. Compliant resource: all 4 settings true
        let compliant_res = Resource {
            id: Resource::deterministic_id(org_id, account_id, "bucket-secure"),
            organization_id: org_id,
            account_id,
            provider_native_id: "bucket-secure".to_string(),
            resource_type: "aws_s3_bucket".to_string(),
            name: Some("bucket-secure".to_string()),
            tags: json!({}),
            region: Some("us-east-1".to_string()),
            configuration: json!({
                "block_public_acls": true,
                "ignore_public_acls": true,
                "block_public_policy": true,
                "restrict_public_buckets": true,
            }),
        };

        assert_eq!(check.evaluate(&compliant_res), CheckEvaluation::Passed);

        // 2. Non-compliant resource: missing ignore_public_acls
        let insecure_res = Resource {
            id: Resource::deterministic_id(org_id, account_id, "bucket-open"),
            organization_id: org_id,
            account_id,
            provider_native_id: "bucket-open".to_string(),
            resource_type: "aws_s3_bucket".to_string(),
            name: Some("bucket-open".to_string()),
            tags: json!({}),
            region: Some("us-east-1".to_string()),
            configuration: json!({
                "block_public_acls": true,
                "ignore_public_acls": false,
                "block_public_policy": true,
                "restrict_public_buckets": true,
            }),
        };

        match check.evaluate(&insecure_res) {
            CheckEvaluation::Failed {
                severity, evidence, ..
            } => {
                assert_eq!(severity, Severity::High);
                assert_eq!(evidence["ignore_public_acls"], false);
            }
            _ => panic!("Expected check to fail for insecure bucket"),
        }
    }

    #[tokio::test]
    async fn orchestrator_runs_end_to_end_and_produces_findings() {
        let mut registry = ProviderRegistry::new();
        let fake_aws = FakeCloudProvider::new(CloudProvider::Aws).with_resource(
            "us-east-1",
            "s3",
            DiscoveredResource {
                provider_native_id: "prod-customer-data".to_string(),
                resource_type: "aws_s3_bucket".to_string(),
                name: Some("prod-customer-data".to_string()),
                region: Some("us-east-1".to_string()),
                tags: json!({"environment": "prod"}),
                configuration: json!({
                    "block_public_acls": false,
                    "ignore_public_acls": false,
                    "block_public_policy": false,
                    "restrict_public_buckets": false,
                }),
            },
        );

        registry.register_provider(Arc::new(fake_aws));
        registry.register_check(Arc::new(AwsS3BlockPublicAccessCheck));

        let metrics = Arc::new(ScannerMetrics::new());
        let orchestrator = ScanOrchestrator::new(Arc::new(registry), metrics.clone());

        let org_id = Uuid::new_v4();
        let account_id = Uuid::new_v4();
        let account = CloudAccount {
            id: account_id,
            organization_id: org_id,
            connection_id: Uuid::new_v4(),
            provider: CloudProvider::Aws,
            native_id: "123456789012".to_string(),
            name: Some("Production AWS".to_string()),
        };

        let mut regions_by_account = HashMap::new();
        regions_by_account.insert(account_id, vec!["us-east-1".to_string()]);

        let target = ScanTarget {
            organization_id: org_id,
            accounts: vec![account],
            regions_by_account,
            services_by_provider: HashMap::new(),
        };

        let result = orchestrator
            .run_scan(target, &[], ScanOptions::default(), None)
            .await;

        assert_eq!(result.scan_run.status, ScanStatus::Succeeded);
        assert_eq!(result.resources.len(), 1);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].check_id, "aws-s3-block-public-access");
        assert_eq!(result.findings[0].status, FindingStatus::Open);
        assert_eq!(result.score_snapshot.score, 0.0); // 0/1 passed
        assert_eq!(
            metrics
                .scans_succeeded
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn retry_with_jitter_recovers_from_throttling() {
        let attempts = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let attempts_clone = attempts.clone();

        let policy = RetryPolicy {
            max_retries: 3,
            base_delay_ms: 10,
            max_delay_ms: 50,
        };

        let res = retry_with_jitter(&policy, None, || {
            let attempts = attempts_clone.clone();
            async move {
                let current = attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if current < 2 {
                    Err(ScannerError::Throttling {
                        message: "slow down".to_string(),
                        retry_after_ms: Some(10),
                    })
                } else {
                    Ok("success")
                }
            }
        })
        .await;

        assert_eq!(res.unwrap(), "success");
        assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn permission_denied_creates_coverage_gap_and_marks_scan_partial() {
        let mut registry = ProviderRegistry::new();
        let fake_aws = FakeCloudProvider::new(CloudProvider::Aws);
        fake_aws.set_permission_denied("s3");

        registry.register_provider(Arc::new(fake_aws));
        registry.register_check(Arc::new(AwsS3BlockPublicAccessCheck));

        let metrics = Arc::new(ScannerMetrics::new());
        let orchestrator = ScanOrchestrator::new(Arc::new(registry), metrics.clone());

        let org_id = Uuid::new_v4();
        let account_id = Uuid::new_v4();
        let account = CloudAccount {
            id: account_id,
            organization_id: org_id,
            connection_id: Uuid::new_v4(),
            provider: CloudProvider::Aws,
            native_id: "123456789012".to_string(),
            name: Some("Production AWS".to_string()),
        };

        let mut regions_by_account = HashMap::new();
        regions_by_account.insert(account_id, vec!["us-east-1".to_string()]);

        let target = ScanTarget {
            organization_id: org_id,
            accounts: vec![account],
            regions_by_account,
            services_by_provider: HashMap::new(),
        };

        let result = orchestrator
            .run_scan(target, &[], ScanOptions::default(), None)
            .await;

        // Missing permissions MUST produce a coverage gap and partial status, NEVER a passing result
        assert_eq!(result.scan_run.status, ScanStatus::Partial);
        assert_eq!(result.coverage_gaps.len(), 1);
        assert!(
            result.coverage_gaps[0]
                .details
                .contains("permission denied")
        );
    }

    #[tokio::test]
    async fn findings_resolve_only_when_covered_and_passed() {
        let mut registry = ProviderRegistry::new();
        let fake_aws = FakeCloudProvider::new(CloudProvider::Aws).with_resource(
            "us-east-1",
            "s3",
            DiscoveredResource {
                provider_native_id: "fixed-bucket".to_string(),
                resource_type: "aws_s3_bucket".to_string(),
                name: Some("fixed-bucket".to_string()),
                region: Some("us-east-1".to_string()),
                tags: json!({}),
                configuration: json!({
                    "block_public_acls": true,
                    "ignore_public_acls": true,
                    "block_public_policy": true,
                    "restrict_public_buckets": true,
                }),
            },
        );

        registry.register_provider(Arc::new(fake_aws));
        registry.register_check(Arc::new(AwsS3BlockPublicAccessCheck));

        let metrics = Arc::new(ScannerMetrics::new());
        let orchestrator = ScanOrchestrator::new(Arc::new(registry), metrics.clone());

        let org_id = Uuid::new_v4();
        let account_id = Uuid::new_v4();
        let fixed_res_id = Resource::deterministic_id(org_id, account_id, "fixed-bucket");
        let other_res_id = Resource::deterministic_id(org_id, account_id, "unscanned-bucket");

        let existing_finding_fixed = Finding {
            id: Uuid::new_v4(),
            organization_id: org_id,
            check_id: "aws-s3-block-public-access".to_string(),
            resource_id: fixed_res_id,
            severity: Severity::High,
            status: FindingStatus::Open,
            evidence: json!({"block_public_acls": false}),
            fingerprint: "fp1".to_string(),
        };

        let existing_finding_unscanned = Finding {
            id: Uuid::new_v4(),
            organization_id: org_id,
            check_id: "aws-s3-block-public-access".to_string(),
            resource_id: other_res_id,
            severity: Severity::High,
            status: FindingStatus::Open,
            evidence: json!({"block_public_acls": false}),
            fingerprint: "fp2".to_string(),
        };

        let account = CloudAccount {
            id: account_id,
            organization_id: org_id,
            connection_id: Uuid::new_v4(),
            provider: CloudProvider::Aws,
            native_id: "123456789012".to_string(),
            name: Some("Production AWS".to_string()),
        };

        let mut regions_by_account = HashMap::new();
        regions_by_account.insert(account_id, vec!["us-east-1".to_string()]);

        let target = ScanTarget {
            organization_id: org_id,
            accounts: vec![account],
            regions_by_account,
            services_by_provider: HashMap::new(),
        };

        let result = orchestrator
            .run_scan(
                target,
                &[
                    existing_finding_fixed.clone(),
                    existing_finding_unscanned.clone(),
                ],
                ScanOptions::default(),
                None,
            )
            .await;

        // fixed-bucket was covered and passed -> finding resolved!
        assert!(
            result
                .resolved_finding_ids
                .contains(&existing_finding_fixed.id)
        );
        // unscanned-bucket was NOT covered -> finding NOT resolved!
        assert!(
            !result
                .resolved_finding_ids
                .contains(&existing_finding_unscanned.id)
        );
    }

    #[tokio::test]
    async fn cancellation_aborts_scan_safely() {
        let mut registry = ProviderRegistry::new();
        let fake_aws = FakeCloudProvider::new(CloudProvider::Aws);
        fake_aws.set_simulated_delay(Duration::from_millis(500));

        registry.register_provider(Arc::new(fake_aws));
        let metrics = Arc::new(ScannerMetrics::new());
        let orchestrator = ScanOrchestrator::new(Arc::new(registry), metrics.clone());

        let org_id = Uuid::new_v4();
        let account_id = Uuid::new_v4();
        let account = CloudAccount {
            id: account_id,
            organization_id: org_id,
            connection_id: Uuid::new_v4(),
            provider: CloudProvider::Aws,
            native_id: "123456789012".to_string(),
            name: Some("Production AWS".to_string()),
        };

        let mut regions_by_account = HashMap::new();
        regions_by_account.insert(account_id, vec!["us-east-1".to_string()]);

        let target = ScanTarget {
            organization_id: org_id,
            accounts: vec![account],
            regions_by_account,
            services_by_provider: HashMap::new(),
        };

        let cancel_token = CancellationToken::new();
        let cancel_clone = cancel_token.clone();

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            cancel_clone.cancel();
        });

        let result = orchestrator
            .run_scan(target, &[], ScanOptions::default(), Some(cancel_token))
            .await;

        assert_eq!(result.scan_run.status, ScanStatus::Cancelled);
    }

    #[test]
    fn structured_logging_redacts_sensitive_credentials() {
        let sensitive_payload = json!({
            "account_id": "123456789012",
            "region": "us-east-1",
            "access_key": "AKIAIOSFODNN7EXAMPLE",
            "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "authorization": "Bearer ya29.a0AfH6SM...",
            "nested": {
                "token": "sensitive_session_token",
                "normal_field": "public_metadata"
            }
        });

        let redacted = redact_sensitive_value(&sensitive_payload);
        assert_eq!(redacted["access_key"], "[REDACTED]");
        assert_eq!(redacted["secret_key"], "[REDACTED]");
        assert_eq!(redacted["authorization"], "[REDACTED]");
        assert_eq!(redacted["nested"]["token"], "[REDACTED]");
        assert_eq!(redacted["nested"]["normal_field"], "public_metadata");

        let log = StructuredLog::new("INFO", "trace-123", "scan started", sensitive_payload);
        let log_str = log.to_json_string();
        assert!(!log_str.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!log_str.contains("sensitive_session_token"));
        assert!(log_str.contains("[REDACTED]"));
    }

    #[test]
    fn aws_onboarding_rejects_static_long_lived_keys() {
        use crate::onboarding::CloudOnboardingValidator;
        use cloudsec_domain::AwsOnboardingConfig;

        let config = AwsOnboardingConfig {
            role_arn: "arn:aws:iam::123456789012:role/SecurityAuditRole".to_string(),
            external_id: "ext-id-12345678".to_string(),
            account_id: "123456789012".to_string(),
            regions: vec!["us-east-1".to_string()],
        };

        let raw_with_keys = json!({
            "role_arn": "arn:aws:iam::123456789012:role/SecurityAuditRole",
            "access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        });

        let err =
            CloudOnboardingValidator::validate_aws_input(&config, &raw_with_keys).unwrap_err();
        assert!(
            err.to_string()
                .contains("Long-lived AWS access keys are not accepted")
        );

        let raw_safe = json!({
            "role_arn": "arn:aws:iam::123456789012:role/SecurityAuditRole",
            "external_id": "ext-id-12345678",
            "account_id": "123456789012"
        });
        assert!(CloudOnboardingValidator::validate_aws_input(&config, &raw_safe).is_ok());
    }

    #[test]
    fn gcp_onboarding_rejects_stored_service_account_private_keys() {
        use crate::onboarding::CloudOnboardingValidator;
        use cloudsec_domain::GcpOnboardingConfig;

        let config = GcpOnboardingConfig {
            project_id: "my-production-project".to_string(),
            workload_identity_pool:
                "projects/123456789/locations/global/workloadIdentityPools/cloudsec-pool"
                    .to_string(),
            service_account_email: "cloudsec-reader@my-production-project.iam.gserviceaccount.com"
                .to_string(),
        };

        let raw_with_private_key = json!({
            "type": "service_account",
            "project_id": "my-production-project",
            "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...",
            "client_email": "cloudsec-reader@my-production-project.iam.gserviceaccount.com"
        });

        let err = CloudOnboardingValidator::validate_gcp_input(&config, &raw_with_private_key)
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("Stored GCP service account JSON private keys are prohibited")
        );

        let raw_safe = json!({
            "project_id": "my-production-project",
            "workload_identity_pool": "projects/123456789/locations/global/workloadIdentityPools/cloudsec-pool",
            "service_account_email": "cloudsec-reader@my-production-project.iam.gserviceaccount.com"
        });
        assert!(CloudOnboardingValidator::validate_gcp_input(&config, &raw_safe).is_ok());
    }

    #[test]
    fn connectivity_testing_detects_missing_permissions() {
        use crate::onboarding::CloudOnboardingValidator;
        use cloudsec_domain::AwsOnboardingConfig;

        let config = AwsOnboardingConfig {
            role_arn: "arn:aws:iam::123456789012:role/SecurityAuditRole".to_string(),
            external_id: "ext-id-12345678".to_string(),
            account_id: "123456789012".to_string(),
            regions: vec!["us-east-1".to_string()],
        };

        // Simulated missing s3:GetBucketPublicAccessBlock permission
        let res = CloudOnboardingValidator::test_aws_connectivity(
            &config,
            &["s3:GetBucketPublicAccessBlock"],
        )
        .unwrap();
        assert!(!res.is_valid);
        assert_eq!(
            res.missing_permissions,
            vec!["s3:GetBucketPublicAccessBlock"]
        );

        // Full permissions
        let res_ok = CloudOnboardingValidator::test_aws_connectivity(&config, &[]).unwrap();
        assert!(res_ok.is_valid);
        assert!(res_ok.missing_permissions.is_empty());
    }

    #[test]
    fn aws_assessment_checks_and_mappings_are_comprehensive() {
        use crate::aws::{
            fixtures::AwsTestFixtures, get_all_aws_checks, mappings::CheckFrameworkMappings,
        };

        let checks = get_all_aws_checks();
        // At least 24 distinct technical checks covering S3, IAM, EC2, RDS, CloudTrail, Lambda
        assert!(checks.len() >= 24);

        for check in &checks {
            let mappings = CheckFrameworkMappings::get_mappings(check.id());
            assert!(
                !mappings.is_empty(),
                "Check {} must have framework mappings",
                check.id()
            );
            assert!(
                mappings
                    .iter()
                    .any(|m| m.framework.contains("CIS Amazon Web Services")),
                "Check {} must map to CIS AWS Foundations Benchmark",
                check.id()
            );
        }

        let org_id = Uuid::new_v4();
        let account_id = Uuid::new_v4();

        // 1. S3 Checks
        let s3_pass = AwsTestFixtures::compliant_s3_bucket(org_id, account_id, "secure-bucket");
        let s3_fail = AwsTestFixtures::non_compliant_s3_bucket(org_id, account_id, "leaky-bucket");
        for check in &checks {
            if check.service() == "s3" {
                assert_eq!(check.evaluate(&s3_pass), CheckEvaluation::Passed);
                match check.evaluate(&s3_fail) {
                    CheckEvaluation::Failed { severity, .. } => {
                        assert!(matches!(
                            severity,
                            Severity::Critical | Severity::High | Severity::Medium | Severity::Low
                        ));
                    }
                    _ => panic!("Expected check {} to fail for non-compliant S3", check.id()),
                }
            }
        }

        // 2. IAM Checks
        let iam_pass = AwsTestFixtures::compliant_iam_summary(org_id, account_id);
        let iam_fail = AwsTestFixtures::non_compliant_iam_summary(org_id, account_id);
        for check in &checks {
            if check.id() == "aws-iam-root-mfa-and-keys" {
                assert_eq!(check.evaluate(&iam_pass), CheckEvaluation::Passed);
                assert!(matches!(
                    check.evaluate(&iam_fail),
                    CheckEvaluation::Failed { .. }
                ));
            }
        }

        // 3. EC2 & Security Group Checks
        let sg_pass = AwsTestFixtures::compliant_security_group(org_id, account_id, "web-sg");
        let sg_fail = AwsTestFixtures::open_admin_security_group(org_id, account_id, "admin-sg");
        for check in &checks {
            if check.id() == "aws-ec2-sg-no-open-admin-ports" {
                assert_eq!(check.evaluate(&sg_pass), CheckEvaluation::Passed);
                assert!(matches!(
                    check.evaluate(&sg_fail),
                    CheckEvaluation::Failed { .. }
                ));
            }
        }

        // 4. RDS Checks
        let rds_pass = AwsTestFixtures::compliant_rds_instance(org_id, account_id, "prod-db");
        let rds_fail = AwsTestFixtures::non_compliant_rds_instance(org_id, account_id, "open-db");
        for check in &checks {
            if check.service() == "rds" {
                assert_eq!(check.evaluate(&rds_pass), CheckEvaluation::Passed);
                assert!(matches!(
                    check.evaluate(&rds_fail),
                    CheckEvaluation::Failed { .. }
                ));
            }
        }

        // 5. CloudTrail Checks
        let trail_pass = AwsTestFixtures::compliant_cloudtrail(org_id, account_id, "main-trail");
        for check in &checks {
            if check.service() == "cloudtrail" {
                assert_eq!(check.evaluate(&trail_pass), CheckEvaluation::Passed);
            }
        }

        // 6. Lambda Checks
        let lambda_pass =
            AwsTestFixtures::compliant_lambda_function(org_id, account_id, "api-handler");
        for check in &checks {
            if check.service() == "lambda" {
                assert_eq!(check.evaluate(&lambda_pass), CheckEvaluation::Passed);
            }
        }

        // 7. Malformed Resource Handling
        let malformed = AwsTestFixtures::malformed_resource(org_id, account_id);
        for check in &checks {
            // Malformed resource should safely evaluate without crashing or panicking
            let eval = check.evaluate(&malformed);
            assert!(matches!(
                eval,
                CheckEvaluation::Passed
                    | CheckEvaluation::NotApplicable
                    | CheckEvaluation::Failed { .. }
            ));
        }
    }

    #[test]
    fn azure_assessment_checks_and_mappings_are_comprehensive() {
        use crate::azure::{
            fixtures::AzureTestFixtures, get_all_azure_checks,
            mappings::AzureCheckFrameworkMappings,
        };

        let checks = get_all_azure_checks();
        assert_eq!(checks.len(), 12);

        let org_id = Uuid::new_v4();
        let account_id = Uuid::new_v4();

        // 1. Framework Mappings Verification
        for check in &checks {
            let mappings = AzureCheckFrameworkMappings::get_mappings(check.id());
            assert!(
                !mappings.is_empty(),
                "Check {} must have framework mappings",
                check.id()
            );
            assert!(
                mappings
                    .iter()
                    .any(|m| m.framework.contains("CIS Microsoft Azure")),
                "Check {} must map to CIS Microsoft Azure Benchmark",
                check.id()
            );
            assert!(
                mappings.iter().any(|m| m.framework == "AICPA SOC 2 (TSC)"),
                "Check {} must map to SOC 2",
                check.id()
            );
            assert!(
                mappings.iter().any(|m| m.framework == "PCI DSS"),
                "Check {} must map to PCI DSS",
                check.id()
            );
            assert!(
                mappings
                    .iter()
                    .any(|m| m.framework == "HIPAA Security Rule"),
                "Check {} must map to HIPAA Security Rule",
                check.id()
            );
        }

        // 2. Storage Accounts
        let storage_pass =
            AzureTestFixtures::compliant_storage_account(org_id, account_id, "prodstorage01");
        let storage_fail =
            AzureTestFixtures::non_compliant_storage_account(org_id, account_id, "devstorage01");
        for check in &checks {
            if check.service() == "storage" {
                assert_eq!(check.evaluate(&storage_pass), CheckEvaluation::Passed);
                assert!(matches!(
                    check.evaluate(&storage_fail),
                    CheckEvaluation::Failed { .. }
                ));
            }
        }

        // 3. RBAC & Microsoft Entra ID
        let role_assign_pass =
            AzureTestFixtures::compliant_role_assignment(org_id, account_id, "assign-reader-grp");
        let role_assign_fail =
            AzureTestFixtures::direct_user_owner_assignment(org_id, account_id, "assign-owner-usr");
        let custom_role_pass =
            AzureTestFixtures::compliant_custom_role(org_id, account_id, "custom-operator");
        let custom_role_fail =
            AzureTestFixtures::wildcard_custom_role(org_id, account_id, "custom-wildcard-admin");
        let entra_pass = AzureTestFixtures::compliant_entra_governance(org_id, account_id);
        let entra_fail = AzureTestFixtures::non_compliant_entra_governance(org_id, account_id);
        let entra_gap = AzureTestFixtures::coverage_gap_entra_governance(org_id, account_id);

        for check in &checks {
            match check.id() {
                "azure-rbac-no-direct-user-owner-assignments" => {
                    assert_eq!(check.evaluate(&role_assign_pass), CheckEvaluation::Passed);
                    assert!(matches!(
                        check.evaluate(&role_assign_fail),
                        CheckEvaluation::Failed { .. }
                    ));
                }
                "azure-rbac-no-wildcard-custom-roles" => {
                    assert_eq!(check.evaluate(&custom_role_pass), CheckEvaluation::Passed);
                    assert!(matches!(
                        check.evaluate(&custom_role_fail),
                        CheckEvaluation::Failed {
                            severity: Severity::Critical,
                            ..
                        }
                    ));
                }
                "azure-entra-privileged-role-governance" => {
                    assert_eq!(check.evaluate(&entra_pass), CheckEvaluation::Passed);
                    assert!(matches!(
                        check.evaluate(&entra_fail),
                        CheckEvaluation::Failed { .. }
                    ));
                }
                "azure-entra-identity-coverage" => {
                    assert_eq!(check.evaluate(&entra_pass), CheckEvaluation::Passed);
                    let eval = check.evaluate(&entra_gap);
                    assert!(
                        matches!(eval, CheckEvaluation::CoverageGap { .. }),
                        "Expected CoverageGap for unlicensed/missing permissions Entra ID check"
                    );
                }
                _ => {}
            }
        }

        // 4. NSG Checks
        let nsg_pass = AzureTestFixtures::compliant_nsg(org_id, account_id, "nsg-prod-web");
        let nsg_open_admin =
            AzureTestFixtures::open_admin_ports_nsg(org_id, account_id, "nsg-open-mgmt");
        let nsg_stale =
            AzureTestFixtures::stale_broad_nsg(org_id, account_id, "nsg-stale-catchall");

        for check in &checks {
            if check.id() == "azure-nsg-no-open-admin-or-db-ports" {
                assert_eq!(check.evaluate(&nsg_pass), CheckEvaluation::Passed);
                assert!(matches!(
                    check.evaluate(&nsg_open_admin),
                    CheckEvaluation::Failed {
                        severity: Severity::Critical,
                        ..
                    }
                ));
            }
            if check.id() == "azure-nsg-no-broad-ranges-or-stale-rules" {
                assert_eq!(check.evaluate(&nsg_pass), CheckEvaluation::Passed);
                assert!(matches!(
                    check.evaluate(&nsg_stale),
                    CheckEvaluation::Failed { .. }
                ));
            }
        }

        // 5. Key Vault Checks
        let kv_pass = AzureTestFixtures::compliant_key_vault(org_id, account_id, "kv-prod-eastus");
        let kv_fail = AzureTestFixtures::non_compliant_key_vault(org_id, account_id, "kv-dev-open");

        for check in &checks {
            if check.service() == "keyvault" {
                assert_eq!(check.evaluate(&kv_pass), CheckEvaluation::Passed);
                assert!(matches!(
                    check.evaluate(&kv_fail),
                    CheckEvaluation::Failed { .. }
                ));
            }
        }

        // 6. Malformed and Wrong Provider Handling
        let malformed =
            AzureTestFixtures::malformed_resource(org_id, account_id, "azure_storage_account");
        let wrong_provider = AzureTestFixtures::wrong_provider_resource(org_id, account_id);

        for check in &checks {
            let eval = check.evaluate(&malformed);
            assert!(matches!(
                eval,
                CheckEvaluation::Passed
                    | CheckEvaluation::NotApplicable
                    | CheckEvaluation::Failed { .. }
                    | CheckEvaluation::CoverageGap { .. }
            ));

            assert_eq!(
                check.evaluate(&wrong_provider),
                CheckEvaluation::NotApplicable,
                "Check {} must return NotApplicable for non-Azure resources",
                check.id()
            );
        }
    }

    #[test]
    fn gcp_assessment_checks_and_mappings_are_comprehensive() {
        use crate::gcp::{
            fixtures::GcpTestFixtures, get_all_gcp_checks, mappings::GcpCheckFrameworkMappings,
        };

        let checks = get_all_gcp_checks();
        assert_eq!(checks.len(), 11);

        let org_id = Uuid::new_v4();
        let account_id = Uuid::new_v4();

        // 1. Framework Mappings Verification
        for check in &checks {
            let mappings = GcpCheckFrameworkMappings::get_mappings(check.id());
            assert!(
                !mappings.is_empty(),
                "Check {} must have framework mappings",
                check.id()
            );
            assert!(
                mappings
                    .iter()
                    .any(|m| m.framework.contains("CIS Google Cloud Platform")),
                "Check {} must map to CIS GCP Benchmark",
                check.id()
            );
            assert!(
                mappings.iter().any(|m| m.framework == "AICPA SOC 2 (TSC)"),
                "Check {} must map to SOC 2",
                check.id()
            );
            assert!(
                mappings.iter().any(|m| m.framework == "PCI DSS"),
                "Check {} must map to PCI DSS",
                check.id()
            );
            assert!(
                mappings
                    .iter()
                    .any(|m| m.framework == "HIPAA Security Rule"),
                "Check {} must map to HIPAA Security Rule",
                check.id()
            );
        }

        // 2. Cloud Storage Checks
        let bucket_pass =
            GcpTestFixtures::compliant_storage_bucket(org_id, account_id, "prod-data-bucket");
        let bucket_fail =
            GcpTestFixtures::public_storage_bucket(org_id, account_id, "public-dev-bucket");
        for check in &checks {
            if check.service() == "storage" {
                assert_eq!(check.evaluate(&bucket_pass), CheckEvaluation::Passed);
                assert!(matches!(
                    check.evaluate(&bucket_fail),
                    CheckEvaluation::Failed { .. }
                ));
            }
        }

        // 3. Compute Engine & VPC Checks
        let fw_pass = GcpTestFixtures::compliant_firewall_rule(org_id, account_id, "allow-web");
        let fw_fail =
            GcpTestFixtures::open_admin_firewall_rule(org_id, account_id, "allow-all-admin");
        let vm_pass = GcpTestFixtures::compliant_compute_instance(org_id, account_id, "backend-vm");
        let vm_fail =
            GcpTestFixtures::external_ip_compute_instance(org_id, account_id, "direct-ip-vm");

        for check in &checks {
            if check.id() == "gcp-compute-firewall-no-open-admin-or-db-ports" {
                assert_eq!(check.evaluate(&fw_pass), CheckEvaluation::Passed);
                assert!(matches!(
                    check.evaluate(&fw_fail),
                    CheckEvaluation::Failed {
                        severity: Severity::Critical,
                        ..
                    }
                ));
            }
            if check.id() == "gcp-compute-firewall-target-logging-and-default-network" {
                assert_eq!(check.evaluate(&fw_pass), CheckEvaluation::Passed);
                assert!(matches!(
                    check.evaluate(&fw_fail),
                    CheckEvaluation::Failed { .. }
                ));
            }
            if check.id() == "gcp-compute-no-unattached-or-direct-external-ips" {
                assert_eq!(check.evaluate(&vm_pass), CheckEvaluation::Passed);
                assert!(matches!(
                    check.evaluate(&vm_fail),
                    CheckEvaluation::Failed { .. }
                ));
            }
        }

        // 4. Cloud SQL Checks
        let sql_pass = GcpTestFixtures::compliant_sql_instance(org_id, account_id, "prod-postgres");
        let sql_fail = GcpTestFixtures::public_sql_instance(org_id, account_id, "open-mysql");
        for check in &checks {
            if check.service() == "sql" {
                assert_eq!(check.evaluate(&sql_pass), CheckEvaluation::Passed);
                assert!(matches!(
                    check.evaluate(&sql_fail),
                    CheckEvaluation::Failed { .. }
                ));
            }
        }

        // 5. IAM & Audit Logging Checks
        let iam_pass = GcpTestFixtures::compliant_iam_policy(org_id, account_id);
        let iam_fail = GcpTestFixtures::non_compliant_iam_policy(org_id, account_id);
        let audit_pass = GcpTestFixtures::compliant_audit_config(org_id, account_id);
        let audit_fail = GcpTestFixtures::non_compliant_audit_config(org_id, account_id);

        for check in &checks {
            if check.id() == "gcp-iam-no-primitive-roles-and-wildcard-custom-roles"
                || check.id() == "gcp-iam-no-public-principals-and-stale-keys"
            {
                assert_eq!(check.evaluate(&iam_pass), CheckEvaluation::Passed);
                assert!(matches!(
                    check.evaluate(&iam_fail),
                    CheckEvaluation::Failed { .. }
                ));
            }
            if check.id() == "gcp-logging-data-access-audit-and-sinks" {
                assert_eq!(check.evaluate(&audit_pass), CheckEvaluation::Passed);
                assert!(matches!(
                    check.evaluate(&audit_fail),
                    CheckEvaluation::Failed { .. }
                ));
            }
        }

        // 6. Malformed and Wrong Provider Handling
        let malformed =
            GcpTestFixtures::malformed_resource(org_id, account_id, "gcp_storage_bucket");
        let wrong_provider = GcpTestFixtures::wrong_provider_resource(org_id, account_id);

        for check in &checks {
            let eval = check.evaluate(&malformed);
            assert!(matches!(
                eval,
                CheckEvaluation::Passed
                    | CheckEvaluation::NotApplicable
                    | CheckEvaluation::Failed { .. }
            ));

            assert_eq!(
                check.evaluate(&wrong_provider),
                CheckEvaluation::NotApplicable,
                "Check {} must return NotApplicable for non-GCP resources",
                check.id()
            );
        }
    }
}
