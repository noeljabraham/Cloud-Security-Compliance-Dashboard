#[cfg(test)]
mod tests {
    use cloudsec_domain::{CloudProvider, CoverageGapReason, Severity};
    use uuid::Uuid;

    use crate::compliance::{
        engine::ComplianceScoringEngine,
        types::{AssessmentProfile, CheckEvaluationRecord, EvaluationOutcome},
    };

    fn make_record(
        check_id: &str,
        provider: CloudProvider,
        service: &str,
        account_id: Uuid,
        severity: Severity,
        outcome: EvaluationOutcome,
    ) -> CheckEvaluationRecord {
        CheckEvaluationRecord {
            check_id: check_id.to_string(),
            resource_id: Uuid::new_v4(),
            provider,
            service: service.to_string(),
            account_id,
            severity,
            outcome,
        }
    }

    #[test]
    fn golden_test_strict_production_profile_exact_math() {
        let acc_aws = Uuid::new_v4();
        let acc_azure = Uuid::new_v4();
        let acc_gcp = Uuid::new_v4();

        // Hand-crafted Golden Dataset
        let records = vec![
            // 1. Critical Passed (weight: 10.0, passed: 10.0)
            make_record(
                "aws-s3-block-public-access",
                CloudProvider::Aws,
                "s3",
                acc_aws,
                Severity::Critical,
                EvaluationOutcome::Passed,
            ),
            // 2. Critical Failed (weight: 10.0, passed: 0.0)
            make_record(
                "aws-iam-root-mfa-and-keys",
                CloudProvider::Aws,
                "iam",
                acc_aws,
                Severity::Critical,
                EvaluationOutcome::Failed,
            ),
            // 3. High Passed (weight: 5.0, passed: 5.0)
            make_record(
                "aws-ec2-sg-no-open-admin-ports",
                CloudProvider::Aws,
                "ec2",
                acc_aws,
                Severity::High,
                EvaluationOutcome::Passed,
            ),
            // 4. High Accepted Risk (weight: 5.0, passed: 0.0 - MUST NOT BECOME A PASS)
            make_record(
                "aws-rds-storage-encrypted",
                CloudProvider::Aws,
                "rds",
                acc_aws,
                Severity::High,
                EvaluationOutcome::AcceptedRisk {
                    reason: "Legacy non-prod database slated for retirement in Q4".to_string(),
                    expires_at: Some("2026-12-31T00:00:00Z".to_string()),
                },
            ),
            // 5. High Passed (weight: 5.0, passed: 5.0)
            make_record(
                "azure-storage-public-access",
                CloudProvider::Azure,
                "storage",
                acc_azure,
                Severity::High,
                EvaluationOutcome::Passed,
            ),
            // 6. High Suppressed (weight: 5.0, passed: 0.0 - MUST NOT BECOME A PASS)
            make_record(
                "azure-keyvault-network-and-rbac",
                CloudProvider::Azure,
                "keyvault",
                acc_azure,
                Severity::High,
                EvaluationOutcome::Suppressed {
                    reason: "Compensating perimeter WAF verified by security team".to_string(),
                },
            ),
            // 7. Critical Passed (weight: 10.0, passed: 10.0)
            make_record(
                "gcp-storage-no-public-iam-bindings",
                CloudProvider::Gcp,
                "storage",
                acc_gcp,
                Severity::Critical,
                EvaluationOutcome::Passed,
            ),
            // 8. High Failed (weight: 5.0, passed: 0.0)
            make_record(
                "gcp-sql-no-public-ip-and-authorized-networks",
                CloudProvider::Gcp,
                "sql",
                acc_gcp,
                Severity::High,
                EvaluationOutcome::Failed,
            ),
            // 9. Not Applicable (weight: 0.0, completely excluded)
            make_record(
                "aws-lambda-vpc-attachment-policy",
                CloudProvider::Aws,
                "lambda",
                acc_aws,
                Severity::Medium,
                EvaluationOutcome::NotApplicable,
            ),
            // 10. Coverage Gap (weight: 0.0, counts only in confidence score)
            make_record(
                "azure-entra-identity-coverage",
                CloudProvider::Azure,
                "iam",
                acc_azure,
                Severity::Medium,
                EvaluationOutcome::CoverageGap {
                    reason: CoverageGapReason::PermissionDenied,
                    details: "Microsoft Graph Directory.Read.All permission missing".to_string(),
                },
            ),
        ];

        let breakdown = ComplianceScoringEngine::calculate_breakdown(
            &records,
            AssessmentProfile::StrictProduction,
        );

        // Hand-calculated assertions:
        // Passed weight = 10.0 + 5.0 + 5.0 + 10.0 = 30.0
        assert_eq!(breakdown.passed_weight, 30.0);
        // Total weight = 10.0 + 10.0 + 5.0 + 5.0 + 5.0 + 5.0 + 10.0 + 5.0 = 55.0
        assert_eq!(breakdown.total_weight, 55.0);
        // Compliance score = 30.0 / 55.0 * 100.0 = 54.55%
        assert_eq!(breakdown.compliance_score, 54.55);

        // Counts
        assert_eq!(breakdown.passed_count, 4);
        assert_eq!(breakdown.failed_count, 2);
        assert_eq!(breakdown.accepted_risk_count, 1);
        assert_eq!(breakdown.suppressed_count, 1);
        assert_eq!(breakdown.not_applicable_count, 1);
        assert_eq!(breakdown.coverage_gaps_count, 1);

        // Confidence math: 8 evaluated / (8 evaluated + 1 gap) = 8 / 9 * 100.0 = 88.89%
        assert_eq!(breakdown.confidence_score, 88.89);
        assert_eq!(breakdown.confidence_level, "Medium");
    }

    #[test]
    fn golden_test_relaxed_development_profile_exact_math() {
        let acc_aws = Uuid::new_v4();
        let acc_azure = Uuid::new_v4();
        let acc_gcp = Uuid::new_v4();

        let records = vec![
            make_record(
                "aws-s3-block-public-access",
                CloudProvider::Aws,
                "s3",
                acc_aws,
                Severity::Critical,
                EvaluationOutcome::Passed,
            ),
            make_record(
                "aws-iam-root-mfa-and-keys",
                CloudProvider::Aws,
                "iam",
                acc_aws,
                Severity::Critical,
                EvaluationOutcome::Failed,
            ),
            make_record(
                "aws-ec2-sg-no-open-admin-ports",
                CloudProvider::Aws,
                "ec2",
                acc_aws,
                Severity::High,
                EvaluationOutcome::Passed,
            ),
            make_record(
                "aws-rds-storage-encrypted",
                CloudProvider::Aws,
                "rds",
                acc_aws,
                Severity::High,
                EvaluationOutcome::AcceptedRisk {
                    reason: "Dev instance".to_string(),
                    expires_at: None,
                },
            ),
            make_record(
                "azure-storage-public-access",
                CloudProvider::Azure,
                "storage",
                acc_azure,
                Severity::High,
                EvaluationOutcome::Passed,
            ),
            make_record(
                "azure-keyvault-network-and-rbac",
                CloudProvider::Azure,
                "keyvault",
                acc_azure,
                Severity::High,
                EvaluationOutcome::Suppressed {
                    reason: "Internal dev only".to_string(),
                },
            ),
            make_record(
                "gcp-storage-no-public-iam-bindings",
                CloudProvider::Gcp,
                "storage",
                acc_gcp,
                Severity::Critical,
                EvaluationOutcome::Passed,
            ),
            make_record(
                "gcp-sql-no-public-ip-and-authorized-networks",
                CloudProvider::Gcp,
                "sql",
                acc_gcp,
                Severity::High,
                EvaluationOutcome::Failed,
            ),
        ];

        let breakdown = ComplianceScoringEngine::calculate_breakdown(
            &records,
            AssessmentProfile::RelaxedDevelopment,
        );

        // Relaxed weights: Critical = 5.0, High = 3.0
        // Passed weight: 5.0 + 3.0 + 3.0 + 5.0 = 16.0
        assert_eq!(breakdown.passed_weight, 16.0);
        // Total weight: 5.0 + 5.0 + 3.0 + 3.0 + 3.0 + 3.0 + 5.0 + 3.0 = 30.0
        assert_eq!(breakdown.total_weight, 30.0);
        // Compliance score: 16.0 / 30.0 * 100.0 = 53.33%
        assert_eq!(breakdown.compliance_score, 53.33);
    }

    #[test]
    fn accepted_risk_and_suppressed_findings_never_silently_become_passes() {
        let acc_id = Uuid::new_v4();

        // 5 Passed, 5 Accepted Risk
        let mut records = Vec::new();
        for _ in 0..5 {
            records.push(make_record(
                "aws-s3-block-public-access",
                CloudProvider::Aws,
                "s3",
                acc_id,
                Severity::High,
                EvaluationOutcome::Passed,
            ));
        }
        for _ in 0..5 {
            records.push(make_record(
                "aws-ec2-sg-no-open-admin-ports",
                CloudProvider::Aws,
                "ec2",
                acc_id,
                Severity::High,
                EvaluationOutcome::AcceptedRisk {
                    reason: "Audited exception".to_string(),
                    expires_at: None,
                },
            ));
        }

        let breakdown = ComplianceScoringEngine::calculate_breakdown(
            &records,
            AssessmentProfile::StrictProduction,
        );

        // MUST be 50.0%, NOT 100.0%!
        assert_eq!(breakdown.passed_weight, 25.0);
        assert_eq!(breakdown.total_weight, 50.0);
        assert_eq!(breakdown.compliance_score, 50.0);
        assert_eq!(breakdown.passed_count, 5);
        assert_eq!(breakdown.accepted_risk_count, 5);
    }

    #[test]
    fn comprehensive_report_computes_multi_dimensional_breakdowns() {
        let acc_aws = Uuid::new_v4();
        let acc_azure = Uuid::new_v4();
        let acc_gcp = Uuid::new_v4();

        let records = vec![
            make_record(
                "aws-s3-block-public-access",
                CloudProvider::Aws,
                "s3",
                acc_aws,
                Severity::Critical,
                EvaluationOutcome::Passed,
            ),
            make_record(
                "azure-storage-public-access",
                CloudProvider::Azure,
                "storage",
                acc_azure,
                Severity::High,
                EvaluationOutcome::Failed,
            ),
            make_record(
                "gcp-storage-no-public-iam-bindings",
                CloudProvider::Gcp,
                "storage",
                acc_gcp,
                Severity::Critical,
                EvaluationOutcome::Passed,
            ),
        ];

        let report = ComplianceScoringEngine::compute_comprehensive_report(
            &records,
            AssessmentProfile::StrictProduction,
        );

        assert_eq!(report.formula_version, "2026.1");

        // Overall: 20.0 passed weight / 25.0 total weight = 80.00%
        assert_eq!(report.overall.compliance_score, 80.0);

        // Provider breakdowns
        assert_eq!(
            report.by_provider.get("aws").unwrap().compliance_score,
            100.0
        );
        assert_eq!(
            report.by_provider.get("azure").unwrap().compliance_score,
            0.0
        );
        assert_eq!(
            report.by_provider.get("gcp").unwrap().compliance_score,
            100.0
        );

        // Framework breakdowns exist (CIS, SOC 2, PCI DSS, HIPAA)
        assert!(report.by_framework.contains_key("CIS"));
        assert!(report.by_framework.contains_key("SOC 2"));
        assert!(report.by_framework.contains_key("PCI DSS"));
        assert!(report.by_framework.contains_key("HIPAA"));

        // Service breakdowns exist (s3, storage)
        assert!(report.by_service.contains_key("s3"));
        assert!(report.by_service.contains_key("storage"));
    }

    #[test]
    fn control_coverage_report_categorizes_controls() {
        let acc_id = Uuid::new_v4();
        let records = vec![
            make_record(
                "aws-s3-block-public-access",
                CloudProvider::Aws,
                "s3",
                acc_id,
                Severity::Critical,
                EvaluationOutcome::Passed,
            ),
            make_record(
                "azure-entra-identity-coverage",
                CloudProvider::Azure,
                "iam",
                acc_id,
                Severity::Medium,
                EvaluationOutcome::CoverageGap {
                    reason: CoverageGapReason::PermissionDenied,
                    details: "Permission denied".to_string(),
                },
            ),
        ];

        let report = ComplianceScoringEngine::generate_control_coverage_report("CIS", &records);

        assert_eq!(report.framework, "CIS");
        assert!(report.total_controls > 0);
        assert!(report.implemented_count > 0);
        assert!(report.implementation_percentage > 0.0);
    }
}
