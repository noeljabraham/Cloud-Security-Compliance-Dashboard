use std::collections::{HashMap, HashSet};

use cloudsec_domain::{CloudProvider, Id};

use crate::{
    aws::mappings::CheckFrameworkMappings as AwsMappings,
    azure::mappings::AzureCheckFrameworkMappings as AzureMappings,
    compliance::types::{
        AssessmentProfile, CheckEvaluationRecord, ComprehensiveScoreReport, ControlCoverageReport,
        ControlCoverageStatus, ControlCoverageSummary, EvaluationOutcome, ScoreBreakdown,
    },
    gcp::mappings::GcpCheckFrameworkMappings as GcpMappings,
};

pub const SCORING_FORMULA_VERSION: &str = "2026.1";

pub struct ComplianceScoringEngine;

impl ComplianceScoringEngine {
    /// Calculate the score breakdown for a collection of evaluation records
    pub fn calculate_breakdown(
        records: &[CheckEvaluationRecord],
        profile: AssessmentProfile,
    ) -> ScoreBreakdown {
        let mut passed_weight = 0.0;
        let mut total_weight = 0.0;
        let mut passed_count = 0;
        let mut failed_count = 0;
        let mut accepted_risk_count = 0;
        let mut suppressed_count = 0;
        let mut not_applicable_count = 0;
        let mut coverage_gaps_count = 0;

        for record in records {
            // Check applicability under the selected profile
            if !profile.is_check_applicable(&record.check_id, record.severity) {
                not_applicable_count += 1;
                continue;
            }

            let weight = profile.severity_weight(record.severity);

            match &record.outcome {
                EvaluationOutcome::Passed => {
                    passed_weight += weight;
                    total_weight += weight;
                    passed_count += 1;
                }
                EvaluationOutcome::Failed => {
                    total_weight += weight;
                    failed_count += 1;
                }
                EvaluationOutcome::AcceptedRisk { .. } => {
                    // Accepted risk does NOT count as a pass; it contributes to total weight
                    total_weight += weight;
                    accepted_risk_count += 1;
                }
                EvaluationOutcome::Suppressed { .. } => {
                    // Suppressed findings do NOT count as a pass; they contribute to total weight
                    total_weight += weight;
                    suppressed_count += 1;
                }
                EvaluationOutcome::NotApplicable => {
                    not_applicable_count += 1;
                }
                EvaluationOutcome::CoverageGap { .. } => {
                    coverage_gaps_count += 1;
                }
            }
        }

        let compliance_score = if total_weight <= 0.0 {
            if passed_count > 0 { 100.0 } else { 0.0 }
        } else {
            ((passed_weight / total_weight) * 100.0 * 100.0).round() / 100.0
        };

        let evaluated_count = passed_count + failed_count + accepted_risk_count + suppressed_count;
        let total_potential = evaluated_count + coverage_gaps_count;

        let confidence_score = if total_potential == 0 {
            100.0
        } else {
            ((evaluated_count as f64 / total_potential as f64) * 100.0 * 100.0).round() / 100.0
        };

        let confidence_level = if confidence_score >= 95.0 {
            "High".to_string()
        } else if confidence_score >= 75.0 {
            "Medium".to_string()
        } else {
            "Low".to_string()
        };

        ScoreBreakdown {
            compliance_score,
            confidence_score,
            confidence_level,
            passed_weight: (passed_weight * 100.0).round() / 100.0,
            total_weight: (total_weight * 100.0).round() / 100.0,
            passed_count,
            failed_count,
            accepted_risk_count,
            suppressed_count,
            not_applicable_count,
            coverage_gaps_count,
        }
    }

    /// Compute full multi-dimensional score report
    pub fn compute_comprehensive_report(
        records: &[CheckEvaluationRecord],
        profile: AssessmentProfile,
    ) -> ComprehensiveScoreReport {
        let overall = Self::calculate_breakdown(records, profile);

        // Breakdown by Provider
        let mut records_by_provider: HashMap<CloudProvider, Vec<CheckEvaluationRecord>> =
            HashMap::new();
        for r in records {
            records_by_provider
                .entry(r.provider)
                .or_default()
                .push(r.clone());
        }

        let mut by_provider = HashMap::new();
        for (provider, prov_records) in records_by_provider {
            by_provider.insert(
                provider.as_str().to_string(),
                Self::calculate_breakdown(&prov_records, profile),
            );
        }

        // Breakdown by Account
        let mut records_by_account: HashMap<Id, Vec<CheckEvaluationRecord>> = HashMap::new();
        for r in records {
            records_by_account
                .entry(r.account_id)
                .or_default()
                .push(r.clone());
        }

        let mut by_account = HashMap::new();
        for (acc_id, acc_records) in records_by_account {
            by_account.insert(acc_id, Self::calculate_breakdown(&acc_records, profile));
        }

        // Breakdown by Service
        let mut records_by_service: HashMap<String, Vec<CheckEvaluationRecord>> = HashMap::new();
        for r in records {
            records_by_service
                .entry(r.service.clone())
                .or_default()
                .push(r.clone());
        }

        let mut by_service = HashMap::new();
        for (service, s_records) in records_by_service {
            by_service.insert(service, Self::calculate_breakdown(&s_records, profile));
        }

        // Breakdown by Framework (CIS, SOC 2, PCI DSS, HIPAA)
        let mut records_by_framework: HashMap<String, Vec<CheckEvaluationRecord>> = HashMap::new();
        for r in records {
            let mappings = match r.provider {
                CloudProvider::Aws => AwsMappings::get_mappings(&r.check_id),
                CloudProvider::Azure => AzureMappings::get_mappings(&r.check_id),
                CloudProvider::Gcp => GcpMappings::get_mappings(&r.check_id),
            };

            let mut added_frameworks = HashSet::new();
            for m in mappings {
                let fw_key = if m.framework.contains("CIS") {
                    "CIS"
                } else if m.framework.contains("SOC 2") {
                    "SOC 2"
                } else if m.framework.contains("PCI DSS") {
                    "PCI DSS"
                } else if m.framework.contains("HIPAA") {
                    "HIPAA"
                } else {
                    m.framework
                };

                if added_frameworks.insert(fw_key) {
                    records_by_framework
                        .entry(fw_key.to_string())
                        .or_default()
                        .push(r.clone());
                }
            }
        }

        let mut by_framework = HashMap::new();
        for (framework, f_records) in records_by_framework {
            by_framework.insert(framework, Self::calculate_breakdown(&f_records, profile));
        }

        ComprehensiveScoreReport {
            formula_version: SCORING_FORMULA_VERSION.to_string(),
            profile,
            overall,
            by_framework,
            by_provider,
            by_account,
            by_service,
        }
    }

    /// Generate a Control Coverage Report showing implemented, unavailable, and unimplemented controls
    pub fn generate_control_coverage_report(
        framework_prefix: &str,
        records: &[CheckEvaluationRecord],
    ) -> ControlCoverageReport {
        // Collect all mappings across AWS, Azure, GCP matching framework_prefix
        let mut controls_map: HashMap<String, (String, String, Vec<String>, bool, bool)> =
            HashMap::new();

        let mut all_checks = Vec::new();
        for check in crate::aws::get_all_aws_checks() {
            all_checks.push((CloudProvider::Aws, check.id().to_string()));
        }
        for check in crate::azure::get_all_azure_checks() {
            all_checks.push((CloudProvider::Azure, check.id().to_string()));
        }
        for check in crate::gcp::get_all_gcp_checks() {
            all_checks.push((CloudProvider::Gcp, check.id().to_string()));
        }

        for (provider, check_id) in &all_checks {
            let mappings = match provider {
                CloudProvider::Aws => AwsMappings::get_mappings(check_id),
                CloudProvider::Azure => AzureMappings::get_mappings(check_id),
                CloudProvider::Gcp => GcpMappings::get_mappings(check_id),
            };

            for m in mappings {
                if m.framework.contains(framework_prefix) {
                    let entry = controls_map
                        .entry(m.control_id.to_string())
                        .or_insert_with(|| {
                            (
                                m.framework.to_string(),
                                m.title.to_string(),
                                Vec::new(),
                                false,
                                false,
                            )
                        });
                    if !entry.2.contains(check_id) {
                        entry.2.push(check_id.clone());
                    }
                }
            }
        }

        // Now inspect records to see if controls are Implemented or Unavailable
        for record in records {
            for (_, entry) in controls_map.iter_mut() {
                if entry.2.contains(&record.check_id) {
                    match &record.outcome {
                        EvaluationOutcome::CoverageGap { .. } => {
                            entry.4 = true; // has coverage gap
                        }
                        EvaluationOutcome::Passed
                        | EvaluationOutcome::Failed
                        | EvaluationOutcome::AcceptedRisk { .. }
                        | EvaluationOutcome::Suppressed { .. } => {
                            entry.3 = true; // has active evaluation
                        }
                        EvaluationOutcome::NotApplicable => {}
                    }
                }
            }
        }

        let mut controls = Vec::new();
        let mut implemented_count = 0;
        let mut unavailable_count = 0;
        let mut unimplemented_count = 0;

        for (control_id, (fw_name, title, mapped_checks, has_eval, has_gap)) in controls_map {
            let status = if has_eval {
                implemented_count += 1;
                ControlCoverageStatus::Implemented
            } else if has_gap {
                unavailable_count += 1;
                ControlCoverageStatus::Unavailable
            } else {
                unimplemented_count += 1;
                ControlCoverageStatus::Unimplemented
            };

            controls.push(ControlCoverageSummary {
                framework: fw_name,
                version: "3.0.0 / 7.1.0".to_string(),
                control_id,
                title,
                status,
                mapped_checks,
                details: if status == ControlCoverageStatus::Unavailable {
                    Some("Blocked due to provider permission or licensing coverage gap".to_string())
                } else {
                    None
                },
            });
        }

        controls.sort_by(|a, b| a.control_id.cmp(&b.control_id));
        let total_controls = controls.len();
        let implementation_percentage = if total_controls == 0 {
            0.0
        } else {
            ((implemented_count as f64 / total_controls as f64) * 100.0 * 100.0).round() / 100.0
        };

        ControlCoverageReport {
            framework: framework_prefix.to_string(),
            version: "current".to_string(),
            total_controls,
            implemented_count,
            unavailable_count,
            unimplemented_count,
            implementation_percentage,
            controls,
        }
    }
}
