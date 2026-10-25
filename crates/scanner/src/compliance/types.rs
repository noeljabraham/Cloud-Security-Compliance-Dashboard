use std::collections::HashMap;

use cloudsec_domain::{CloudProvider, CoverageGapReason, Id, Severity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MappingType {
    /// Check directly verifies the full technical requirement of the control
    Direct,
    /// Check verifies a specific clause or subset of the control
    Partial,
    /// Check provides secondary or compensating evidence for the control
    Supporting,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DetailedFrameworkMapping {
    pub framework: &'static str,
    pub version: &'static str,
    pub control_id: &'static str,
    pub title: &'static str,
    pub mapping_type: MappingType,
    pub rationale: &'static str,
    pub evidence_requirement: &'static str,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AssessmentProfile {
    StrictProduction,
    RelaxedDevelopment,
}

impl AssessmentProfile {
    pub fn severity_weight(&self, severity: Severity) -> f64 {
        match self {
            Self::StrictProduction => match severity {
                Severity::Critical => 10.0,
                Severity::High => 5.0,
                Severity::Medium => 2.0,
                Severity::Low => 1.0,
                Severity::Informational => 0.0,
            },
            Self::RelaxedDevelopment => match severity {
                Severity::Critical => 5.0,
                Severity::High => 3.0,
                Severity::Medium => 1.0,
                Severity::Low => 0.0,
                Severity::Informational => 0.0,
            },
        }
    }

    pub fn is_check_applicable(&self, _check_id: &str, severity: Severity) -> bool {
        match self {
            Self::StrictProduction => true,
            Self::RelaxedDevelopment => {
                // In relaxed dev profile, low/info non-critical checks are optional
                !matches!(severity, Severity::Low | Severity::Informational)
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationOutcome {
    Passed,
    Failed,
    /// Risk has been formally accepted by security approval; does NOT silently become a pass
    AcceptedRisk {
        reason: String,
        expires_at: Option<String>,
    },
    /// Finding is suppressed with an audit note; does NOT silently become a pass
    Suppressed {
        reason: String,
    },
    NotApplicable,
    CoverageGap {
        reason: CoverageGapReason,
        details: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CheckEvaluationRecord {
    pub check_id: String,
    pub resource_id: Id,
    pub provider: CloudProvider,
    pub service: String,
    pub account_id: Id,
    pub severity: Severity,
    pub outcome: EvaluationOutcome,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScoreBreakdown {
    /// Technical compliance score (0.0 to 100.0). Passed weight / Total applicable weight.
    pub compliance_score: f64,
    /// Coverage confidence score (0.0 to 100.0). Evaluated checks / (Evaluated + Coverage Gaps).
    pub confidence_score: f64,
    /// Confidence tier: High, Medium, Low
    pub confidence_level: String,
    pub passed_weight: f64,
    pub total_weight: f64,
    pub passed_count: usize,
    pub failed_count: usize,
    pub accepted_risk_count: usize,
    pub suppressed_count: usize,
    pub not_applicable_count: usize,
    pub coverage_gaps_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ComprehensiveScoreReport {
    pub formula_version: String,
    pub profile: AssessmentProfile,
    pub overall: ScoreBreakdown,
    pub by_framework: HashMap<String, ScoreBreakdown>,
    pub by_provider: HashMap<String, ScoreBreakdown>,
    pub by_account: HashMap<Id, ScoreBreakdown>,
    pub by_service: HashMap<String, ScoreBreakdown>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ControlCoverageStatus {
    /// Control has active automated checks that were successfully evaluated
    Implemented,
    /// Control has automated checks, but provider returned permission-denied or unsupported licensing
    Unavailable,
    /// Control is part of the framework standard but not yet automated
    Unimplemented,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ControlCoverageSummary {
    pub framework: String,
    pub version: String,
    pub control_id: String,
    pub title: String,
    pub status: ControlCoverageStatus,
    pub mapped_checks: Vec<String>,
    pub details: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ControlCoverageReport {
    pub framework: String,
    pub version: String,
    pub total_controls: usize,
    pub implemented_count: usize,
    pub unavailable_count: usize,
    pub unimplemented_count: usize,
    pub implementation_percentage: f64,
    pub controls: Vec<ControlCoverageSummary>,
}
