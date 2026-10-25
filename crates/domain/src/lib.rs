#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const APP_NAME: &str = "Cloud Security Compliance Dashboard";

pub type Id = Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum CloudProvider {
    Aws,
    Azure,
    Gcp,
}

impl CloudProvider {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Aws => "aws",
            Self::Azure => "azure",
            Self::Gcp => "gcp",
        }
    }

    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "aws" => Some(Self::Aws),
            "azure" => Some(Self::Azure),
            "gcp" => Some(Self::Gcp),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Informational => "informational",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    Open,
    Acknowledged,
    Resolved,
    Suppressed,
    Accepted,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    Queued,
    Running,
    Succeeded,
    Partial,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionStatus {
    Pending,
    Active,
    Disabled,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CloudConnection {
    pub id: Id,
    pub organization_id: Id,
    pub provider: CloudProvider,
    pub name: String,
    pub status: ConnectionStatus,
    pub secret_reference: Option<String>,
    pub metadata: Value,
    pub last_validated_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditLog {
    pub id: Id,
    pub organization_id: Id,
    pub actor_id: Option<Id>,
    pub action: String,
    pub entity_type: Option<String>,
    pub entity_id: Option<Id>,
    pub metadata: Value,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AwsOnboardingConfig {
    pub role_arn: String,
    pub external_id: String,
    pub account_id: String,
    pub regions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AzureOnboardingConfig {
    pub tenant_id: String,
    pub client_id: String,
    pub subscription_id: String,
    pub federated_credential: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GcpOnboardingConfig {
    pub project_id: String,
    pub workload_identity_pool: String,
    pub service_account_email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Organization {
    pub id: Id,
    pub name: String,
    pub slug: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CloudAccount {
    pub id: Id,
    pub organization_id: Id,
    pub connection_id: Id,
    pub provider: CloudProvider,
    pub native_id: String,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Resource {
    pub id: Id,
    pub organization_id: Id,
    pub account_id: Id,
    pub provider_native_id: String,
    pub resource_type: String,
    pub name: Option<String>,
    pub tags: Value,
    pub region: Option<String>,
    pub configuration: Value,
}

impl Resource {
    pub fn deterministic_id(organization_id: Id, account_id: Id, provider_native_id: &str) -> Id {
        let mut hasher = Sha256::new();
        hasher.update(organization_id.as_bytes());
        hasher.update([0]);
        hasher.update(account_id.as_bytes());
        hasher.update([0]);
        hasher.update(provider_native_id.as_bytes());
        let hash = hasher.finalize();
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&hash[0..16]);
        bytes[6] = (bytes[6] & 0x0f) | 0x40; // RFC 4122 version 4
        bytes[8] = (bytes[8] & 0x3f) | 0x80; // RFC 4122 variant 1
        Uuid::from_bytes(bytes)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DiscoveredResource {
    pub provider_native_id: String,
    pub resource_type: String,
    pub name: Option<String>,
    pub region: Option<String>,
    pub tags: Value,
    pub configuration: Value,
}

impl DiscoveredResource {
    pub fn into_resource(self, organization_id: Id, account_id: Id) -> Resource {
        let id = Resource::deterministic_id(organization_id, account_id, &self.provider_native_id);
        Resource {
            id,
            organization_id,
            account_id,
            provider_native_id: self.provider_native_id,
            resource_type: self.resource_type,
            name: self.name,
            tags: self.tags,
            region: self.region,
            configuration: self.configuration,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CoverageGapReason {
    PermissionDenied,
    Throttled,
    UnsupportedRegion,
    UnsupportedService,
    Timeout,
    InternalError,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CoverageGap {
    pub account_id: Id,
    pub provider: CloudProvider,
    pub region: Option<String>,
    pub service: String,
    pub check_id: Option<String>,
    pub reason: CoverageGapReason,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CheckMetadata {
    pub id: String,
    pub provider: CloudProvider,
    pub service: String,
    pub category: String,
    pub version: String,
    pub title: String,
    pub description: String,
    pub remediation: String,
    pub severity: Severity,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScanRun {
    pub id: Id,
    pub organization_id: Id,
    pub status: ScanStatus,
    pub scanner_version: String,
    pub coverage: Value,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScanJob {
    pub id: Id,
    pub scan_run_id: Id,
    pub organization_id: Id,
    pub account_id: Id,
    pub status: ScanStatus,
    pub coverage: Value,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScoreSnapshot {
    pub id: Id,
    pub organization_id: Id,
    pub scan_run_id: Option<Id>,
    pub provider: Option<CloudProvider>,
    pub account_id: Option<Id>,
    pub score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Finding {
    pub id: Id,
    pub organization_id: Id,
    pub check_id: String,
    pub resource_id: Id,
    pub severity: Severity,
    pub status: FindingStatus,
    pub evidence: Value,
    pub fingerprint: String,
}

impl Finding {
    pub fn fingerprint(check_id: &str, resource_native_id: &str, evidence: &Value) -> String {
        let mut hasher = Sha256::new();
        hasher.update(check_id.as_bytes());
        hasher.update([0]);
        hasher.update(resource_native_id.as_bytes());
        hasher.update([0]);
        hasher.update(canonical_json(evidence).as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UserRole {
    Admin,
    SecurityEngineer,
    Auditor,
    Viewer,
}

impl UserRole {
    pub fn can_write_connections(&self) -> bool {
        matches!(self, Self::Admin)
    }

    pub fn can_manage_scans(&self) -> bool {
        matches!(self, Self::Admin | Self::SecurityEngineer)
    }

    pub fn can_request_exceptions(&self) -> bool {
        matches!(self, Self::Admin | Self::SecurityEngineer)
    }

    pub fn can_approve_exceptions(&self) -> bool {
        matches!(self, Self::Admin)
    }

    pub fn can_apply_remediations(&self) -> bool {
        matches!(self, Self::Admin | Self::SecurityEngineer)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthUser {
    pub user_id: Id,
    pub email: String,
    pub role: UserRole,
    pub organization_id: Id,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExceptionStatus {
    PendingApproval,
    Approved,
    Rejected,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FindingException {
    pub id: Id,
    pub organization_id: Id,
    pub finding_id: Id,
    pub requested_by: Id,
    pub owner: String,
    pub reason: String,
    pub compensating_controls: Option<String>,
    pub expires_at: Option<String>,
    pub status: ExceptionStatus,
    pub approved_by: Option<Id>,
    pub reviewed_at: Option<String>,
    pub review_notes: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RemediationStatus {
    Draft,
    Approved,
    Applied,
    Failed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RemediationExecutionState {
    Draft,
    Requested,
    Approved,
    Rejected,
    InProgress,
    Completed,
    Failed,
    RolledBack,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RemediationEffort {
    Low,
    Medium,
    High,
    VeryHigh,
}

impl RemediationEffort {
    pub fn description(&self) -> &'static str {
        match self {
            Self::Low => "Minimal effort (< 1 hour): single command or trivial config toggle",
            Self::Medium => "Moderate effort (1-4 hours): template update and standard review",
            Self::High => {
                "Significant effort (1-2 days): multi-resource dependency or coordination"
            }
            Self::VeryHigh => {
                "Complex effort (> 2 days): architectural change or migration required"
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RemediationTemplate {
    pub template_id: String,
    pub check_id: String,
    pub provider: CloudProvider,
    pub resource_type: String,
    pub title: String,
    pub description: String,
    pub effort: RemediationEffort,
    pub terraform_template: String,
    pub cli_template: String,
    pub preventive_policy_example: String,
    pub version: String,
    pub requires_approval: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RemediationAction {
    pub id: Id,
    pub organization_id: Id,
    pub finding_id: Id,
    pub title: String,
    pub description: String,
    pub action_type: String, // e.g. "cli", "terraform", "api"
    pub script: String,
    pub status: RemediationStatus,
    pub execution_state: RemediationExecutionState,
    pub effort: RemediationEffort,
    pub approved_by: Option<Id>,
    pub applied_at: Option<String>,
    pub change_ticket_ref: Option<String>,
    pub verification_evidence: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReportFormat {
    Json,
    Markdown,
    Csv,
    Pdf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GeneratedReport {
    pub id: Id,
    pub organization_id: Id,
    pub title: String,
    pub report_type: String, // e.g. "executive", "cis", "soc2", "audit"
    pub format: ReportFormat,
    pub content: String,
    pub is_partial_data: bool,
    pub generated_by: Id,
    pub created_at: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CostAllocationConfidence {
    Direct,
    Inferred,
    Unallocated,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CostOfRiskItem {
    pub resource_id: Id,
    pub provider_native_id: String,
    pub provider: CloudProvider,
    pub service: String,
    pub actual_monthly_spend_usd: f64,
    pub estimated_risk_exposure_usd: f64,
    pub savings_potential_usd: f64,
    pub confidence: CostAllocationConfidence,
    pub critical_findings_count: usize,
    pub high_findings_count: usize,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ComprehensiveCostRiskReport {
    pub total_actual_monthly_spend_usd: f64,
    pub total_risk_exposure_usd: f64,
    pub total_monthly_savings_potential_usd: f64,
    pub items: Vec<CostOfRiskItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScanSchedule {
    pub id: Id,
    pub organization_id: Id,
    pub connection_id: Option<Id>,
    pub name: String,
    pub cron_expression: String,
    pub timezone: String,
    pub enabled: bool,
    pub last_run_at: Option<String>,
    pub next_run_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BaselineScan {
    pub organization_id: Id,
    pub scan_run_id: Id,
    pub promoted_by: Id,
    pub promoted_at: String,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingLifecycleChange {
    New,
    Persistent,
    Resolved,
    Reopened,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FindingLifecycleDelta {
    pub finding_id: Id,
    pub check_id: String,
    pub resource_id: Id,
    pub change: FindingLifecycleChange,
    pub detected_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TerraformResourceMapping {
    pub address: String,
    pub resource_type: String,
    pub cloud_resource_id: String,
    pub has_drift: bool,
    pub drift_attributes: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AlertTriggerCondition {
    NewCriticalFinding,
    SecurityRegression,
    IaCDrift,
    ScanFailure,
    CoverageLoss,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AlertDestinationType {
    SlackWebhook,
    PagerDutyEventsV2,
    GenericSignedWebhook,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AlertDestination {
    pub id: Id,
    pub organization_id: Id,
    pub name: String,
    pub destination_type: AlertDestinationType,
    pub endpoint_url: String,
    pub encrypted_secret_reference: Option<String>,
    pub enabled: bool,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AlertRule {
    pub id: Id,
    pub organization_id: Id,
    pub name: String,
    pub triggers: Vec<AlertTriggerCondition>,
    pub destination_ids: Vec<Id>,
    pub severity_threshold: Severity,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WebhookDeliveryRecord {
    pub id: Id,
    pub organization_id: Id,
    pub rule_id: Id,
    pub destination_id: Id,
    pub trigger: AlertTriggerCondition,
    pub status_code: Option<u16>,
    pub success: bool,
    pub error_message: Option<String>,
    pub delivered_at: String,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CostOptimizationItem {
    pub resource_id: Id,
    pub resource_native_id: String,
    pub provider: CloudProvider,
    pub item_type: String, // e.g. "unattached_ip", "idle_database", "unencrypted_bucket"
    pub estimated_monthly_waste_usd: f64,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CostReport {
    pub total_estimated_monthly_waste_usd: f64,
    pub items: Vec<CostOptimizationItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DriftItem {
    pub id: Id,
    pub organization_id: Id,
    pub resource_id: Id,
    pub resource_name: String,
    pub provider: CloudProvider,
    pub check_id: String,
    pub drift_type: String, // e.g. "new_finding", "regression", "resolved"
    pub detected_at: String,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TrendDataPoint {
    pub timestamp: String,
    pub compliance_score: f64,
    pub open_findings_count: usize,
    pub resolved_findings_count: usize,
    pub critical_findings_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PostureTrendReport {
    pub organization_id: Id,
    pub history: Vec<TrendDataPoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PaginationMeta {
    pub page: usize,
    pub per_page: usize,
    pub total_count: usize,
    pub total_pages: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PaginatedResponse<T> {
    pub data: Vec<T>,
    pub pagination: PaginationMeta,
}

pub fn calculate_finding_risk_score(
    severity: Severity,
    is_publicly_accessible: bool,
    has_wildcard_admin: bool,
    is_sensitive_data: bool,
    has_approved_exception: bool,
) -> u32 {
    let mut score = match severity {
        Severity::Critical => 90i32,
        Severity::High => 70,
        Severity::Medium => 45,
        Severity::Low => 20,
        Severity::Informational => 0,
    };

    if is_publicly_accessible {
        score += 10;
    }
    if has_wildcard_admin {
        score += 10;
    }
    if is_sensitive_data {
        score += 5;
    }
    if has_approved_exception {
        score -= 10;
    }

    score.clamp(0, 100) as u32
}

pub fn calculate_compliance_score(total_evaluations: usize, passed_evaluations: usize) -> f64 {
    if total_evaluations == 0 {
        0.0
    } else {
        ((passed_evaluations as f64 / total_evaluations as f64) * 100.0 * 100.0).round() / 100.0
    }
}

fn canonical_json(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by_key(|(key, _)| *key);
            entries
                .into_iter()
                .map(|(key, value)| format!("{key}:{}", canonical_json(value)))
                .collect::<Vec<_>>()
                .join(",")
        }
        Value::Array(values) => values
            .iter()
            .map(canonical_json)
            .collect::<Vec<_>>()
            .join(","),
        _ => value.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn finding_fingerprint_is_stable_for_object_key_order() {
        let first = json!({"enabled": true, "port": 443});
        let second = json!({"port": 443, "enabled": true});

        assert_eq!(
            Finding::fingerprint("tls-required", "bucket-1", &first),
            Finding::fingerprint("tls-required", "bucket-1", &second)
        );
    }

    #[test]
    fn finding_fingerprint_changes_for_identity_inputs() {
        let evidence = json!({"enabled": false});

        assert_ne!(
            Finding::fingerprint("check-a", "resource", &evidence),
            Finding::fingerprint("check-b", "resource", &evidence)
        );
    }

    #[test]
    fn deterministic_resource_id_is_stable_and_unique() {
        let org_a = Uuid::new_v4();
        let org_b = Uuid::new_v4();
        let account = Uuid::new_v4();
        let id1 = Resource::deterministic_id(org_a, account, "bucket-alpha");
        let id2 = Resource::deterministic_id(org_a, account, "bucket-alpha");
        let id3 = Resource::deterministic_id(org_b, account, "bucket-alpha");
        let id4 = Resource::deterministic_id(org_a, account, "bucket-beta");

        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
        assert_ne!(id1, id4);
    }

    #[test]
    fn risk_score_calculation_applies_modifiers_and_clamps() {
        let base_high = calculate_finding_risk_score(Severity::High, false, false, false, false);
        assert_eq!(base_high, 70);

        let high_with_exposure =
            calculate_finding_risk_score(Severity::High, true, true, true, false);
        assert_eq!(high_with_exposure, 95);

        let critical_with_all =
            calculate_finding_risk_score(Severity::Critical, true, true, true, false);
        assert_eq!(critical_with_all, 100);

        let info_with_exception =
            calculate_finding_risk_score(Severity::Informational, false, false, false, true);
        assert_eq!(info_with_exception, 0);
    }

    #[test]
    fn compliance_score_computes_percentage() {
        assert_eq!(calculate_compliance_score(10, 8), 80.0);
        assert_eq!(calculate_compliance_score(0, 0), 0.0);
        assert_eq!(calculate_compliance_score(3, 1), 33.33);
    }
}
