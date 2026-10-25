export type CloudProvider = "aws" | "azure" | "gcp";

export type Severity = "critical" | "high" | "medium" | "low" | "informational";

export type FindingStatus =
  "open" | "acknowledged" | "resolved" | "suppressed" | "accepted";

export type UserRole = "Admin" | "SecurityEngineer" | "Auditor" | "Viewer";

export interface FindingItem {
  id: string;
  check_id: string;
  resource_id: string;
  severity: Severity;
  status: FindingStatus;
  evidence: Record<string, unknown>;
  fingerprint: string;
  title?: string;
  provider?: CloudProvider;
  region?: string;
}

export interface ResourceItem {
  id: string;
  organization_id: string;
  account_id: string;
  provider_native_id: string;
  resource_type: string;
  name?: string | null;
  region?: string | null;
  tags?: Record<string, string>;
  configuration?: Record<string, unknown>;
}

export interface ConnectionItem {
  id: string;
  provider: CloudProvider;
  name: string;
  status: "pending" | "active" | "disabled" | "error";
  metadata: Record<string, unknown>;
  last_validated_at?: string;
}

export interface ScanRunItem {
  id: string;
  status:
    "queued" | "running" | "succeeded" | "partial" | "failed" | "cancelled";
  scanner_version: string;
  coverage: Record<string, unknown>;
  error?: string | null;
}

export interface ScoreItem {
  id: string;
  score: number;
}

export interface AuditLogItem {
  id: string;
  action: string;
  entity_type?: string;
  entity_id?: string;
  metadata: Record<string, unknown>;
  created_at: string;
}

export interface RemediationTemplateItem {
  template_id: string;
  check_id: string;
  provider: CloudProvider;
  resource_type: string;
  title: string;
  description: string;
  effort: "low" | "medium" | "high" | "very_high";
  terraform_template: string;
  cli_template: string;
  preventive_policy_example: string;
  version: string;
  requires_approval: boolean;
}

export interface RemediationGuidance {
  template_id: string;
  check_id: string;
  title: string;
  effort: string;
  impact_assessment: string;
  terraform_snippet: string;
  cli_command: string;
  policy_as_code_snippet: string;
  documentation_url: string;
}

export interface CostRiskReport {
  total_actual_monthly_spend_usd: number;
  total_risk_exposure_usd: number;
  total_monthly_savings_potential_usd: number;
  items: Array<{
    resource_id: string;
    monthly_cost_usd: number;
    risk_exposure_usd: number;
    findings_count: number;
    confidence: string;
    recommendation?: string;
  }>;
}

export interface ScanScheduleItem {
  id: string;
  organization_id: string;
  name: string;
  cron_expression: string;
  timezone: string;
  enabled: boolean;
  last_run_at?: string | null;
}

export interface AlertDestinationItem {
  id: string;
  name: string;
  destination_type:
    "slack_webhook" | "pager_duty_events_v2" | "generic_signed_webhook";
  endpoint_url: string;
  enabled: boolean;
  created_at: string;
}

export interface ComplianceFrameworkScore {
  name: string;
  score: number;
  passed: number;
  total: number;
}

export interface RegionSummary {
  region: string;
  provider: CloudProvider;
  resourceCount: number;
  findingCount: number;
  criticalCount: number;
}
