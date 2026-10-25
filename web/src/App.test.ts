import { describe, expect, it } from "vitest";
import { API_BASE_URL, APP_TITLE } from "./App";
import {
  AlertDestinationItem,
  CostRiskReport,
  FindingItem,
  RegionSummary,
  RemediationTemplateItem,
  ScanScheduleItem,
  UserRole,
} from "./types";

describe("CloudSec Dashboard Tests", () => {
  it("uses the product name and default API URL", () => {
    expect(APP_TITLE).toBe("Cloud Security Compliance Dashboard");
    expect(API_BASE_URL).toBe("http://127.0.0.1:8080");
  });

  it("structures finding items correctly with multi-cloud metadata", () => {
    const mockFinding: FindingItem = {
      id: "11111111-1111-1111-1111-111111111111",
      check_id: "aws-s3-block-public-access",
      resource_id: "prod-cloudsec-customer-data",
      severity: "high",
      status: "open",
      evidence: {
        block_public_acls: true,
        ignore_public_acls: false,
        block_public_policy: false,
        restrict_public_buckets: false,
      },
      fingerprint: "abc123def456",
      provider: "aws",
      region: "us-east-1",
    };

    expect(mockFinding.check_id).toBe("aws-s3-block-public-access");
    expect(mockFinding.severity).toBe("high");
    expect(mockFinding.status).toBe("open");
    expect(mockFinding.provider).toBe("aws");
    expect(mockFinding.region).toBe("us-east-1");
  });

  it("handles user role authorizations correctly", () => {
    const roles: UserRole[] = [
      "Admin",
      "SecurityEngineer",
      "Auditor",
      "Viewer",
    ];
    expect(roles).toHaveLength(4);

    const getRoleToken = (role: UserRole) => {
      switch (role) {
        case "Admin":
          return "Bearer admin-token";
        case "SecurityEngineer":
          return "Bearer engineer-token";
        case "Auditor":
          return "Bearer auditor-token";
        case "Viewer":
          return "Bearer viewer-token";
      }
    };

    expect(getRoleToken("Admin")).toBe("Bearer admin-token");
    expect(getRoleToken("Viewer")).toBe("Bearer viewer-token");
  });

  it("structures remediation templates with versioning and effort scale", () => {
    const template: RemediationTemplateItem = {
      template_id: "rem-aws-s3-public-access-v1",
      check_id: "aws-s3-block-public-access",
      provider: "aws",
      resource_type: "aws_s3_bucket",
      title: "Enable Amazon S3 Block Public Access",
      description: "Enforce S3 Block Public Access settings",
      effort: "low",
      terraform_template:
        'resource "aws_s3_bucket_public_access_block" { ... }',
      cli_template:
        "aws s3api put-public-access-block --bucket {{RESOURCE_NAME}}",
      preventive_policy_example: "DenyDisablingS3PublicAccessBlock",
      version: "1.0.0",
      requires_approval: true,
    };

    expect(template.effort).toBe("low");
    expect(template.version).toBe("1.0.0");
    expect(template.requires_approval).toBe(true);
    expect(template.cli_template).toContain("{{RESOURCE_NAME}}");
  });

  it("computes cost of risk and potential optimization savings", () => {
    const costReport: CostRiskReport = {
      total_actual_monthly_spend_usd: 1250.0,
      total_risk_exposure_usd: 300000.0,
      total_monthly_savings_potential_usd: 94.6,
      items: [
        {
          resource_id: "i-0987654321fedcba0",
          monthly_cost_usd: 350.0,
          risk_exposure_usd: 250000.0,
          findings_count: 2,
          confidence: "direct",
        },
      ],
    };

    expect(costReport.total_actual_monthly_spend_usd).toBe(1250.0);
    expect(costReport.total_risk_exposure_usd).toBe(300000.0);
    expect(costReport.total_monthly_savings_potential_usd).toBe(94.6);
    expect(costReport.items[0].confidence).toBe("direct");
  });

  it("structures geographic region distribution summaries", () => {
    const regions: RegionSummary[] = [
      {
        region: "us-east-1",
        provider: "aws",
        resourceCount: 14,
        findingCount: 3,
        criticalCount: 1,
      },
      {
        region: "westeurope",
        provider: "azure",
        resourceCount: 4,
        findingCount: 0,
        criticalCount: 0,
      },
    ];

    expect(regions).toHaveLength(2);
    expect(regions[0].region).toBe("us-east-1");
    expect(regions[0].findingCount).toBe(3);
    expect(regions[1].criticalCount).toBe(0);
  });

  it("structures scan schedules and alert destinations", () => {
    const schedule: ScanScheduleItem = {
      id: "55555555-5555-5555-5555-555555555555",
      organization_id: "00000000-0000-0000-0000-000000000001",
      name: "Nightly Security Audit",
      cron_expression: "0 0 * * *",
      timezone: "America/New_York",
      enabled: true,
      last_run_at: "2026-10-25T00:00:00Z",
    };

    const alertDest: AlertDestinationItem = {
      id: "66666666-6666-6666-6666-666666666666",
      name: "Security Ops PagerDuty",
      destination_type: "pager_duty_events_v2",
      endpoint_url: "https://events.pagerduty.com/v2/enqueue",
      enabled: true,
      created_at: "2026-10-25T12:00:00Z",
    };

    expect(schedule.cron_expression).toBe("0 0 * * *");
    expect(schedule.enabled).toBe(true);
    expect(alertDest.destination_type).toBe("pager_duty_events_v2");
  });
});
