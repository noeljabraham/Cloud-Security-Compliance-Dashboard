use serde_json::Value;

pub fn generate_openapi_spec() -> Value {
    serde_json::from_str(SPEC).expect("Valid OpenAPI spec")
}

const SPEC: &str = r#"{
  "openapi": "3.1.0",
  "info": {
    "title": "CloudSec Posture & Compliance API",
    "version": "1.0.0",
    "description": "Production-grade multi-cloud security posture management, compliance scoring, drift tracking, risk exceptions, and remediation engine."
  },
  "servers": [
    {
      "url": "http://127.0.0.1:8080",
      "description": "Local Development Server"
    }
  ],
  "security": [
    {
      "BearerAuth": []
    }
  ],
  "components": {
    "securitySchemes": {
      "BearerAuth": {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
        "description": "OIDC Provider JWT Bearer token. Supports roles: Admin, SecurityEngineer, Auditor, Viewer."
      }
    },
    "schemas": {
      "CloudProvider": {
        "type": "string",
        "enum": ["aws", "azure", "gcp"]
      },
      "Severity": {
        "type": "string",
        "enum": ["critical", "high", "medium", "low", "informational"]
      },
      "FindingStatus": {
        "type": "string",
        "enum": ["open", "resolved", "suppressed", "accepted"]
      },
      "ConnectionStatus": {
        "type": "string",
        "enum": ["pending", "active", "error", "disabled"]
      },
      "ExceptionStatus": {
        "type": "string",
        "enum": ["pending_approval", "approved", "rejected", "expired"]
      },
      "RemediationStatus": {
        "type": "string",
        "enum": ["draft", "approved", "applied", "failed"]
      },
      "ReportFormat": {
        "type": "string",
        "enum": ["json", "markdown", "csv"]
      },
      "PaginationMeta": {
        "type": "object",
        "properties": {
          "page": { "type": "integer" },
          "per_page": { "type": "integer" },
          "total_count": { "type": "integer" },
          "total_pages": { "type": "integer" }
        },
        "required": ["page", "per_page", "total_count", "total_pages"]
      },
      "ErrorResponse": {
        "type": "object",
        "properties": {
          "error": {
            "type": "object",
            "properties": {
              "code": { "type": "string" },
              "message": { "type": "string" },
              "details": { "type": "object" }
            },
            "required": ["code", "message"]
          }
        },
        "required": ["error"]
      }
    }
  },
  "paths": {
    "/health": {
      "get": {
        "summary": "Health check",
        "description": "Returns operational health status of the API service.",
        "responses": {
          "200": { "description": "Service is healthy" }
        }
      }
    },
    "/ready": {
      "get": {
        "summary": "Readiness probe",
        "description": "Returns service readiness along with registered cloud providers and check counts.",
        "responses": {
          "200": { "description": "Service is ready" }
        }
      }
    },
    "/api/openapi.json": {
      "get": {
        "summary": "OpenAPI Specification",
        "description": "Returns the live OpenAPI 3.1 schema specification for the API.",
        "responses": {
          "200": { "description": "OpenAPI JSON schema" }
        }
      }
    },
    "/api/connections": {
      "get": {
        "summary": "List cloud connections",
        "description": "Returns paginated list of cloud connections scoped to caller organization.",
        "responses": {
          "200": { "description": "List of cloud connections" },
          "401": { "description": "Unauthorized" },
          "403": { "description": "Forbidden" }
        }
      },
      "post": {
        "summary": "Create cloud connection",
        "description": "Onboard a new AWS, Azure, or GCP cloud connection. Requires Admin role.",
        "responses": {
          "200": { "description": "Connection created successfully" },
          "400": { "description": "Invalid input / credential rejected" },
          "403": { "description": "Forbidden" }
        }
      }
    },
    "/api/connections/{id}": {
      "get": {
        "summary": "Get cloud connection details",
        "responses": {
          "200": { "description": "Connection details" },
          "404": { "description": "Connection not found" }
        }
      },
      "delete": {
        "summary": "Delete cloud connection",
        "description": "Requires Admin role.",
        "responses": {
          "204": { "description": "Connection deleted" },
          "403": { "description": "Forbidden" },
          "404": { "description": "Connection not found" }
        }
      }
    },
    "/api/connections/{id}/test": {
      "post": {
        "summary": "Test cloud connection connectivity",
        "responses": {
          "200": { "description": "Connectivity test results" }
        }
      }
    },
    "/api/connections/{id}/rotate": {
      "post": {
        "summary": "Rotate connection credentials",
        "description": "Rotate external ID or federated credential. Requires Admin role.",
        "responses": {
          "200": { "description": "Credentials rotated" }
        }
      }
    },
    "/api/connections/{id}/disable": {
      "post": {
        "summary": "Disable connection",
        "responses": {
          "200": { "description": "Connection disabled" }
        }
      }
    },
    "/api/connections/{id}/enable": {
      "post": {
        "summary": "Enable connection",
        "responses": {
          "200": { "description": "Connection enabled" }
        }
      }
    },
    "/api/accounts": {
      "get": {
        "summary": "List cloud accounts",
        "description": "Lists onboarded cloud accounts across providers for organization.",
        "responses": {
          "200": { "description": "List of accounts" }
        }
      }
    },
    "/api/accounts/{id}": {
      "get": {
        "summary": "Get cloud account by ID",
        "responses": {
          "200": { "description": "Account details" },
          "404": { "description": "Account not found" }
        }
      }
    },
    "/api/scans": {
      "get": {
        "summary": "List scan runs",
        "responses": {
          "200": { "description": "List of scan runs" }
        }
      },
      "post": {
        "summary": "Trigger a new scan run",
        "description": "Starts assessment scan with concurrency and idempotency protection. Requires Admin or SecurityEngineer role.",
        "responses": {
          "200": { "description": "Scan started or completed" },
          "409": { "description": "Conflict - scan already in progress" }
        }
      }
    },
    "/api/scans/{id}": {
      "get": {
        "summary": "Get scan run status",
        "responses": {
          "200": { "description": "Scan run details" },
          "404": { "description": "Scan run not found" }
        }
      }
    },
    "/api/scans/{id}/cancel": {
      "post": {
        "summary": "Cancel an active scan run",
        "description": "Requires Admin or SecurityEngineer role.",
        "responses": {
          "200": { "description": "Scan cancellation initiated" },
          "404": { "description": "Scan run not found" }
        }
      }
    },
    "/api/resources": {
      "get": {
        "summary": "List discovered cloud resources",
        "description": "Supports filtering, sorting, and pagination.",
        "responses": {
          "200": { "description": "Paginated resources list" }
        }
      }
    },
    "/api/resources/{id}": {
      "get": {
        "summary": "Get resource by ID",
        "responses": {
          "200": { "description": "Resource details" },
          "404": { "description": "Resource not found" }
        }
      }
    },
    "/api/findings": {
      "get": {
        "summary": "List compliance and security findings",
        "description": "Supports filtering by severity, status, provider, sorting, and pagination.",
        "responses": {
          "200": { "description": "Paginated findings list" }
        }
      }
    },
    "/api/findings/{id}": {
      "get": {
        "summary": "Get finding by ID",
        "responses": {
          "200": { "description": "Finding details" },
          "404": { "description": "Finding not found" }
        }
      }
    },
    "/api/findings/{id}/evidence": {
      "get": {
        "summary": "Get sanitized finding evidence",
        "description": "Returns deep technical evidence with credentials and secrets redacted.",
        "responses": {
          "200": { "description": "Evidence payload" }
        }
      }
    },
    "/api/findings/{id}/status": {
      "patch": {
        "summary": "Update finding status",
        "description": "Validates status transitions. Direct transition to 'Accepted' requires exception workflow. Requires Admin or SecurityEngineer role.",
        "responses": {
          "200": { "description": "Status updated" },
          "400": { "description": "Invalid status transition" }
        }
      }
    },
    "/api/findings/{id}/exceptions": {
      "post": {
        "summary": "Request risk acceptance exception for finding",
        "description": "Creates exception request with owner, reason, compensating controls, and expiry date. Requires Admin or SecurityEngineer role.",
        "responses": {
          "200": { "description": "Exception request created" }
        }
      }
    },
    "/api/exceptions": {
      "get": {
        "summary": "List exception requests",
        "responses": {
          "200": { "description": "List of finding exceptions" }
        }
      }
    },
    "/api/exceptions/{id}/approve": {
      "post": {
        "summary": "Approve exception request",
        "description": "Approves exception and updates finding status to 'Accepted'. Requires Admin role.",
        "responses": {
          "200": { "description": "Exception approved" },
          "403": { "description": "Forbidden - Admin role required" }
        }
      }
    },
    "/api/exceptions/{id}/reject": {
      "post": {
        "summary": "Reject exception request",
        "description": "Rejects exception request. Requires Admin role.",
        "responses": {
          "200": { "description": "Exception rejected" },
          "403": { "description": "Forbidden - Admin role required" }
        }
      }
    },
    "/api/findings/{id}/remediations": {
      "post": {
        "summary": "Create remediation action for finding",
        "description": "Drafts remediation script or CLI command. Requires Admin or SecurityEngineer role.",
        "responses": {
          "200": { "description": "Remediation action created" }
        }
      }
    },
    "/api/remediations": {
      "get": {
        "summary": "List remediation actions",
        "responses": {
          "200": { "description": "List of remediations" }
        }
      }
    },
    "/api/remediations/{id}/approve": {
      "post": {
        "summary": "Approve remediation action",
        "description": "Requires Admin role.",
        "responses": {
          "200": { "description": "Remediation approved" },
          "403": { "description": "Forbidden - Admin role required" }
        }
      }
    },
    "/api/remediations/{id}/apply": {
      "post": {
        "summary": "Apply remediation action",
        "description": "Executes or marks remediation as applied. Requires approved state and Admin/SecurityEngineer role.",
        "responses": {
          "200": { "description": "Remediation applied" },
          "400": { "description": "Remediation not in approved status" }
        }
      }
    },
    "/api/costs": {
      "get": {
        "summary": "Get cost optimization and waste report",
        "description": "Identifies waste, idle infrastructure, and unattached assets.",
        "responses": {
          "200": { "description": "Cost report" }
        }
      }
    },
    "/api/drift": {
      "get": {
        "summary": "List posture configuration drift items",
        "description": "Tracks regressions, new misconfigurations, and drift between scan runs.",
        "responses": {
          "200": { "description": "List of drift items" }
        }
      }
    },
    "/api/trends": {
      "get": {
        "summary": "Get historical posture trend report",
        "description": "Returns time-series history of scores and finding counts.",
        "responses": {
          "200": { "description": "Posture trend report" }
        }
      }
    },
    "/api/reports/generate": {
      "post": {
        "summary": "Generate compliance or executive report",
        "description": "Generates executive, CIS, SOC 2, or audit report in JSON, Markdown, or CSV format.",
        "responses": {
          "200": { "description": "Generated report metadata" }
        }
      }
    },
    "/api/reports": {
      "get": {
        "summary": "List generated reports",
        "responses": {
          "200": { "description": "List of generated reports" }
        }
      }
    },
    "/api/reports/{id}/download": {
      "get": {
        "summary": "Securely download generated report",
        "description": "Returns report content with proper Content-Disposition and Content-Type headers.",
        "responses": {
          "200": { "description": "Report content stream / download" },
          "404": { "description": "Report not found" }
        }
      }
    },
    "/api/scores": {
      "get": {
        "summary": "List historical score snapshots",
        "responses": {
          "200": { "description": "List of score snapshots" }
        }
      }
    },
    "/api/compliance/report": {
      "get": {
        "summary": "Get comprehensive multi-framework compliance report",
        "responses": {
          "200": { "description": "Multi-framework compliance report" }
        }
      }
    },
    "/api/compliance/coverage": {
      "get": {
        "summary": "Get control coverage report",
        "responses": {
          "200": { "description": "Control coverage metrics" }
        }
      }
    },
    "/api/checks": {
      "get": {
        "summary": "List registered security assessment checks",
        "responses": {
          "200": { "description": "List of checks with framework mappings" }
        }
      }
    },
    "/api/audit-logs": {
      "get": {
        "summary": "List audit logs",
        "responses": {
          "200": { "description": "List of audit logs" }
        }
      }
    },
    "/api/metrics": {
      "get": {
        "summary": "Get Prometheus-style scanner metrics",
        "responses": {
          "200": { "description": "Scanner metrics snapshot" }
        }
      }
    },
    "/api/remediations/templates": {
      "get": {
        "summary": "List all versioned remediation guidance templates",
        "responses": {
          "200": { "description": "List of remediation templates" }
        }
      }
    },
    "/api/remediations/generate": {
      "post": {
        "summary": "Generate copyable CLI and Terraform remediation snippets for a resource",
        "responses": {
          "200": { "description": "Rendered remediation guidance" }
        }
      }
    },
    "/api/costs/analyze": {
      "get": {
        "summary": "Compute comprehensive cost-of-risk and waste optimization report",
        "responses": {
          "200": { "description": "Comprehensive cost-risk report" }
        }
      }
    },
    "/api/costs/ingest": {
      "post": {
        "summary": "Ingest cloud billing records for cost correlation",
        "responses": {
          "200": { "description": "Ingestion confirmation" }
        }
      }
    },
    "/api/schedules": {
      "get": {
        "summary": "List recurring scan schedules",
        "responses": {
          "200": { "description": "List of scan schedules" }
        }
      },
      "post": {
        "summary": "Create a recurring scan schedule",
        "responses": {
          "200": { "description": "Created schedule" }
        }
      }
    },
    "/api/schedules/{id}/toggle": {
      "post": {
        "summary": "Toggle active state of a scan schedule",
        "responses": {
          "200": { "description": "Updated schedule" }
        }
      }
    },
    "/api/drift/baseline": {
      "get": {
        "summary": "Get promoted last-known-good baseline posture",
        "responses": {
          "200": { "description": "Baseline scan details" }
        }
      },
      "post": {
        "summary": "Promote a scan run to baseline",
        "responses": {
          "200": { "description": "Promoted baseline" }
        }
      }
    },
    "/api/drift/terraform": {
      "post": {
        "summary": "Compare live resources against parsed Terraform state v4",
        "responses": {
          "200": { "description": "Terraform resource mappings and drift flags" }
        }
      }
    },
    "/api/drift/metrics": {
      "get": {
        "summary": "Get drift and lifecycle velocity metrics (reopen rate, MTTR)",
        "responses": {
          "200": { "description": "Drift metrics summary" }
        }
      }
    },
    "/api/alerts/rules": {
      "get": {
        "summary": "List alert notification rules",
        "responses": {
          "200": { "description": "List of alert rules" }
        }
      },
      "post": {
        "summary": "Create an alert notification rule",
        "responses": {
          "200": { "description": "Created alert rule" }
        }
      }
    },
    "/api/alerts/destinations": {
      "get": {
        "summary": "List alert destinations (Slack, PagerDuty, Webhook)",
        "responses": {
          "200": { "description": "List of alert destinations" }
        }
      },
      "post": {
        "summary": "Create an alert destination",
        "responses": {
          "200": { "description": "Created destination" }
        }
      }
    },
    "/api/alerts/destinations/{id}/test": {
      "post": {
        "summary": "Test destination connectivity with HMAC signed payload",
        "responses": {
          "200": { "description": "Delivery record" }
        }
      }
    },
    "/api/alerts/history": {
      "get": {
        "summary": "List outbound webhook delivery logs",
        "responses": {
          "200": { "description": "Delivery log history" }
        }
      }
    },
    "/api/reports/export": {
      "post": {
        "summary": "Export multi-format security reports with partial data watermarks",
        "responses": {
          "200": { "description": "Generated report with content" }
        }
      }
    },
    "/api/operations/slo": {
      "get": {
        "summary": "Get real-time operational SLO compliance telemetry",
        "responses": {
          "200": { "description": "Operational SLO compliance metrics" }
        }
      }
    },
    "/api/operations/cleanup": {
      "post": {
        "summary": "Execute or dry-run retention cleanup for expired scan data",
        "responses": {
          "200": { "description": "Retention cleanup outcome summary" }
        }
      }
    }
  }
}"#;
