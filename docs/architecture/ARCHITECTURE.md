# CloudSec Architecture & Security Specification

**Document Version:** 1.0.0  
**Target:** CloudSec Platform v0.1.0 MVP  

---

## 1. System Architecture & Component Diagram

```
 +-----------------------------------------------------------------------------------+
 |                              OPERATOR / BROWSER                                   |
 |  +-----------------------------------------------------------------------------+  |
 |  | React 19 Dashboard (OIDC Auth, RBAC Switcher, Executive, Engineer Views)   |  |
 |  +--------------------------------------+--------------------------------------+  |
 +-----------------------------------------|-----------------------------------------+
                                           | HTTPS / REST
                                           v
 +-----------------------------------------------------------------------------------+
 |                                CLOUDSEC API GATEWAY                               |
 |  +-----------------------------------------------------------------------------+  |
 |  | Axum REST API (Port 8080)                                                   |  |
 |  | - Bearer JWT Auth & Tenant Scoping Middleware                               |  |
 |  | - Strict Input Sanitization & OpenAPI 3.1 Contract                          |  |
 |  | - Rate Limiter, CORS & Security Headers (CSP, HSTS, X-Content-Type)         |  |
 |  +--------------------+------------------------------------+-------------------+  |
 +-----------------------|------------------------------------|----------------------+
                         |                                    |
          Enqueue Jobs   |                                    | Read / Write State
                         v                                    v
 +-----------------------------------+     +-----------------------------------------+
 |       DISTRIBUTED WORKER          |     |           PERSISTENCE LAYER             |
 | - Lease-Based Locking             |     | - PostgreSQL 16 (Additive Migrations)   |
 | - Resumable Checkpoints           |     | - AES-256-GCM / KMS Secret References   |
 | - Provider Throttling / Retries   |     | - Immutable Audit Trail                 |
 +-----------------+-----------------+     +-----------------------------------------+
                   |
     Read-only API | Scanning
                   v
 +-----------------------------------------------------------------------------------+
 |                             TARGET CLOUD PROVIDERS                                |
 |   +--------------------+     +--------------------+     +---------------------+   |
 |   | AWS (STS AssumeRole|     | Azure (ARM OIDC /  |     | GCP (Workload Id /  |   |
 |   |  SecurityAudit)    |     |  Reader Role)      |     |  Security Reviewer) |   |
 |   +--------------------+     +--------------------+     +---------------------+   |
 +-----------------------------------------------------------------------------------+
```

---

## 2. Cloud Provider Permission Matrix

CloudSec operates under strict **Least Privilege Read-Only** access. It never requests or executes write/modify permissions.

### 2.1 Amazon Web Services (AWS)
- **Role Pattern**: Cross-account IAM Role with External ID (`ext-id-...`).
- **Managed Policy**: `arn:aws:iam::aws:policy/SecurityAudit`

| API Action | Reason & Assessment Check |
| :--- | :--- |
| `s3:GetBucketPublicAccessBlock` | Evaluates check `aws-s3-block-public-access` (CIS 2.1.4.1). |
| `s3:GetEncryptionConfiguration` | Evaluates check `aws-s3-default-encryption` (CIS 2.1.1). |
| `iam:GetAccountSummary` | Assesses root MFA and account-level credential hygiene. |
| `iam:ListUsers` & `iam:ListAccessKeys` | Evaluates check `aws-iam-root-no-access-keys` (CIS 1.4). |
| `ec2:DescribeSecurityGroups` | Verifies no open ingress on ports 22/3389 to 0.0.0.0/0. |
| `cloudtrail:DescribeTrails` & `GetTrailStatus` | Confirms multi-region management event logging and file validation. |

### 2.2 Microsoft Azure
- **Identity Pattern**: Azure App Registration / Service Principal with Directory Reader and Subscription Reader roles.

| Role / Permission | Reason & Assessment Check |
| :--- | :--- |
| `Microsoft.Storage/storageAccounts/read` | Evaluates `azure-storage-public-access` and HTTPS-only transfer. |
| `Microsoft.Authorization/roleAssignments/read` | Audits custom RBAC roles and excessive subscription privileges. |
| `Microsoft.Network/networkSecurityGroups/read` | Identifies unrestricted inbound rules on administrative ports. |
| `Microsoft.KeyVault/vaults/read` | Verifies soft-delete and purge protection configuration. |

### 2.3 Google Cloud Platform (GCP)
- **Identity Pattern**: Workload Identity Federation or dedicated service account.
- **Predefined Role**: `roles/iam.securityReviewer` and `roles/viewer`

| API Permission | Reason & Assessment Check |
| :--- | :--- |
| `storage.buckets.get` & `getIamPolicy` | Evaluates `gcp-storage-no-public-iam` ensuring no `allUsers` access. |
| `sql.instances.get` | Evaluates `gcp-sql-no-public-ip` ensuring Cloud SQL has private IP only. |
| `compute.firewalls.list` | Detects ingress rules opening ports 22/3389 to `0.0.0.0/0`. |
| `resourcemanager.projects.getIamPolicy` | Audits project-level IAM bindings and default service account usage. |

---

## 3. Check Authoring & Scoring Specification

### 3.1 Check Definition Structure
Each check implements the `Check` trait:
```rust
pub trait Check: Send + Sync {
    fn id(&self) -> &'static str;
    fn provider(&self) -> CloudProvider;
    fn service(&self) -> &'static str;
    fn base_severity(&self) -> Severity;
    fn evaluate(&self, resource: &Resource) -> CheckEvaluation;
    fn framework_mappings(&self) -> Vec<DetailedFrameworkMapping>;
}
```

### 3.2 Evaluation Outcomes
- `CheckEvaluation::Passed`: Resource satisfies all compliance criteria.
- `CheckEvaluation::Failed { details }`: Misconfiguration detected with evidence dictionary.
- `CheckEvaluation::CoverageGap { reason, details }`: Provider returned permission-denied or resource API was unavailable. Evaluates to a **Coverage Gap**, preventing false passing scores.
- `CheckEvaluation::NotApplicable`: Resource type does not apply to check logic.

### 3.3 Scoring Formula
Compliance scores use weighted mathematical aggregation:
$$\text{Technical Score} = \left( \frac{\sum \text{Weights of Passed Checks}}{\sum \text{Weights of Applicable Checks}} \right) \times 100$$
$$\text{Coverage Confidence} = \left( \frac{\text{Evaluated Checks}}{\text{Evaluated Checks} + \text{Coverage Gaps}} \right) \times 100$$
Risk Severity Weights:
- Critical: Weight 10.0
- High: Weight 5.0
- Medium: Weight 2.0
- Low: Weight 0.5

---

## 4. Score Limitations & Framework Disclaimer

> **IMPORTANT COMPLIANCE NOTICE**:  
> CloudSec evaluates technical configuration controls accessible via cloud provider APIs. It does **not** evaluate organizational policies, employee background checks, physical data center security, or non-technical governance procedures.  
> A 100% technical compliance score on CloudSec is an internal assessment tool and does **not** constitute formal ISO 27001, SOC 2, or HIPAA certification by an accredited third-party auditor.

