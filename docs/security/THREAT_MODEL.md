# CloudSec Threat Model & Security Architecture

**Document Version:** 1.0.0  
**Target:** CloudSec Platform v0.1.0 MVP  
**Classification:** Internal Security Architecture  

---

## 1. System Overview & Asset Inventory

CloudSec is a self-hosted multi-cloud security posture management (CSPM) and compliance scoring platform. It continuously connects to Amazon Web Services (AWS), Microsoft Azure, and Google Cloud Platform (GCP) to audit infrastructure configurations against CIS Benchmarks, SOC 2, PCI-DSS, and HIPAA standards.

### Critical Assets
1. **Cloud Access Credentials**: AWS IAM cross-account Role ARNs with External IDs, Azure Service Principal Client IDs and Client Secrets, GCP Service Account Private Keys.
2. **Discovered Resource Configurations**: Cloud metadata detailing bucket names, security group rules, network topologies, database configurations, and IAM policies.
3. **Audit Findings & Evidence**: Specific misconfiguration records, policy non-compliance evidence, and configuration snippets.
4. **Tenant Isolation Data**: Organization identifiers, user roles (Admin, SecurityEngineer, Auditor, Viewer), and tenancy scoping.
5. **Outbound Notification Endpoints & Secrets**: Webhook URLs and HMAC-SHA256 shared secrets for Slack and PagerDuty.
6. **Infrastructure as Code State Files**: Parsed Terraform `.tfstate` snapshots used for drift tracking.

---

## 2. Trust Boundaries & Data Flow Diagram

```
+-----------------------------------------------------------------------------------------+
| TRUST BOUNDARY 1: Cloud Service Providers (External)                                     |
|                                                                                         |
|   +--------------------+     +--------------------+     +---------------------------+   |
|   | AWS STS / IAM / S3 |     | Azure ARM / RBAC   |     | GCP Cloud Resource / IAM  |   |
|   +---------+----------+     +---------+----------+     +-------------+-------------+   |
+-------------|--------------------------|------------------------------|-----------------+
              |                          |                              |
              | Read-only metadata via   | Read-only ARM API via        | Read-only API via
              | STS AssumeRole           | OIDC / Client Secret         | Workload Identity
              v                          v                              v
+-----------------------------------------------------------------------------------------+
| TRUST BOUNDARY 2: CloudSec Ingestion & Worker Subsystem (Isolated DMZ)                  |
|                                                                                         |
|   +---------------------------------------------------------------------------------+   |
|   | Distributed Scan Worker Queue (Lease-based lock, non-concurrent execution)      |   |
|   +---------------------------------------+-----------------------------------------+   |
|                                           |                                             |
|                                           v                                             |
|   +---------------------------------------------------------------------------------+   |
|   | Ingestion Sanitizer & Evidence Redactor (Masks keys, passwords, bearer tokens)  |   |
|   +---------------------------------------+-----------------------------------------+   |
+-------------------------------------------|---------------------------------------------+
                                            |
                                            | Internal Bus / gRPC / DB
                                            v
+-----------------------------------------------------------------------------------------+
| TRUST BOUNDARY 3: Core API & Multi-Tenant Data Store                                    |
|                                                                                         |
|   +---------------------------------------------------------------------------------+   |
|   | CloudSec REST API Gateway (JWT Bearer Auth, Rate Limiter, Security Headers)     |   |
|   +---------------------------------------+-----------------------------------------+   |
|                                           |                                             |
|                                           v                                             |
|   +---------------------------------------------------------------------------------+   |
|   | Tenant Isolation Boundary (Enforces org_id filter on EVERY query and mutation)  |   |
|   +---------------------------------------+-----------------------------------------+   |
|                                           |                                             |
|                                           v                                             |
|   +---------------------------------------------------------------------------------+   |
|   | PostgreSQL Database (Encrypted at Rest with AES-256-GCM / KMS, TLS in transit)  |   |
|   +---------------------------------------------------------------------------------+   |
+-----------------------------------------------------------------------------------------+
                                            |
                                            v
+-----------------------------------------------------------------------------------------+
| TRUST BOUNDARY 4: Operator & External Alert Integrations                                 |
|                                                                                         |
|   +--------------------+     +--------------------+     +---------------------------+   |
|   | Web Dashboard (UI) |     | Slack Block Kit    |     | PagerDuty Events API v2   |   |
|   | (OIDC Authenticated|     | (HMAC-SHA256       |     | (Signed HTTPS Webhook)    |   |
|   |  RBAC Enforced)    |     |  Signature)        |     |                           |   |
|   +--------------------+     +--------------------+     +---------------------------+   |
+-----------------------------------------------------------------------------------------+
```

---

## 3. STRIDE Threat Analysis by Subsystem

### 3.1 Cloud Credentials & Onboarding (AWS, Azure, GCP)
- **Spoofing**: An attacker claims to own an AWS account or Azure subscription belonging to another party.
  - *Mitigation*: Mandatory cryptographically random External ID (`ext-id-...`) for AWS STS role assumptions; explicit subscription UUID validation for Azure; project ID binding for GCP. Static long-lived root keys and raw JSON keys are rejected at onboarding time.
- **Tampering**: Modifying stored connection credentials in the database to intercept or re-route queries.
  - *Mitigation*: Credentials and secrets are encrypted at rest using AES-256-GCM authenticated encryption (`EncryptionService`). Any tampering with ciphertext or authentication tag causes immediate decryption failure.
- **Information Disclosure**: Accidental logging or serialization of connection secrets in error traces.
  - *Mitigation*: Secret references are redacted in all API responses (`[REDACTED]`), logs use structured key masking, and external IDs are masked in audit logs.
- **Elevation of Privilege**: Scanner attempting to modify cloud resources.
  - *Mitigation*: CloudSec runs under strictly read-only policies (e.g., `SecurityAudit` on AWS, `Reader` on Azure, `Viewer`/`Security Reviewer` on GCP). Release 1 contains zero write or remediation execution code.

### 3.2 Tenant Boundaries & Data Access
- **Spoofing**: An authenticated user of Organization A sends a request querying Organization B's findings.
  - *Mitigation*: Every endpoint extracts the authenticated user's `organization_id` from validated JWT claims. `check_tenant_isolation` immediately aborts with `403 Forbidden` if a requested entity does not match the token's organization.
- **Information Disclosure**: Leaking findings across tenants via bulk queries or global searches.
  - *Mitigation*: All database queries and in-memory filters apply `WHERE organization_id = :org_id` before evaluating any user-provided filters.

### 3.3 Evidence Collection & Log Sanitization
- **Information Disclosure**: Configuration dumps containing access keys, database passwords, private certificates, or session tokens.
  - *Mitigation*: Automated recursive evidence redaction replaces values matching known credential regexes (`password`, `secret`, `access_key`, `token`, `bearer`, `private_key`) with `[REDACTED]`.

### 3.4 Outbound Webhooks & Alert Notification
- **Tampering / Replay**: Intercepting outbound alerts and replaying them to trigger false incident escalations.
  - *Mitigation*: Outbound payloads are signed using HMAC-SHA256 (`AlertingEngine::sign_payload`) using a pre-shared secret. Payloads contain delivery timestamps and unique UUIDv4 `idempotency_key` headers.
- **Information Disclosure**: Webhook destination secrets leaked via the API.
  - *Mitigation*: Webhook secrets are stored encrypted. The `GET /api/alerts/destinations` endpoint never returns the plaintext secret.

### 3.5 Generated Remediation Guidance
- **Tampering / Command Injection**: Injecting malicious shell or Terraform syntax via cloud resource names (e.g., bucket name `my-bucket; rm -rf /`).
  - *Mitigation*: `sanitize_input` strips all shell and HCL control characters (`;`, `&`, `|`, `$`, `>`, `<`, `` ` ``, `\n`, `\r`, `/`), permitting only alphanumeric characters and safe delimiters (`-`, `_`, `.`, `:`, `@`).
- **Elevation of Privilege**: Automatic application of untested infrastructure changes.
  - *Mitigation*: Automated remediation execution is completely disabled. Remediations are strictly generated as parameterized recommendations requiring manual review, ticket tracking, and explicit administrative approval.

### 3.6 Reports Export
- **Tampering**: Altering compliance scores on generated reports.
  - *Mitigation*: Exported reports contain immutable generation timestamps, cryptographic finding counts, formula versions, and partial-data watermarks when scans encounter access limitations.

### 3.7 Worker Queues & Job Execution
- **Denial of Service / Race Conditions**: Multiple workers picking up the same scan job and overloading cloud provider rate limits.
  - *Mitigation*: Lease-based distributed locking (`DistributedWorkerQueue`) with time-to-live expiration guarantees mutual exclusion across workers. Resumable checkpointing prevents re-running completed scan stages upon restart.

---

## 4. Security Verification Checklist

| Security Control | Implementation Mechanism | Verification Test |
| :--- | :--- | :--- |
| **Transport Security** | TLS 1.3 enforced for API, DB, and cloud outbound | Automated in reverse proxy and client connections |
| **Encryption at Rest** | AES-256-GCM with unique 12-byte nonces | `crypto::tests::test_encryption_and_decryption_roundtrip` |
| **Tamper Detection** | Authenticated ciphertext tags | `crypto::tests::test_decryption_tamper_detection` |
| **Credential Redaction** | `redact_sensitive_value` recursive dictionary scrub | `tests::finding_evidence_and_connection_secrets_are_strictly_redacted` |
| **Static Key Rejection** | Onboarding validation checks against long-lived keys | `tests::aws_onboarding_rejects_static_long_lived_keys` |
| **Tenant Isolation** | Multi-tenant claim checks in auth middleware | `tests::tenant_isolation_strictly_enforced` |
| **Role-Based Access** | Role permission matrix (`Admin`, `Engineer`, etc.) | `tests::role_based_authorization_enforced` |
| **Command Injection Guard** | Regex-based input sanitizer for CLI & HCL templates | `remediation::tests::input_sanitizer_removes_dangerous_metacharacters` |
| **Webhook Integrity** | HMAC-SHA256 signature verification | `alerting::tests::hmac_sha256_signs_payloads_deterministically` |
| **Worker Concurrency** | Lease locking with TTL check | `tests::lease_locking_prevents_duplicate_acquisition` |
| **State File Drift** | Secure parsing of Terraform state attributes | `drift::tests::parses_terraform_state_and_identifies_live_drift` |

