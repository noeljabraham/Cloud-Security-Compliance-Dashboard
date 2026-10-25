# Release 1 Definition

Status: approved project baseline  
Decision date: 2026-10-25  
Release name: MVP

## Goal

Release 1 proves the complete assessment loop: securely connect one account from each supported cloud, collect configuration metadata with read-only access, produce normalized findings, map those findings to compliance controls, show current and historical posture, recommend fixes, export reports, and notify a webhook.

This release is a self-hosted, non-commercial learning deployment for one organization. It is an assessment aid, not a certification product or a substitute for an auditor.

## Deployment model

- One organization per installation.
- Self-hosted as a modular monolith: Rust API/worker, React dashboard, and PostgreSQL.
- One deployment region selected by the operator. The database, backups, logs, and exported reports remain in that region/jurisdiction.
- Cloud access is read-only. Release 1 can display and download remediation commands but cannot execute them.
- One AWS account, one Azure subscription, and one GCP project are supported. Organization-wide onboarding is deferred.
- Daily scheduled scans and on-demand scans are supported. Hourly schedules are deferred.

## Framework baseline

The implementation must pin mappings to these versions; upgrades require a mapping review and a new mapping version:

| Framework | Release 1 baseline | Use in Release 1 |
| --- | --- | --- |
| CIS Amazon Web Services Foundations Benchmark | 7.1.0 | Primary AWS technical baseline |
| CIS Microsoft Azure Foundations Benchmark | 6.0.0 | Primary Azure technical baseline |
| CIS Google Cloud Platform Foundation Benchmark | 5.0.0 | Primary GCP technical baseline |
| AICPA Trust Services Criteria | 2017 criteria, revised points of focus 2022 | Supporting mappings for Security and, where directly evidenced, Availability and Confidentiality |
| HIPAA Security Rule | 45 CFR Part 160 and Part 164, Subparts A and C, rule in effect on 2026-10-25 | Supporting mappings for technical safeguards; the 2025 proposed rule is excluded until effective |
| PCI DSS | 4.0.1 | Supporting mappings for cloud configuration requirements |

The selected CIS versions were verified against the [CIS benchmark catalog](https://www.cisecurity.org/cis-benchmarks). The SOC 2 baseline is the [AICPA 2017 Trust Services Criteria with revised points of focus (2022)](https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022). The HIPAA scope follows the [HHS description of the currently effective Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html). PCI DSS 4.0.1 is listed in the [PCI SSC document library](https://www.pcisecuritystandards.org/document_library/).

Only controls backed by collected technical evidence are scored. Organizational, procedural, and physical controls appear as `not_assessed`; they are never inferred as passing.

## Supported cloud scope

### AWS

- Region: `us-east-1`, plus global IAM metadata.
- Services: S3, IAM, EC2/VPC security groups, and CloudTrail.
- Initial checks:
  - S3 Block Public Access is enabled.
  - S3 default encryption is enabled.
  - Root user MFA is enabled.
  - Customer-managed IAM policies do not grant wildcard administrative access.
  - Security groups do not expose TCP 22 or 3389 to `0.0.0.0/0` or `::/0`.
  - A multi-region CloudTrail trail records management events.
  - CloudTrail log-file validation is enabled.

### Azure

- Region: `eastus`, plus subscription-level RBAC metadata.
- Services: Storage Accounts, Azure RBAC, Network Security Groups, and Key Vault.
- Initial checks:
  - Anonymous public blob access is disabled.
  - Secure transfer is required for Storage Accounts.
  - Owner assignments directly granted to users at subscription scope are reported.
  - NSG rules do not expose TCP 22 or 3389 to the internet.
  - Key Vault public network access is disabled.
  - Key Vault purge protection is enabled.

### GCP

- Region: `us-central1`, `US` multi-region buckets, plus project-level IAM metadata.
- Services: Cloud Storage, IAM, Compute Engine firewalls, and Cloud Audit Logs.
- Initial checks:
  - Buckets do not grant access to `allUsers` or `allAuthenticatedUsers`.
  - Uniform bucket-level access is enabled.
  - Project IAM does not grant roles to public principals.
  - Primitive Owner or Editor roles granted to users are reported.
  - Firewall rules do not expose TCP 22 or 3389, or all protocols, to `0.0.0.0/0` or `::/0`.
  - Data Access audit logging is enabled for supported services.

Resources outside the listed regions are reported as `not_scanned`, not compliant. Access-denied or throttled checks are coverage gaps, not passes.

## Compliance profiles

- `production-strict`: every implemented security and durability check is scored; exceptions require recorded approval and expiry.
- `development-relaxed`: identity, public exposure, encryption, audit logging, and credential checks remain fully enforced. Durability and cost-only checks may be advisory and do not affect the score.

Release 1 defaults to `production-strict`.

## Roles

| Capability | Admin | Security reviewer | Engineer | Executive |
| --- | :---: | :---: | :---: | :---: |
| Manage users, roles, connections, and retention | Yes | No | No | No |
| Start or cancel scans | Yes | Yes | Yes | No |
| View resources, evidence, findings, and recommendations | Yes | Yes | Yes | Summary only |
| Assign findings and update remediation progress | Yes | Yes | Yes | No |
| Approve/reject exceptions and remediations | Yes | Yes | No | No |
| View executive scores and trends | Yes | Yes | Yes | Yes |
| Export technical reports | Yes | Yes | Yes | No |
| Export executive reports | Yes | Yes | No | Yes |
| View audit log | Yes | Yes | No | No |

The API enforces these permissions; hiding a dashboard control is not authorization.

## Finding and remediation states

Finding states:

- `open`: currently observed and requires review or remediation.
- `resolved`: absent from a later successful scan that covered the same resource and check.
- `accepted_risk`: an authorized reviewer accepted the finding until a required expiry date.
- `suppressed`: an authorized reviewer documented a false positive or duplicate until a required expiry date.

A resolved finding observed again returns to `open` and records a `reopened` history event. Partial or failed scans never resolve findings.

Remediation states:

- `proposed`, `approved`, `rejected`, `in_progress`, `completed`, `failed`, `rolled_back`.

Only an admin or security reviewer can approve or reject a remediation. Release 1 records workflow state but never runs the proposed command.

## Severity and risk scoring

Each check has a reviewed base severity. A finding receives a deterministic 0–100 risk score:

| Base severity | Starting score |
| --- | ---: |
| Critical | 90 |
| High | 70 |
| Medium | 45 |
| Low | 20 |
| Informational | 0 |

Apply these evidence-based modifiers once each, then clamp the result to 0–100:

- `+10` when the resource is directly reachable from the public internet.
- `+10` for wildcard administrative/owner permissions.
- `+5` when the resource carries a `data_classification=sensitive` or `data_classification=restricted` tag/label.
- `-10` for an active, approved compensating-control exception.

Display bands are Critical `90–100`, High `70–89`, Medium `40–69`, Low `1–39`, and Informational `0`. Missing tags do not imply sensitive or non-sensitive data. Compliance scores and risk scores are separate values.

## Retention

| Data | Retention after creation or final state |
| --- | --- |
| Normalized resources, findings, scan runs, and score snapshots | 24 months |
| Minimum evidence required to explain a finding | 90 days after resolution; retained while open |
| Cost and optimization data | 13 months |
| Audit events, exception decisions, remediation approvals, and generated report metadata | 7 years |
| Generated report files | 90 days |
| Failed webhook payloads and delivery logs | 30 days |
| Disabled connection credentials/tokens | Revoke and delete immediately |

Release 1 does not retain complete raw provider API responses. Retention cleanup must be auditable, and legal holds override deletion.

## Data residency, privacy, and secrets

- Store only cloud resource metadata and the minimum configuration evidence required to explain a check result.
- Do not collect object contents, database records, VM disk contents, source code, ePHI, payment card data, or application payloads.
- Treat account IDs, resource names, IP addresses, tags, configurations, findings, costs, and reports as confidential customer data.
- Encrypt database, backups, report storage, and secrets at rest; require TLS in transit.
- Use short-lived federation/role assumption where available. Never store AWS access keys, downloaded GCP service-account keys, or Azure client secrets in the database.
- Keep secrets in the deployment's secret store, redact them from logs/errors/exports, and never expose them through the API after creation.
- Keep primary data, backups, and logs in the operator-selected jurisdiction. No cross-region replication is enabled by default.
- Tenant isolation remains mandatory even though the MVP supports one organization, so future expansion cannot expose data through unscoped queries.
- Audit authentication, connection changes, scans, exports, exception decisions, and remediation decisions without logging tokens or raw authorization headers.

## Content licensing policy

This repository is a non-commercial learning project. CIS states that its benchmark PDFs are available for non-commercial use under its [non-member terms](https://www.cisecurity.org/terms-of-use-for-non-member-cis-products). Release 1 therefore:

- stores framework name, version, control identifier, original check logic, and an original short mapping rationale;
- links users to the framework publisher instead of bundling benchmark PDFs or reproducing control text;
- does not use certification marks or claim that the platform or a customer is certified/compliant;
- requires a fresh license and legal review before any commercial distribution, hosted service, or copied control content;
- keeps AICPA and PCI source documents outside the repository unless their applicable terms expressly allow redistribution.

The source owner remains authoritative. A mapping is technical guidance, not legal advice or an auditor's conclusion.

## MVP acceptance test

Run this scenario in staging with dedicated test cloud accounts containing both conforming and deliberately misconfigured resources.

### Preconditions

- [ ] The service is deployed in one region with TLS, encrypted PostgreSQL storage, backups, and a configured secret store.
- [ ] Test users exist for all four roles.
- [ ] One read-only AWS role, Azure identity, and GCP workload identity are available.
- [ ] Each cloud contains at least one passing and one failing resource for its initial checks.
- [ ] A local webhook receiver is ready and records signatures and idempotency keys.

### Scenario

- [ ] An admin connects the AWS account, Azure subscription, and GCP project without persisting long-lived credentials.
- [ ] An engineer starts a scan; the UI shows provider/account progress, completion, and any coverage gaps.
- [ ] The scan evaluates every initial check and stores normalized resources, evidence, findings, framework mappings, and score snapshots.
- [ ] The dashboard shows overall and per-provider scores, coverage, severity counts, data freshness, and the selected compliance profile.
- [ ] An executive sees only summary posture, trends, top risks, and executive report export.
- [ ] An engineer drills into a finding and sees redacted evidence, mapped controls, history, effort, Terraform guidance, and a CLI recommendation.
- [ ] An engineer cannot approve a remediation; a security reviewer can approve or reject it; neither action executes cloud changes.
- [ ] A second scan resolves a corrected finding, preserves unchanged findings, and does not resolve findings in an intentionally incomplete scan.
- [ ] The dashboard trend compares the two successful scans and shows the score and finding-count change.
- [ ] A new critical finding sends one signed, redacted webhook event; retrying delivery uses the same idempotency key.
- [ ] Technical and executive reports export with framework versions, profile, scope, coverage gaps, timestamps, and compliance disclaimers.
- [ ] Cross-role API tests deny unauthorized actions, and a log/export review finds no credentials, authorization headers, or collected workload content.

### Pass condition

Every scenario item passes, no critical security defect remains open, and results can be reproduced from the same fixtures and pinned mapping versions.

## Explicitly deferred

- More than one organization or broad organization/management-group/folder onboarding.
- Regions other than the three listed above.
- The remaining services and the 200+ control target.
- Automatic remediation execution.
- Hourly/event-driven scans, PagerDuty, Terraform-state comparison, advanced cost-of-risk modeling, and production-scale partitioning.
- Claims of certification or complete compliance with any framework.

