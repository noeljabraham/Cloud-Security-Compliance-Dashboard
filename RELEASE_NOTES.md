# Release Notes - CloudSec v0.1.0 (MVP)

**Release Tag:** `v0.1.0`  
**Release Date:** 2026-10-25  
**Baseline Status:** Approved Production MVP  

---

## 1. Executive Summary

CloudSec v0.1.0 delivers a multi-cloud security posture management (CSPM) and compliance scoring platform. It provides continuous compliance monitoring against CIS Benchmarks, SOC 2 Type II, PCI-DSS v4.0, and HIPAA across Amazon Web Services (AWS), Microsoft Azure, and Google Cloud Platform (GCP).

---

## 2. Feature Matrix

### Multi-Cloud Onboarding & Connectivity
- **AWS**: STS AssumeRole with external ID validation (`ext-id-...`) and managed policy auditing. Rejects static IAM user access keys.
- **Azure**: Azure AD App Registration / Service Principal with Directory Reader and Reader roles. Rejects expired client secrets.
- **GCP**: Project-level IAM binding with service accounts and Workload Identity Federation. Rejects embedded private key files.
- **Security**: All credential secrets are stored using AES-256-GCM authenticated encryption with dual-key rotation fallback.

### Comprehensive Assessment & Compliance Scoring
- **Automated Checks**: Evaluates S3 Public Access, S3 Default Encryption, Root MFA & Credentials, Azure Storage Public Access, Azure HTTPS Only, GCP Storage Public IAM, and GCP Cloud SQL Public IP.
- **Mathematical Scoring Formula**: Weighted aggregation across frameworks with dedicated coverage gap tracking. Suppressed or accepted risks never silently pass.
- **Profiles**: Strict Production (full penalty) and Relaxed Development (suppression-tolerant).

### React 19 Operator Dashboard
- **Executive View**: SVG score gauge, 7-day posture trend, findings breakdown, compliance progress cards, cost-of-risk exposure ($), and waste optimization savings ($).
- **Engineer View**: Faceted multi-cloud search, bulk status transitions (Accept Risk, False Positive), finding drawer with copyable Terraform HCL and CLI commands.
- **Geographic View**: Interactive SVG world map plotting regional footprints across `us-east-1`, `us-west-2`, `eastus`, `westeurope`, `us-central1`, and `asia-east1`.
- **Accessibility**: Full keyboard navigation, screen reader live announcements (`aria-live="polite"`), and high-contrast mode conforming to WCAG AA.

### Continuous Monitoring, Drift & Alerting
- **Distributed Worker Queue**: Lease-based locking (`try_acquire_lease`) to prevent duplicate concurrent runs across worker restarts.
- **Resumable Checkpoints**: Multi-stage checkpoints (`Discovery`, `Evaluation`, `Scoring`, `Alerting`) allowing crashed workers to resume without redundant API queries.
- **Terraform Drift Detection**: Compares live cloud state with uploaded Terraform v4 `.tfstate` files.
- **Baseline Promotion**: Promotion of last-known-good posture with regression tracking.
- **Signed Outbound Alerts**: HMAC-SHA256 signed webhooks, Slack Block Kit messages, and PagerDuty Events API v2 integration.
- **Multi-Format Export**: PDF, CSV, Markdown, and JSON audit packages with partial-data watermarks.

### Reliability & Operations
- **SLO Telemetry**: Real-time tracking of API availability (99.9%), scan latency (p95 < 10m), data freshness (<24h), and alert delivery (99.5%).
- **Retention Cleanup**: Automated purging of expired scan data with dry-run support and audit logging.
- **Infrastructure as Code**: Terraform modules for production AWS deployment (VPC, RDS PostgreSQL, KMS, Secrets Manager).

---

## 3. Known Limitations & Scope Disclaimers

1. **Remediation Execution**: Release 1 generates parameterized CLI commands and Terraform snippets as recommendations. Automated execution is intentionally disabled in this release.
2. **Account Scope**: Release 1 supports single AWS accounts, Azure subscriptions, and GCP projects per connection. Multi-account organizational tree discovery (AWS Organizations / GCP Folders) is scheduled for v0.2.0.
3. **Compliance Scope**: Technical checks evaluate cloud infrastructure configuration only. Non-technical controls (personnel policies, physical site audits) must be assessed out-of-band by certified auditors.

