# Cloud Security Compliance Dashboard — TODO

This checklist is ordered by dependency. Complete each milestone's acceptance criteria before moving to the next one.

> Compliance note: this platform can collect evidence and assess technical controls, but it does not by itself certify CIS, SOC 2, HIPAA, or PCI DSS compliance. Validate control text, mappings, and report language with qualified compliance and legal reviewers before production use.

## 0. Define the first release

- [x] Choose the MVP deployment model: one organization, self-hosted, read-only cloud access. See [`docs/release-1.md`](docs/release-1.md).
- [x] Choose supported framework versions and record them explicitly (CIS AWS/Azure/GCP, SOC 2, HIPAA, PCI DSS).
- [x] Define the first supported regions and services for each cloud.
- [x] Define user roles: `admin`, `security_reviewer`, `engineer`, and `executive`.
- [x] Define severity levels, finding states, remediation states, and risk-scoring rules.
- [x] Decide retention periods for findings, scan evidence, audit events, and cost data.
- [x] Document data residency, privacy, and secrets-handling requirements.
- [x] Confirm licensing permits using the selected benchmark/control content; store references rather than copying restricted text when required.
- [x] Write an MVP acceptance test: connect one account per provider, run scans, view findings and scores, compare two scans, export a report, and send a test webhook.

## 1. Bootstrap the repository

- [x] Create a Cargo workspace for the Rust API, workers, scanners, and shared domain crates.
- [x] Create a React + TypeScript application for the dashboard.
- [x] Add PostgreSQL and a migration tool.
- [x] Add local development services with Docker Compose.
- [x] Add `.env.example` containing safe placeholders only.
- [x] Add `.gitignore`, `rustfmt`, Clippy, frontend formatting/linting, and test commands.
- [x] Add a `Makefile` or task runner with `dev`, `test`, `lint`, `migrate`, and `build` targets backed by Cargo and the frontend package manager.
- [x] Add CI for Cargo tests, `rustfmt`, Clippy, frontend tests, builds, migration validation, dependency scanning, and secret scanning.
- [x] Add a short architecture decision record explaining the initial modular-monolith design.
- [x] Document local setup and the minimum supported Rust, Node.js, PostgreSQL, and Terraform versions.

## 2. Design the core domain and database

- [x] Define stable IDs and schemas for organizations, users, roles, cloud connections, accounts/projects/subscriptions, and regions.
- [x] Define a normalized resource model with provider-native ID, type, name, tags/labels, region, account, and captured configuration.
- [x] Define a normalized finding model with check ID, resource ID, severity, status, evidence, first/last seen timestamps, and fingerprint.
- [x] Define check metadata with provider, service, category, version, remediation, and framework mappings.
- [x] Define scan runs and per-account scan jobs with status, timing, errors, coverage, and scanner version.
- [x] Define immutable finding observations/snapshots for historical tracking.
- [x] Define framework, framework version, control, profile, and check-to-control mapping tables.
- [x] Define score snapshots by organization, provider, account, framework, service/category, and time.
- [x] Define costs, cost periods, optimization opportunities, risk estimates, and currencies.
- [x] Define remediation recommendations, approvals, executions, evidence, owners, and status history.
- [x] Define drift events, alert deliveries, reports, and audit log records.
- [x] Decide which raw provider responses must be retained; encrypt sensitive evidence and avoid storing secrets.
- [x] Add database constraints and indexes for tenant isolation, finding fingerprints, scan history, and dashboard queries.
- [x] Add migrations plus repository/integration tests for core queries.

## 3. Build the scanner framework

- [x] Define a small async Rust provider trait for authentication validation, resource discovery, assessment, and capability reporting.
- [x] Define a Rust check trait that returns normalized findings and evidence without provider-specific UI logic.
- [x] Add a provider registry for AWS, Azure, and GCP implementations.
- [x] Build a scan orchestrator that fans out by account and region with bounded concurrency.
- [x] Add provider-specific rate limiting, pagination, retry with jitter, timeout, and cancellation handling.
- [x] Distinguish permission failures, throttling, unsupported regions/services, partial scans, and internal failures.
- [x] Persist scan progress and support safe retries without duplicating findings.
- [x] Generate deterministic resource IDs and finding fingerprints.
- [x] Mark findings resolved only after a successful scan covered the same resource and check.
- [x] Record coverage gaps so missing permissions never appear as a passing result.
- [x] Add structured logging, metrics, tracing IDs, and health/readiness endpoints.
- [x] Add fake provider clients and unit tests for normalization, retry behavior, partial scans, and deduplication.

### Milestone: vertical slice

- [x] Implement one read-only check for one provider end to end.
- [x] Store the resource, finding, evidence, scan status, and score.
- [x] Expose it through the API and render it in the dashboard.
- [x] Confirm tenant isolation and verify that logs contain no credentials or sensitive provider responses.

## 4. Implement secure cloud onboarding

### AWS

- [x] Use cross-account IAM roles with external IDs; do not accept long-lived access keys for production onboarding.
- [x] Create a least-privilege read-only IAM policy and deployment template.
- [x] Validate role assumption, account identity, enabled regions, and required permissions.
- [x] Document AWS Organizations onboarding for multiple accounts.

### Azure

- [x] Use workload identity/service principals with least-privilege Reader-style permissions.
- [x] Validate tenant, subscription access, token acquisition, and required resource-provider permissions.
- [x] Document management-group onboarding for multiple subscriptions.

### GCP

- [x] Prefer workload identity federation and service-account impersonation over stored JSON keys.
- [x] Validate organization/folder/project access and required IAM permissions.
- [x] Document organization-wide and multi-project onboarding.

### Shared security requirements

- [x] Encrypt connection metadata and tokens at rest using a managed key service.
- [x] Never return secrets through APIs or include them in logs, errors, findings, exports, or support bundles.
- [x] Add credential rotation, connection disable/delete, and connectivity-test flows.
- [x] Record all connection and permission changes in an immutable audit log.
- [x] Add negative tests for cross-tenant access and insufficient provider permissions.

## 5. Implement AWS assessments

### S3

- [x] Check account- and bucket-level public access blocks.
- [x] Check bucket policies and ACLs for public or cross-account exposure.
- [x] Check default encryption and approved KMS keys.
- [x] Check access logging or approved data-event monitoring.
- [x] Check versioning and lifecycle configuration where required by profile.

### IAM

- [x] Check root MFA and root access-key usage where the available API permits it.
- [x] Check console users for MFA and password-policy compliance.
- [x] Check inactive users, old access keys, and unused credentials.
- [x] Detect wildcard and high-risk actions/resources in users, groups, roles, and policies.
- [x] Detect risky trust policies and excessive cross-account access.

### EC2 and VPC

- [x] Detect security-group ingress open to the internet on administrative or database ports.
- [x] Detect unrestricted ingress/egress according to the selected profile.
- [x] Identify unused security groups and stale rules without assuming deletion is safe.
- [x] Check IMDSv2 enforcement and EBS encryption where supported.
- [x] Check VPC flow logs.
- [x] Check default security groups for non-default rules.
- [x] Identify unattached public IP addresses for cost/security optimization.

### RDS

- [x] Check public accessibility and network exposure.
- [x] Check storage encryption and approved KMS keys.
- [x] Check automated backup retention and deletion protection.
- [x] Check engine/version policy and logging requirements.

### CloudTrail and logging

- [x] Check for an enabled multi-region trail covering management events.
- [x] Check log-file validation, encryption, and secure destination bucket controls.
- [x] Check CloudWatch integration and required alerting controls.

### Lambda

- [x] Check execution roles for excessive permissions.
- [x] Check public function URLs and resource policies.
- [x] Check VPC attachment only when required by policy; do not treat it as universally safer.
- [x] Check environment encryption and supported runtime policy.

- [x] Map every AWS check to versioned CIS controls and applicable cross-framework controls.
- [x] Add fixtures for pass, fail, not-applicable, access-denied, and malformed provider responses.
- [x] Add tests using mocked Rust SDK client traits; add optional integration tests against a dedicated sandbox account.

## 6. Implement Azure assessments

### Storage Accounts

- [x] Check public blob/container exposure and anonymous access.
- [x] Check secure transfer, minimum TLS, firewall/network access, and private endpoints where required.
- [x] Check encryption and customer-managed keys according to profile.
- [x] Check diagnostic logging and retention.

### RBAC and Microsoft Entra ID

- [x] Detect owner/contributor assignments that are broad, stale, or assigned directly to users.
- [x] Detect custom roles with wildcard or high-risk permissions.
- [x] Check privileged-role governance, MFA/conditional-access evidence, and guest access where APIs and licensing permit.
- [x] Report unavailable identity checks as coverage gaps, not passes.

### Network Security Groups

- [x] Detect internet-exposed administrative, database, and all-port rules.
- [x] Detect overly broad source/destination ranges and stale rules.

### Key Vault

- [x] Check public network access, firewall/private endpoint configuration, and RBAC/access policies.
- [x] Check soft delete, purge protection, logging, and key/secret expiration policies.

- [x] Map every Azure check to versioned CIS controls and applicable cross-framework controls.
- [x] Add pass/fail/not-applicable/access-denied fixtures and mocked Rust SDK client tests.
- [x] Add optional integration tests against a dedicated sandbox subscription.

## 7. Implement GCP assessments

### Cloud Storage

- [x] Detect `allUsers` and `allAuthenticatedUsers` IAM bindings.
- [x] Check uniform bucket-level access and public-access prevention.
- [x] Check encryption/key policy, logging, versioning, and retention according to profile.

### Compute Engine and VPC

- [x] Detect firewall rules open to the internet on administrative, database, or all ports.
- [x] Detect broad target scope, disabled logging, and risky default-network usage.
- [x] Check external IP exposure and identify unused addresses.

### Cloud SQL

- [x] Check public IP and authorized-network exposure.
- [x] Check encryption/key policy, backups, point-in-time recovery, deletion protection, and database flags.

### IAM and audit logging

- [x] Detect primitive/basic roles and overly broad custom roles.
- [x] Detect public principals, stale service-account keys, and risky service-account impersonation.
- [x] Check Data Access audit logs, required exclusions, retention, and log sinks.

- [x] Map every GCP check to versioned CIS controls and applicable cross-framework controls.
- [x] Add pass/fail/not-applicable/access-denied fixtures and mocked Rust SDK client tests.
- [x] Add optional integration tests against a dedicated sandbox project.

## 8. Build the compliance mapping and scoring engine

- [x] Store checks and mappings as versioned data, separate from scanner code where practical.
- [x] Add mappings for CIS, SOC 2 Trust Services Criteria, HIPAA Security Rule, and PCI DSS.
- [x] Record mapping rationale and evidence requirements; distinguish direct, partial, and supporting mappings.
- [x] Support strict production and relaxed development profiles through explicit check applicability/weights.
- [x] Define score math before implementation, including treatment of severity, not-applicable checks, exceptions, coverage gaps, and partial scans.
- [x] Calculate scores per framework, provider, account/project/subscription, service/category, and organization.
- [x] Keep coverage/confidence separate from the compliance score.
- [x] Version score formulas so historical scores remain reproducible.
- [x] Prevent accepted risk or suppressed findings from silently becoming passes.
- [x] Add golden test datasets with hand-calculated expected scores.
- [x] Add a control-coverage report showing implemented, unavailable, and unimplemented controls.
- [x] Expand to 200+ CIS checks only after the metadata format, fixtures, and scoring tests are stable.

## 9. Build the API and authorization layer

- [x] Implement authentication using an OIDC provider; avoid building password storage unless required.
- [x] Enforce organization scoping and role-based authorization on every endpoint and background job.
- [x] Add endpoints for connections, accounts, scan runs, resources, findings, evidence, scores, trends, costs, remediations, drift, reports, and audit logs.
- [x] Add filtering, sorting, pagination, and stable response schemas.
- [x] Add scan start/cancel/status endpoints with idempotency and concurrency protection.
- [x] Add exception/risk-acceptance workflows with owner, reason, expiry, and approval.
- [x] Add remediation approval and status-transition endpoints.
- [x] Add report generation and secure download endpoints.
- [x] Generate and publish an OpenAPI specification.
- [x] Add request validation, safe error responses, rate limits, CORS/CSRF protections as applicable, and security headers.
- [x] Add API tests for role permissions, tenant isolation, pagination, invalid transitions, and data redaction.

## 10. Build the React dashboard

### Shared application shell

- [x] Add OIDC login/logout, protected routes, and role-aware navigation.
- [x] Add provider/account/profile/time-range filters shared through URL state.
- [x] Add loading, empty, partial-data, permission-error, and failure states.
- [x] Meet keyboard navigation, focus, contrast, labeling, and screen-reader accessibility requirements.

### Executive view

- [x] Show overall posture, framework scores, coverage, critical findings, and change since the previous period.
- [x] Show provider and business-unit/account comparisons.
- [x] Add trend charts for scores, open/closed findings, and remediation velocity.
- [x] Show high-risk/high-cost exposure and top recommended actions.
- [x] Add concise explanations of score scope and data freshness.

### Engineer view

- [x] Add a risk-prioritized findings table with provider, service, resource, severity, age, owner, and status.
- [x] Add drill-down by provider, account/project/subscription, region, service, check, and control.
- [x] Add finding details with evidence, affected controls, history, estimated effort, Terraform, and CLI recommendations.
- [x] Add bulk assignment and status updates without bulk execution of remediations.
- [x] Add resource inventory and resource history views.

### Geographic view

- [x] Show regional resource/finding counts on a geographic map.
- [x] Handle global resources and unknown/custom regions separately.
- [x] Provide an accessible tabular alternative to the map.

- [x] Add component tests for critical states and end-to-end tests for executive and engineer journeys.
- [x] Test layouts at common desktop and tablet sizes.

## 11. Add remediation recommendations

- [x] Define versioned remediation templates linked to checks and provider/resource types.
- [x] Generate Terraform snippets that use safe placeholders and preserve required existing configuration.
- [x] Generate provider CLI commands with explicit account/project/subscription and region context.
- [x] Add preventive examples such as policy-as-code, organization policies, Azure Policy, and AWS controls where applicable.
- [x] Clearly label generated code as a recommendation requiring review and testing.
- [x] Estimate effort using a simple documented scale.
- [x] Require security-team approval before any execution status can begin.
- [x] Track requested, approved, rejected, in-progress, completed, failed, and rolled-back states.
- [x] Capture approver, timestamps, change/ticket reference, output, and post-change verification evidence.
- [x] Sanitize all template inputs to prevent code/command injection.
- [x] Add snapshot tests for Terraform and CLI output.
- [x] Keep automatic execution disabled in the first release; provide copy/download workflows only.

## 12. Add cost-security optimization

- [x] Ingest AWS Cost Explorer, Azure Cost Management, and GCP billing-export data with least-privilege access.
- [x] Normalize costs by resource, account, service, region, period, and currency when provider data permits.
- [x] Record allocation confidence for costs that cannot be tied directly to a resource.
- [x] Correlate findings with costs using stable provider resource IDs.
- [x] Flag expensive resources with high/critical exposure.
- [x] Detect security improvements with likely savings, such as unused public IPs and idle exposed resources.
- [x] Treat right-sizing as a recommendation based on utilization data, not billing data alone.
- [x] Define and document a cost-of-risk model; keep estimated exposure separate from actual spend.
- [x] Show calculation inputs and confidence instead of presenting estimates as facts.
- [x] Add tests for missing costs, shared costs, currencies, partial periods, and unallocated resources.

## 13. Add continuous monitoring and drift detection

- [x] Add per-connection hourly/daily schedules with time zone, enable/disable, and overlap protection.
- [x] Use a durable job queue and distributed lock so restarts do not lose or duplicate scans.
- [x] Compare successful scan snapshots to detect new, changed, resolved, and reopened findings.
- [x] Define the last-known-good baseline and allow authorized users to promote a scan to baseline.
- [x] Suppress alerts for incomplete scans and surface the coverage failure separately.
- [x] Parse supported Terraform state versions and map managed resource addresses to cloud resource IDs.
- [x] Encrypt Terraform state at rest and redact sensitive attributes before persistence or display.
- [x] Detect live-vs-state differences while accounting for ignored/computed fields and provider normalization.
- [x] Add fixture-based tests for drift additions, updates, deletions, missing permissions, and sensitive values.
- [x] Add trend snapshots and calculate remediation velocity, mean age, reopen rate, and score change.

## 14. Add alerting and reporting

- [x] Define alert rules for new critical findings, regressions, drift, scan failures, and coverage loss.
- [x] Add signed outbound webhooks with retries, exponential backoff, idempotency keys, and delivery history.
- [x] Add Slack webhook formatting.
- [x] Add PagerDuty Events API formatting and deduplication keys.
- [x] Store alert endpoints as encrypted secrets and redact them everywhere else.
- [x] Add test-delivery, disable, rotate, and delete flows.
- [x] Generate technical reports with findings, evidence, mappings, owners, and remediation status.
- [x] Generate executive reports with posture, trends, material risks, coverage, and priorities.
- [x] Support CSV and PDF export with organization, framework version, profile, scan range, and generation timestamp.
- [x] Clearly mark partial/incomplete data in exports.
- [x] Add golden tests for alert payloads and report contents.

## 15. Security hardening

- [x] Create a threat model covering cloud credentials, tenant boundaries, evidence, webhooks, generated commands, reports, and worker queues.
- [x] Enforce TLS in transit and managed encryption at rest.
- [x] Use a secrets manager and short-lived workload identity for the platform itself.
- [x] Apply least privilege to database, queue, object storage, deployment, and cloud-scanning identities.
- [x] Validate and sanitize all external input, uploaded Terraform state, filters, templates, and webhook configuration.
- [x] Add strict tenant filters and authorization checks at service and data-access boundaries.
- [x] Add audit logging for authentication, connections, scans, exceptions, approvals, exports, and administrative actions.
- [x] Add dependency, container, IaC, SAST, secret, and license scanning to CI.
- [x] Add backup/restore procedures and test restoration.
- [x] Define incident response, credential revocation, key rotation, vulnerability handling, and data deletion procedures.
- [x] Run a focused penetration test before exposing the platform to production credentials.

## 16. Reliability, scale, and operations

- [x] Set service-level objectives for API availability, scan completion, data freshness, and alert delivery.
- [x] Add metrics for queue depth, scan duration, provider throttles, API errors, coverage, database latency, and alert failures.
- [x] Add dashboards and alerts for the platform itself.
- [x] Make scan jobs idempotent and resumable where practical.
- [x] Load-test the API and workers using realistic account/resource counts.
- [x] Test provider throttling and outage behavior.
- [x] Add database partitioning/archival only after measurements show it is necessary.
- [x] Add retention cleanup jobs with dry-run and audit output.
- [x] Document deployment, upgrade, rollback, backup, restore, and disaster-recovery runbooks.
- [x] Add infrastructure as code for development, staging, and production environments.
- [x] Validate zero-downtime or explicitly scheduled migration behavior.

## 17. Documentation and release

- [x] Write architecture, data-flow, trust-boundary, and deployment diagrams.
- [x] Document every provider permission and why it is needed.
- [x] Document check authoring, test fixtures, control mapping, scoring, and remediation template formats.
- [x] Document onboarding and troubleshooting for AWS, Azure, and GCP.
- [x] Document score limitations, coverage gaps, false-positive handling, and framework disclaimers.
- [x] Publish API documentation and example requests.
- [x] Add a demo dataset that contains no real cloud identifiers or secrets.
- [x] Run the complete MVP acceptance test in staging.
- [x] Have security and compliance reviewers approve production-facing permissions, mappings, wording, and reports.
- [x] Tag the release, publish release notes, and record known limitations.

## Definition of done for each security check

- [x] Stable check ID, title, severity, provider, service, resource type, and supported profile(s).
- [x] Versioned framework mappings and mapping rationale.
- [x] Exact API permissions and coverage limitations documented.
- [x] Deterministic evaluation and finding fingerprint.
- [x] Evidence that explains the result without exposing secrets.
- [x] Pass, fail, not-applicable, access-denied, throttled, and malformed-response behavior defined.
- [x] Terraform and CLI recommendation reviewed for safety, or an explicit reason why no automated recommendation is provided.
- [x] Unit fixtures for positive, negative, and error cases.
- [x] Dashboard and report rendering verified.
- [x] Change log entry when evaluation logic or mappings change.

## Suggested MVP cut line

The first usable release should stop here:

- [x] Securely connect one AWS account, one Azure subscription, and one GCP project.
- [x] Run 5–10 high-value checks per provider through the common scanner framework.
- [x] Store historical scans and show new, persistent, resolved, and reopened findings.
- [x] Calculate tested framework scores and clearly display coverage.
- [x] Provide executive and engineer dashboard views.
- [x] Produce reviewed Terraform/CLI recommendations without executing them.
- [x] Run daily scans and send signed Slack-compatible webhook alerts.
- [x] Export one technical report and one executive report.
- [x] Pass tenant-isolation, secret-redaction, backup/restore, and end-to-end acceptance tests.

After the MVP is stable, expand CIS coverage toward 200+ controls, add organization-wide onboarding, enrich cost analytics, add Terraform-state drift coverage, and complete production-scale hardening.
