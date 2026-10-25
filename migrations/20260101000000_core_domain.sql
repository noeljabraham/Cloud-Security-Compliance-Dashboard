CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE organizations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL,
    slug text NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email text NOT NULL,
    display_name text NOT NULL,
    external_subject text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, email),
    UNIQUE (organization_id, external_subject)
);

CREATE TABLE roles (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name text NOT NULL CHECK (name IN ('admin', 'security_reviewer', 'engineer', 'executive')),
    UNIQUE (organization_id, name)
);

CREATE TABLE user_roles (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    assigned_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE regions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    provider text NOT NULL CHECK (provider IN ('aws', 'azure', 'gcp')),
    code text NOT NULL,
    name text NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    UNIQUE (provider, code)
);

CREATE TABLE cloud_connections (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    provider text NOT NULL CHECK (provider IN ('aws', 'azure', 'gcp')),
    name text NOT NULL,
    secret_reference text,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    status text NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'active', 'disabled', 'error')),
    last_validated_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, name)
);

CREATE TABLE cloud_accounts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    connection_id uuid NOT NULL REFERENCES cloud_connections(id) ON DELETE RESTRICT,
    provider text NOT NULL CHECK (provider IN ('aws', 'azure', 'gcp')),
    native_id text NOT NULL,
    name text,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, provider, native_id)
);

CREATE TABLE account_regions (
    account_id uuid NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    region_id uuid NOT NULL REFERENCES regions(id) ON DELETE RESTRICT,
    enabled boolean NOT NULL DEFAULT true,
    PRIMARY KEY (account_id, region_id)
);

CREATE TABLE resources (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    account_id uuid NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    region_id uuid REFERENCES regions(id) ON DELETE RESTRICT,
    provider_native_id text NOT NULL,
    resource_type text NOT NULL,
    name text,
    tags jsonb NOT NULL DEFAULT '{}'::jsonb,
    configuration jsonb NOT NULL DEFAULT '{}'::jsonb,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, account_id, provider_native_id)
);

CREATE TABLE checks (
    id text PRIMARY KEY,
    provider text NOT NULL CHECK (provider IN ('aws', 'azure', 'gcp', 'agnostic')),
    service text NOT NULL,
    category text NOT NULL,
    version text NOT NULL,
    title text NOT NULL,
    description text NOT NULL,
    remediation text NOT NULL,
    enabled boolean NOT NULL DEFAULT true
);

CREATE TABLE frameworks (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid REFERENCES organizations(id) ON DELETE CASCADE,
    slug text NOT NULL,
    name text NOT NULL,
    UNIQUE (organization_id, slug)
);

CREATE TABLE framework_versions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    framework_id uuid NOT NULL REFERENCES frameworks(id) ON DELETE CASCADE,
    version text NOT NULL,
    released_at date,
    UNIQUE (framework_id, version)
);

CREATE TABLE controls (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    framework_version_id uuid NOT NULL REFERENCES framework_versions(id) ON DELETE CASCADE,
    external_id text NOT NULL,
    title text NOT NULL,
    description text,
    UNIQUE (framework_version_id, external_id)
);

CREATE TABLE profiles (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name text NOT NULL,
    description text,
    UNIQUE (organization_id, name)
);

CREATE TABLE check_control_mappings (
    check_id text NOT NULL REFERENCES checks(id) ON DELETE CASCADE,
    control_id uuid NOT NULL REFERENCES controls(id) ON DELETE CASCADE,
    profile_id uuid NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    PRIMARY KEY (check_id, control_id, profile_id)
);

CREATE TABLE scan_runs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    status text NOT NULL DEFAULT 'queued'
        CHECK (status IN ('queued', 'running', 'succeeded', 'partial', 'failed', 'cancelled')),
    scanner_version text NOT NULL,
    started_at timestamptz,
    completed_at timestamptz,
    error text,
    coverage jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (completed_at IS NULL OR started_at IS NULL OR completed_at >= started_at)
);

CREATE TABLE scan_jobs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_run_id uuid NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    account_id uuid NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    status text NOT NULL DEFAULT 'queued'
        CHECK (status IN ('queued', 'running', 'succeeded', 'partial', 'failed', 'cancelled')),
    started_at timestamptz,
    completed_at timestamptz,
    error text,
    coverage jsonb NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (scan_run_id, account_id),
    CHECK (completed_at IS NULL OR started_at IS NULL OR completed_at >= started_at)
);

CREATE TABLE findings (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    check_id text NOT NULL REFERENCES checks(id) ON DELETE RESTRICT,
    resource_id uuid NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
    severity text NOT NULL CHECK (severity IN ('informational', 'low', 'medium', 'high', 'critical')),
    status text NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'acknowledged', 'resolved', 'suppressed')),
    evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
    fingerprint text NOT NULL,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    resolved_at timestamptz,
    UNIQUE (organization_id, fingerprint)
);

CREATE TABLE finding_observations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    scan_run_id uuid NOT NULL REFERENCES scan_runs(id) ON DELETE RESTRICT,
    observed_at timestamptz NOT NULL DEFAULT now(),
    status text NOT NULL CHECK (status IN ('open', 'acknowledged', 'resolved', 'suppressed')),
    evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
    evidence_encrypted bytea,
    UNIQUE (finding_id, scan_run_id)
);

CREATE TABLE score_snapshots (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    scan_run_id uuid REFERENCES scan_runs(id) ON DELETE SET NULL,
    provider text CHECK (provider IN ('aws', 'azure', 'gcp')),
    account_id uuid REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    framework_version_id uuid REFERENCES framework_versions(id) ON DELETE SET NULL,
    service text,
    category text,
    score numeric(5,2) NOT NULL CHECK (score >= 0 AND score <= 100),
    measured_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE cost_periods (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    account_id uuid REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    period_start date NOT NULL,
    period_end date NOT NULL,
    currency char(3) NOT NULL,
    UNIQUE (organization_id, account_id, period_start, period_end),
    CHECK (period_end >= period_start)
);

CREATE TABLE costs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    cost_period_id uuid NOT NULL REFERENCES cost_periods(id) ON DELETE CASCADE,
    service text NOT NULL,
    region text,
    amount numeric(18,6) NOT NULL CHECK (amount >= 0),
    currency char(3) NOT NULL
);

CREATE TABLE optimization_opportunities (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    account_id uuid REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    resource_id uuid REFERENCES resources(id) ON DELETE SET NULL,
    title text NOT NULL,
    details text NOT NULL,
    estimated_monthly_savings numeric(18,6) CHECK (estimated_monthly_savings >= 0),
    risk_estimate text CHECK (risk_estimate IN ('low', 'medium', 'high')),
    currency char(3),
    status text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'accepted', 'dismissed', 'resolved')),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE remediation_recommendations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    finding_id uuid REFERENCES findings(id) ON DELETE CASCADE,
    title text NOT NULL,
    instructions text NOT NULL,
    risk_estimate text CHECK (risk_estimate IN ('low', 'medium', 'high')),
    owner_id uuid REFERENCES users(id) ON DELETE SET NULL,
    status text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'accepted', 'in_progress', 'completed', 'dismissed')),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE remediation_approvals (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    recommendation_id uuid NOT NULL REFERENCES remediation_recommendations(id) ON DELETE CASCADE,
    approver_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    decision text NOT NULL CHECK (decision IN ('approved', 'rejected')),
    comment text,
    decided_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE remediation_executions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    recommendation_id uuid NOT NULL REFERENCES remediation_recommendations(id) ON DELETE CASCADE,
    requested_by uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    status text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')),
    started_at timestamptz,
    completed_at timestamptz,
    error text
);

CREATE TABLE remediation_evidence (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    execution_id uuid NOT NULL REFERENCES remediation_executions(id) ON DELETE CASCADE,
    evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
    evidence_encrypted bytea,
    captured_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE remediation_status_history (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    recommendation_id uuid NOT NULL REFERENCES remediation_recommendations(id) ON DELETE CASCADE,
    status text NOT NULL,
    changed_by uuid REFERENCES users(id) ON DELETE SET NULL,
    changed_at timestamptz NOT NULL DEFAULT now(),
    comment text
);

CREATE TABLE drift_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    resource_id uuid NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
    scan_run_id uuid REFERENCES scan_runs(id) ON DELETE SET NULL,
    before_configuration jsonb NOT NULL,
    after_configuration jsonb NOT NULL,
    detected_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE alert_deliveries (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    event_type text NOT NULL,
    destination text NOT NULL,
    status text NOT NULL CHECK (status IN ('queued', 'sent', 'failed')),
    response_code integer,
    error text,
    delivered_at timestamptz
);

CREATE TABLE reports (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    requested_by uuid REFERENCES users(id) ON DELETE SET NULL,
    framework_version_id uuid REFERENCES framework_versions(id) ON DELETE SET NULL,
    format text NOT NULL CHECK (format IN ('json', 'csv', 'pdf')),
    status text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'ready', 'failed')),
    storage_reference text,
    created_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz
);

CREATE TABLE audit_logs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    actor_id uuid REFERENCES users(id) ON DELETE SET NULL,
    action text NOT NULL,
    entity_type text,
    entity_id uuid,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX users_organization_idx ON users (organization_id);
CREATE INDEX connections_organization_idx ON cloud_connections (organization_id);
CREATE INDEX accounts_organization_idx ON cloud_accounts (organization_id);
CREATE INDEX resources_organization_last_seen_idx ON resources (organization_id, last_seen_at DESC);
CREATE INDEX findings_dashboard_idx ON findings (organization_id, status, severity, last_seen_at DESC);
CREATE INDEX findings_resource_check_idx ON findings (resource_id, check_id);
CREATE INDEX observations_history_idx ON finding_observations (finding_id, observed_at DESC);
CREATE INDEX scan_runs_history_idx ON scan_runs (organization_id, created_at DESC);
CREATE INDEX scan_jobs_account_idx ON scan_jobs (organization_id, account_id, status);
CREATE INDEX scores_dashboard_idx ON score_snapshots (organization_id, measured_at DESC);
CREATE INDEX costs_period_idx ON costs (cost_period_id);
CREATE INDEX audit_logs_tenant_time_idx ON audit_logs (organization_id, created_at DESC);
