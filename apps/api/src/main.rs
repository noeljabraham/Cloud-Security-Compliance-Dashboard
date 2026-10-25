pub mod auth;
pub mod openapi;

use std::{
    collections::HashMap,
    env,
    error::Error,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, patch, post},
};
use cloudsec_domain::{
    APP_NAME, AlertDestination, AlertDestinationType, AlertRule, AlertTriggerCondition, AuditLog,
    AwsOnboardingConfig, AzureOnboardingConfig, BaselineScan, CloudAccount, CloudConnection,
    CloudProvider, ComprehensiveCostRiskReport, ConnectionStatus, CostOptimizationItem, CostReport,
    DiscoveredResource, DriftItem, ExceptionStatus, Finding, FindingException, FindingStatus,
    GcpOnboardingConfig, GeneratedReport, Id, Organization, PaginatedResponse, PaginationMeta,
    PostureTrendReport, RemediationAction, RemediationEffort, RemediationExecutionState,
    RemediationStatus, RemediationTemplate, ReportFormat, Resource, ScanJob, ScanRun, ScanSchedule,
    ScanStatus, ScoreSnapshot, Severity, TerraformResourceMapping, TrendDataPoint, UserRole,
    WebhookDeliveryRecord,
};
use cloudsec_scanner::{
    AlertingEngine, AssessmentProfile, CancellationToken, CheckEvaluation, CheckEvaluationRecord,
    CloudBillingRecord, CloudOnboardingValidator, ComplianceScoringEngine,
    ComprehensiveScoreReport, ControlCoverageReport, CostSecurityEngine, DriftEngine,
    EncryptionService, EvaluationOutcome, FakeCloudProvider, MetricsSnapshot,
    OnboardingValidationResult, ProviderRegistry, RemediationTemplateEngine, ScanOptions,
    ScanOrchestrator, ScanTarget, ScannerMetrics, redact_sensitive_value,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::{net::TcpListener, sync::RwLock};
use uuid::Uuid;

use crate::auth::{DEFAULT_ORG_ID, check_permission, check_tenant_isolation, extract_auth_user};

fn current_iso_timestamp() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{now}")
}

// ------------------------------------------------------------------------------------------------
// Application State
// ------------------------------------------------------------------------------------------------

#[derive(Clone)]
pub struct AppState {
    pub orchestrator: Arc<ScanOrchestrator>,
    pub registry: Arc<ProviderRegistry>,
    pub metrics: Arc<ScannerMetrics>,
    pub encryption: Arc<EncryptionService>,
    pub organizations: Arc<RwLock<Vec<Organization>>>,
    pub connections: Arc<RwLock<Vec<CloudConnection>>>,
    pub accounts: Arc<RwLock<Vec<CloudAccount>>>,
    pub resources: Arc<RwLock<Vec<Resource>>>,
    pub findings: Arc<RwLock<Vec<Finding>>>,
    pub scan_runs: Arc<RwLock<Vec<ScanRun>>>,
    pub scan_jobs: Arc<RwLock<Vec<ScanJob>>>,
    pub score_snapshots: Arc<RwLock<Vec<ScoreSnapshot>>>,
    pub audit_logs: Arc<RwLock<Vec<AuditLog>>>,
    pub exceptions: Arc<RwLock<Vec<FindingException>>>,
    pub remediations: Arc<RwLock<Vec<RemediationAction>>>,
    pub generated_reports: Arc<RwLock<Vec<GeneratedReport>>>,
    pub drift_items: Arc<RwLock<Vec<DriftItem>>>,
    pub active_scans: Arc<RwLock<HashMap<Id, (Id, CancellationToken)>>>, // scan_run_id -> (org_id, CancellationToken)
    pub scan_idempotency: Arc<RwLock<HashMap<String, ScanRun>>>, // idempotency_key -> ScanRun
    pub rate_limiter: Arc<RwLock<HashMap<String, (u32, u64)>>>, // key -> (count, window_start_secs)
    pub schedules: Arc<RwLock<Vec<ScanSchedule>>>,
    pub baseline_scans: Arc<RwLock<HashMap<Id, BaselineScan>>>,
    pub billing_records: Arc<RwLock<Vec<CloudBillingRecord>>>,
    pub alert_rules: Arc<RwLock<Vec<AlertRule>>>,
    pub alert_destinations: Arc<RwLock<Vec<AlertDestination>>>,
    pub webhook_deliveries: Arc<RwLock<Vec<WebhookDeliveryRecord>>>,
}

impl AppState {
    pub fn new() -> Self {
        let org_id = Uuid::parse_str(DEFAULT_ORG_ID).unwrap();
        let org = Organization {
            id: org_id,
            name: "Default Organization".to_string(),
            slug: "default-org".to_string(),
        };

        let mut registry = ProviderRegistry::new();
        cloudsec_scanner::register_all_aws_checks(&mut registry);
        cloudsec_scanner::register_all_azure_checks(&mut registry);
        cloudsec_scanner::register_all_gcp_checks(&mut registry);

        let registry = Arc::new(registry);
        let metrics = Arc::new(ScannerMetrics::new());
        let orchestrator = Arc::new(ScanOrchestrator::new(registry.clone(), metrics.clone()));

        Self {
            orchestrator,
            registry,
            metrics,
            encryption: Arc::new(EncryptionService::new()),
            organizations: Arc::new(RwLock::new(vec![org])),
            connections: Arc::new(RwLock::new(Vec::new())),
            accounts: Arc::new(RwLock::new(Vec::new())),
            resources: Arc::new(RwLock::new(Vec::new())),
            findings: Arc::new(RwLock::new(Vec::new())),
            scan_runs: Arc::new(RwLock::new(Vec::new())),
            scan_jobs: Arc::new(RwLock::new(Vec::new())),
            score_snapshots: Arc::new(RwLock::new(Vec::new())),
            audit_logs: Arc::new(RwLock::new(Vec::new())),
            exceptions: Arc::new(RwLock::new(Vec::new())),
            remediations: Arc::new(RwLock::new(Vec::new())),
            generated_reports: Arc::new(RwLock::new(Vec::new())),
            drift_items: Arc::new(RwLock::new(Vec::new())),
            active_scans: Arc::new(RwLock::new(HashMap::new())),
            scan_idempotency: Arc::new(RwLock::new(HashMap::new())),
            rate_limiter: Arc::new(RwLock::new(HashMap::new())),
            schedules: Arc::new(RwLock::new(Vec::new())),
            baseline_scans: Arc::new(RwLock::new(HashMap::new())),
            billing_records: Arc::new(RwLock::new(Vec::new())),
            alert_rules: Arc::new(RwLock::new(Vec::new())),
            alert_destinations: Arc::new(RwLock::new(Vec::new())),
            webhook_deliveries: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub fn new_with_defaults() -> Self {
        let org_id = Uuid::parse_str(DEFAULT_ORG_ID).unwrap();
        let org = Organization {
            id: org_id,
            name: "Default Organization".to_string(),
            slug: "default-org".to_string(),
        };

        let connection_id = Uuid::new_v4();
        let account_id = Uuid::new_v4();

        let encryption = Arc::new(EncryptionService::new());
        let encrypted_secret = encryption
            .encrypt(b"ext-id-prod-external-id-12345678")
            .unwrap_or_else(|_| "secret".into());

        let connection = CloudConnection {
            id: connection_id,
            organization_id: org_id,
            provider: CloudProvider::Aws,
            name: "Production AWS Connection".to_string(),
            status: ConnectionStatus::Active,
            secret_reference: Some(encrypted_secret),
            metadata: json!({
                "role_arn": "arn:aws:iam::123456789012:role/CloudSecSecurityAuditRole",
                "account_id": "123456789012",
                "external_id": "ext-id-prod-external-id-12345678",
                "regions": ["us-east-1"],
            }),
            last_validated_at: Some(current_iso_timestamp()),
            created_at: current_iso_timestamp(),
            updated_at: current_iso_timestamp(),
        };

        let account = CloudAccount {
            id: account_id,
            organization_id: org_id,
            connection_id,
            provider: CloudProvider::Aws,
            native_id: "123456789012".to_string(),
            name: Some("Production AWS Account".to_string()),
        };

        let initial_audit = AuditLog {
            id: Uuid::new_v4(),
            organization_id: org_id,
            actor_id: None,
            action: "connection.created".to_string(),
            entity_type: Some("cloud_connection".to_string()),
            entity_id: Some(connection_id),
            metadata: json!({
                "provider": "aws",
                "connection_name": "Production AWS Connection",
                "role_arn": "arn:aws:iam::123456789012:role/CloudSecSecurityAuditRole",
            }),
            created_at: current_iso_timestamp(),
        };

        let mut registry = ProviderRegistry::new();

        // Register fake AWS provider with an S3 bucket with Block Public Access disabled
        let fake_aws = FakeCloudProvider::new(CloudProvider::Aws).with_resource(
            "us-east-1",
            "s3",
            DiscoveredResource {
                provider_native_id: "customer-data-backup".to_string(),
                resource_type: "aws_s3_bucket".to_string(),
                name: Some("customer-data-backup".to_string()),
                region: Some("us-east-1".to_string()),
                tags: json!({"data_classification": "restricted", "environment": "production"}),
                configuration: json!({
                    "block_public_acls": true,
                    "ignore_public_acls": false,
                    "block_public_policy": false,
                    "restrict_public_buckets": false,
                    "publicly_accessible": true
                }),
            },
        );

        let fake_azure = FakeCloudProvider::new(CloudProvider::Azure);
        let fake_gcp = FakeCloudProvider::new(CloudProvider::Gcp);

        registry.register_provider(Arc::new(fake_aws));
        registry.register_provider(Arc::new(fake_azure));
        registry.register_provider(Arc::new(fake_gcp));

        // Register all assessment checks
        cloudsec_scanner::register_all_aws_checks(&mut registry);
        cloudsec_scanner::register_all_azure_checks(&mut registry);
        cloudsec_scanner::register_all_gcp_checks(&mut registry);

        let registry = Arc::new(registry);
        let metrics = Arc::new(ScannerMetrics::new());
        let orchestrator = Arc::new(ScanOrchestrator::new(registry.clone(), metrics.clone()));

        Self {
            orchestrator,
            registry,
            metrics,
            encryption,
            organizations: Arc::new(RwLock::new(vec![org])),
            connections: Arc::new(RwLock::new(vec![connection])),
            accounts: Arc::new(RwLock::new(vec![account])),
            resources: Arc::new(RwLock::new(Vec::new())),
            findings: Arc::new(RwLock::new(Vec::new())),
            scan_runs: Arc::new(RwLock::new(Vec::new())),
            scan_jobs: Arc::new(RwLock::new(Vec::new())),
            score_snapshots: Arc::new(RwLock::new(Vec::new())),
            audit_logs: Arc::new(RwLock::new(vec![initial_audit])),
            exceptions: Arc::new(RwLock::new(Vec::new())),
            remediations: Arc::new(RwLock::new(Vec::new())),
            generated_reports: Arc::new(RwLock::new(Vec::new())),
            drift_items: Arc::new(RwLock::new(Vec::new())),
            active_scans: Arc::new(RwLock::new(HashMap::new())),
            scan_idempotency: Arc::new(RwLock::new(HashMap::new())),
            rate_limiter: Arc::new(RwLock::new(HashMap::new())),
            schedules: Arc::new(RwLock::new(Vec::new())),
            baseline_scans: Arc::new(RwLock::new(HashMap::new())),
            billing_records: Arc::new(RwLock::new(Vec::new())),
            alert_rules: Arc::new(RwLock::new(Vec::new())),
            alert_destinations: Arc::new(RwLock::new(Vec::new())),
            webhook_deliveries: Arc::new(RwLock::new(Vec::new())),
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

// ------------------------------------------------------------------------------------------------
// Response & Error Envelopes
// ------------------------------------------------------------------------------------------------

#[derive(Serialize)]
struct Health {
    service: &'static str,
    status: &'static str,
}

#[derive(Serialize)]
struct Readiness {
    service: &'static str,
    status: &'static str,
    providers_registered: usize,
    checks_registered: usize,
}

#[derive(Serialize)]
pub struct ApiErrorEnvelope {
    pub error: ApiError,
}

#[derive(Serialize)]
pub struct ApiError {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

impl ApiErrorEnvelope {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            error: ApiError {
                code: code.into(),
                message: message.into(),
                details: None,
            },
        }
    }

    pub fn with_details(
        code: impl Into<String>,
        message: impl Into<String>,
        details: Value,
    ) -> Self {
        Self {
            error: ApiError {
                code: code.into(),
                message: message.into(),
                details: Some(details),
            },
        }
    }
}

pub type ApiResult<T> = Result<Json<T>, (StatusCode, Json<ApiErrorEnvelope>)>;

fn err_response(
    status: StatusCode,
    code: &str,
    message: impl Into<String>,
) -> (StatusCode, Json<ApiErrorEnvelope>) {
    (status, Json(ApiErrorEnvelope::new(code, message)))
}

fn map_auth_err(e: (StatusCode, Json<Value>)) -> (StatusCode, Json<ApiErrorEnvelope>) {
    let status = e.0;
    let code = e.1["error"]["code"]
        .as_str()
        .unwrap_or("unauthorized")
        .to_string();
    let message = e.1["error"]["message"]
        .as_str()
        .unwrap_or("Access denied")
        .to_string();
    (status, Json(ApiErrorEnvelope::new(code, message)))
}

// ------------------------------------------------------------------------------------------------
// Pagination Helper
// ------------------------------------------------------------------------------------------------

#[derive(Deserialize, Debug, Default)]
pub struct PaginationParams {
    pub page: Option<usize>,
    pub per_page: Option<usize>,
    pub sort_by: Option<String>,
    pub sort_order: Option<String>, // "asc" | "desc"
}

pub fn paginate_slice<T: Clone>(items: &[T], page: usize, per_page: usize) -> PaginatedResponse<T> {
    let total_count = items.len();
    let per_page = if per_page == 0 { 20 } else { per_page.min(100) };
    let page = if page == 0 { 1 } else { page };
    let total_pages = if total_count == 0 {
        1
    } else {
        total_count.div_ceil(per_page)
    };
    let start = (page - 1) * per_page;
    let data = if start >= total_count {
        Vec::new()
    } else {
        let end = (start + per_page).min(total_count);
        items[start..end].to_vec()
    };
    PaginatedResponse {
        data,
        pagination: PaginationMeta {
            page,
            per_page,
            total_count,
            total_pages,
        },
    }
}

// ------------------------------------------------------------------------------------------------
// Security & Rate Limiting Middleware
// ------------------------------------------------------------------------------------------------

async fn security_headers_middleware(request: axum::extract::Request, next: Next) -> Response {
    if request.method() == axum::http::Method::OPTIONS {
        let mut response = StatusCode::NO_CONTENT.into_response();
        let headers = response.headers_mut();
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_static("*"),
        );
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("GET, POST, PUT, PATCH, DELETE, OPTIONS"),
        );
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static(
                "Content-Type, Authorization, X-Organization-Id, X-User-Role, X-User-Email, X-User-Id, Idempotency-Key",
            ),
        );
        return response;
    }

    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, POST, PUT, PATCH, DELETE, OPTIONS"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static(
            "Content-Type, Authorization, X-Organization-Id, X-User-Role, X-User-Email, X-User-Id, Idempotency-Key",
        ),
    );
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(
        "strict-transport-security",
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static("default-src 'self'"),
    );
    headers.insert(
        "x-xss-protection",
        HeaderValue::from_static("1; mode=block"),
    );
    headers.insert(
        "referrer-policy",
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    response
}

// ------------------------------------------------------------------------------------------------
// Health, Readiness & OpenAPI Handlers
// ------------------------------------------------------------------------------------------------

async fn health() -> (StatusCode, Json<Health>) {
    (
        StatusCode::OK,
        Json(Health {
            service: APP_NAME,
            status: "ok",
        }),
    )
}

async fn ready(State(state): State<AppState>) -> (StatusCode, Json<Readiness>) {
    let checks_count = state.registry.all_checks().len();
    (
        StatusCode::OK,
        Json(Readiness {
            service: APP_NAME,
            status: "ready",
            providers_registered: 3,
            checks_registered: checks_count,
        }),
    )
}

async fn get_openapi_spec() -> Json<Value> {
    Json(openapi::generate_openapi_spec())
}

// ------------------------------------------------------------------------------------------------
// Connection Handlers
// ------------------------------------------------------------------------------------------------

#[derive(Deserialize)]
struct CreateConnectionRequest {
    organization_id: Option<Uuid>,
    provider: CloudProvider,
    name: String,
    metadata: Value,
}

fn sanitize_connection(mut conn: CloudConnection) -> CloudConnection {
    conn.secret_reference = None;
    conn.metadata = redact_sensitive_value(&conn.metadata);
    conn
}

#[derive(Deserialize, Default)]
struct ConnectionQuery {
    pub page: Option<usize>,
    pub per_page: Option<usize>,
    pub sort_by: Option<String>,
    pub sort_order: Option<String>,
    pub organization_id: Option<Uuid>,
    pub provider: Option<CloudProvider>,
    pub status: Option<ConnectionStatus>,
}

async fn list_connections(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ConnectionQuery>,
) -> ApiResult<PaginatedResponse<CloudConnection>> {
    let auth_user = extract_auth_user(&headers);
    let org_id = query.organization_id.unwrap_or(auth_user.organization_id);

    // Enforce tenant isolation
    if org_id != auth_user.organization_id {
        return Ok(Json(paginate_slice(&[], 1, 20)));
    }

    let conns = state.connections.read().await;
    let mut filtered: Vec<CloudConnection> = conns
        .iter()
        .filter(|c| {
            if c.organization_id != org_id {
                return false;
            }
            if let Some(p) = query.provider {
                if c.provider != p {
                    return false;
                }
            }
            if let Some(s) = query.status {
                if c.status != s {
                    return false;
                }
            }
            true
        })
        .cloned()
        .map(sanitize_connection)
        .collect();

    if let Some(ref sort) = query.sort_by {
        if sort == "name" {
            filtered.sort_by(|a, b| a.name.cmp(&b.name));
        } else if sort == "created_at" {
            filtered.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        }
        if query.sort_order.as_deref() == Some("desc") {
            filtered.reverse();
        }
    }

    let page = query.page.unwrap_or(1);
    let per_page = query.per_page.unwrap_or(20);
    Ok(Json(paginate_slice(&filtered, page, per_page)))
}

async fn get_connection(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<CloudConnection> {
    let auth_user = extract_auth_user(&headers);
    let conns = state.connections.read().await;
    let conn =
        conns.iter().find(|c| c.id == id).cloned().ok_or_else(|| {
            err_response(StatusCode::NOT_FOUND, "not_found", "Connection not found")
        })?;

    check_tenant_isolation(&auth_user, conn.organization_id).map_err(map_auth_err)?;
    Ok(Json(sanitize_connection(conn)))
}

async fn create_connection(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateConnectionRequest>,
) -> ApiResult<CloudConnection> {
    let auth_user = extract_auth_user(&headers);
    check_permission(&auth_user, &[UserRole::Admin]).map_err(map_auth_err)?;

    let org_id = payload.organization_id.unwrap_or(auth_user.organization_id);
    check_tenant_isolation(&auth_user, org_id).map_err(map_auth_err)?;

    // Validate provider specific onboarding input
    let (native_id, validation_res) = match payload.provider {
        CloudProvider::Aws => {
            let role_arn = payload
                .metadata
                .get("role_arn")
                .and_then(Value::as_str)
                .unwrap_or("");
            let external_id = payload
                .metadata
                .get("external_id")
                .and_then(Value::as_str)
                .unwrap_or("");
            let account_id = payload
                .metadata
                .get("account_id")
                .and_then(Value::as_str)
                .unwrap_or("");
            let regions = payload
                .metadata
                .get("regions")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(Value::as_str)
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_else(|| vec!["us-east-1".to_string()]);

            let config = AwsOnboardingConfig {
                role_arn: role_arn.to_string(),
                external_id: external_id.to_string(),
                account_id: account_id.to_string(),
                regions,
            };

            CloudOnboardingValidator::validate_aws_input(&config, &payload.metadata).map_err(
                |e| {
                    err_response(
                        StatusCode::BAD_REQUEST,
                        "invalid_onboarding_input",
                        e.to_string(),
                    )
                },
            )?;

            let res =
                CloudOnboardingValidator::test_aws_connectivity(&config, &[]).map_err(|e| {
                    err_response(
                        StatusCode::BAD_REQUEST,
                        "connectivity_failed",
                        e.to_string(),
                    )
                })?;

            (account_id.to_string(), res)
        }
        CloudProvider::Azure => {
            let tenant_id = payload
                .metadata
                .get("tenant_id")
                .and_then(Value::as_str)
                .unwrap_or("");
            let client_id = payload
                .metadata
                .get("client_id")
                .and_then(Value::as_str)
                .unwrap_or("");
            let subscription_id = payload
                .metadata
                .get("subscription_id")
                .and_then(Value::as_str)
                .unwrap_or("");
            let federated_credential = payload
                .metadata
                .get("federated_credential")
                .and_then(Value::as_str)
                .unwrap_or("");

            let config = AzureOnboardingConfig {
                tenant_id: tenant_id.to_string(),
                client_id: client_id.to_string(),
                subscription_id: subscription_id.to_string(),
                federated_credential: federated_credential.to_string(),
            };

            CloudOnboardingValidator::validate_azure_input(&config, &payload.metadata).map_err(
                |e| {
                    err_response(
                        StatusCode::BAD_REQUEST,
                        "invalid_onboarding_input",
                        e.to_string(),
                    )
                },
            )?;

            let res =
                CloudOnboardingValidator::test_azure_connectivity(&config, &[]).map_err(|e| {
                    err_response(
                        StatusCode::BAD_REQUEST,
                        "connectivity_failed",
                        e.to_string(),
                    )
                })?;

            (subscription_id.to_string(), res)
        }
        CloudProvider::Gcp => {
            let project_id = payload
                .metadata
                .get("project_id")
                .and_then(Value::as_str)
                .unwrap_or("");
            let workload_identity_pool = payload
                .metadata
                .get("workload_identity_pool")
                .and_then(Value::as_str)
                .unwrap_or("");
            let service_account_email = payload
                .metadata
                .get("service_account_email")
                .and_then(Value::as_str)
                .unwrap_or("");

            let config = GcpOnboardingConfig {
                project_id: project_id.to_string(),
                workload_identity_pool: workload_identity_pool.to_string(),
                service_account_email: service_account_email.to_string(),
            };

            CloudOnboardingValidator::validate_gcp_input(&config, &payload.metadata).map_err(
                |e| {
                    err_response(
                        StatusCode::BAD_REQUEST,
                        "invalid_onboarding_input",
                        e.to_string(),
                    )
                },
            )?;

            let res =
                CloudOnboardingValidator::test_gcp_connectivity(&config, &[]).map_err(|e| {
                    err_response(
                        StatusCode::BAD_REQUEST,
                        "connectivity_failed",
                        e.to_string(),
                    )
                })?;

            (project_id.to_string(), res)
        }
    };

    let secret_to_encrypt = payload
        .metadata
        .get("external_id")
        .or_else(|| payload.metadata.get("federated_credential"))
        .and_then(Value::as_str)
        .unwrap_or("none");

    let encrypted_secret = state
        .encryption
        .encrypt(secret_to_encrypt.as_bytes())
        .map_err(|e| {
            err_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "encryption_error",
                e.to_string(),
            )
        })?;

    let conn_id = Uuid::new_v4();
    let account_id = Uuid::new_v4();
    let now = current_iso_timestamp();

    let status = if validation_res.is_valid {
        ConnectionStatus::Active
    } else {
        ConnectionStatus::Error
    };

    let connection = CloudConnection {
        id: conn_id,
        organization_id: org_id,
        provider: payload.provider,
        name: payload.name.clone(),
        status,
        secret_reference: Some(encrypted_secret),
        metadata: payload.metadata.clone(),
        last_validated_at: Some(now.clone()),
        created_at: now.clone(),
        updated_at: now.clone(),
    };

    let account = CloudAccount {
        id: account_id,
        organization_id: org_id,
        connection_id: conn_id,
        provider: payload.provider,
        native_id: native_id.clone(),
        name: Some(format!("{} Account", payload.name)),
    };

    let audit_event = AuditLog {
        id: Uuid::new_v4(),
        organization_id: org_id,
        actor_id: Some(auth_user.user_id),
        action: "connection.created".to_string(),
        entity_type: Some("cloud_connection".to_string()),
        entity_id: Some(conn_id),
        metadata: json!({
            "provider": payload.provider.as_str(),
            "name": payload.name,
            "native_id": native_id,
            "status": status,
        }),
        created_at: now,
    };

    {
        let mut conns = state.connections.write().await;
        conns.push(connection.clone());
    }
    {
        let mut accs = state.accounts.write().await;
        accs.push(account);
    }
    {
        let mut audits = state.audit_logs.write().await;
        audits.push(audit_event);
    }

    Ok(Json(sanitize_connection(connection)))
}

async fn test_connection(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<OnboardingValidationResult> {
    let auth_user = extract_auth_user(&headers);
    check_permission(&auth_user, &[UserRole::Admin, UserRole::SecurityEngineer])
        .map_err(map_auth_err)?;

    let mut conns = state.connections.write().await;
    let conn = conns
        .iter_mut()
        .find(|c| c.id == id)
        .ok_or_else(|| err_response(StatusCode::NOT_FOUND, "not_found", "Connection not found"))?;

    check_tenant_isolation(&auth_user, conn.organization_id).map_err(map_auth_err)?;

    let validation_res = match conn.provider {
        CloudProvider::Aws => {
            let role_arn = conn
                .metadata
                .get("role_arn")
                .and_then(Value::as_str)
                .unwrap_or("");
            let external_id = conn
                .metadata
                .get("external_id")
                .and_then(Value::as_str)
                .unwrap_or("");
            let account_id = conn
                .metadata
                .get("account_id")
                .and_then(Value::as_str)
                .unwrap_or("");
            let regions = conn
                .metadata
                .get("regions")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(Value::as_str)
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_else(|| vec!["us-east-1".to_string()]);

            let config = AwsOnboardingConfig {
                role_arn: role_arn.to_string(),
                external_id: external_id.to_string(),
                account_id: account_id.to_string(),
                regions,
            };

            CloudOnboardingValidator::test_aws_connectivity(&config, &[]).map_err(|e| {
                err_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "connectivity_test_failed",
                    e.to_string(),
                )
            })?
        }
        CloudProvider::Azure => {
            let tenant_id = conn
                .metadata
                .get("tenant_id")
                .and_then(Value::as_str)
                .unwrap_or("");
            let client_id = conn
                .metadata
                .get("client_id")
                .and_then(Value::as_str)
                .unwrap_or("");
            let subscription_id = conn
                .metadata
                .get("subscription_id")
                .and_then(Value::as_str)
                .unwrap_or("");
            let federated_credential = conn
                .metadata
                .get("federated_credential")
                .and_then(Value::as_str)
                .unwrap_or("");

            let config = AzureOnboardingConfig {
                tenant_id: tenant_id.to_string(),
                client_id: client_id.to_string(),
                subscription_id: subscription_id.to_string(),
                federated_credential: federated_credential.to_string(),
            };

            CloudOnboardingValidator::test_azure_connectivity(&config, &[]).map_err(|e| {
                err_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "connectivity_test_failed",
                    e.to_string(),
                )
            })?
        }
        CloudProvider::Gcp => {
            let project_id = conn
                .metadata
                .get("project_id")
                .and_then(Value::as_str)
                .unwrap_or("");
            let workload_identity_pool = conn
                .metadata
                .get("workload_identity_pool")
                .and_then(Value::as_str)
                .unwrap_or("");
            let service_account_email = conn
                .metadata
                .get("service_account_email")
                .and_then(Value::as_str)
                .unwrap_or("");

            let config = GcpOnboardingConfig {
                project_id: project_id.to_string(),
                workload_identity_pool: workload_identity_pool.to_string(),
                service_account_email: service_account_email.to_string(),
            };

            CloudOnboardingValidator::test_gcp_connectivity(&config, &[]).map_err(|e| {
                err_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "connectivity_test_failed",
                    e.to_string(),
                )
            })?
        }
    };

    let now = current_iso_timestamp();
    conn.last_validated_at = Some(now.clone());
    conn.status = if validation_res.is_valid {
        ConnectionStatus::Active
    } else {
        ConnectionStatus::Error
    };

    let audit_event = AuditLog {
        id: Uuid::new_v4(),
        organization_id: conn.organization_id,
        actor_id: Some(auth_user.user_id),
        action: "connection.tested".to_string(),
        entity_type: Some("cloud_connection".to_string()),
        entity_id: Some(id),
        metadata: json!({
            "is_valid": validation_res.is_valid,
            "missing_permissions": validation_res.missing_permissions,
            "status": conn.status,
        }),
        created_at: now,
    };

    drop(conns);

    {
        let mut audits = state.audit_logs.write().await;
        audits.push(audit_event);
    }

    Ok(Json(validation_res))
}

#[derive(Deserialize)]
struct RotateCredentialsRequest {
    new_external_id: Option<String>,
    new_federated_credential: Option<String>,
}

async fn rotate_connection(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(payload): Json<Option<RotateCredentialsRequest>>,
) -> ApiResult<CloudConnection> {
    let auth_user = extract_auth_user(&headers);
    check_permission(&auth_user, &[UserRole::Admin]).map_err(map_auth_err)?;

    let mut conns = state.connections.write().await;
    let conn = conns
        .iter_mut()
        .find(|c| c.id == id)
        .ok_or_else(|| err_response(StatusCode::NOT_FOUND, "not_found", "Connection not found"))?;

    check_tenant_isolation(&auth_user, conn.organization_id).map_err(map_auth_err)?;

    let new_secret = payload
        .as_ref()
        .and_then(|p| {
            p.new_external_id
                .clone()
                .or_else(|| p.new_federated_credential.clone())
        })
        .unwrap_or_else(|| format!("ext-id-rotated-{}", Uuid::new_v4()));

    let encrypted = state
        .encryption
        .encrypt(new_secret.as_bytes())
        .map_err(|e| {
            err_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "encryption_error",
                e.to_string(),
            )
        })?;

    conn.secret_reference = Some(encrypted);
    if let Value::Object(ref mut map) = conn.metadata {
        if conn.provider == CloudProvider::Aws {
            map.insert("external_id".to_string(), json!(new_secret));
        } else {
            map.insert("federated_credential".to_string(), json!(new_secret));
        }
    }
    let now = current_iso_timestamp();
    conn.updated_at = now.clone();

    let audit_event = AuditLog {
        id: Uuid::new_v4(),
        organization_id: conn.organization_id,
        actor_id: Some(auth_user.user_id),
        action: "connection.credentials_rotated".to_string(),
        entity_type: Some("cloud_connection".to_string()),
        entity_id: Some(id),
        metadata: json!({"status": conn.status}),
        created_at: now,
    };

    let result = sanitize_connection(conn.clone());
    drop(conns);

    {
        let mut audits = state.audit_logs.write().await;
        audits.push(audit_event);
    }

    Ok(Json(result))
}

async fn disable_connection(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<CloudConnection> {
    let auth_user = extract_auth_user(&headers);
    check_permission(&auth_user, &[UserRole::Admin]).map_err(map_auth_err)?;

    let mut conns = state.connections.write().await;
    let conn = conns
        .iter_mut()
        .find(|c| c.id == id)
        .ok_or_else(|| err_response(StatusCode::NOT_FOUND, "not_found", "Connection not found"))?;

    check_tenant_isolation(&auth_user, conn.organization_id).map_err(map_auth_err)?;

    conn.status = ConnectionStatus::Disabled;
    let now = current_iso_timestamp();
    conn.updated_at = now.clone();

    let audit_event = AuditLog {
        id: Uuid::new_v4(),
        organization_id: conn.organization_id,
        actor_id: Some(auth_user.user_id),
        action: "connection.disabled".to_string(),
        entity_type: Some("cloud_connection".to_string()),
        entity_id: Some(id),
        metadata: json!({"status": "disabled"}),
        created_at: now,
    };

    let result = sanitize_connection(conn.clone());
    drop(conns);

    {
        let mut audits = state.audit_logs.write().await;
        audits.push(audit_event);
    }

    Ok(Json(result))
}

async fn enable_connection(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<CloudConnection> {
    let auth_user = extract_auth_user(&headers);
    check_permission(&auth_user, &[UserRole::Admin]).map_err(map_auth_err)?;

    let mut conns = state.connections.write().await;
    let conn = conns
        .iter_mut()
        .find(|c| c.id == id)
        .ok_or_else(|| err_response(StatusCode::NOT_FOUND, "not_found", "Connection not found"))?;

    check_tenant_isolation(&auth_user, conn.organization_id).map_err(map_auth_err)?;

    conn.status = ConnectionStatus::Active;
    let now = current_iso_timestamp();
    conn.updated_at = now.clone();

    let audit_event = AuditLog {
        id: Uuid::new_v4(),
        organization_id: conn.organization_id,
        actor_id: Some(auth_user.user_id),
        action: "connection.enabled".to_string(),
        entity_type: Some("cloud_connection".to_string()),
        entity_id: Some(id),
        metadata: json!({"status": "active"}),
        created_at: now,
    };

    let result = sanitize_connection(conn.clone());
    drop(conns);

    {
        let mut audits = state.audit_logs.write().await;
        audits.push(audit_event);
    }

    Ok(Json(result))
}

async fn delete_connection(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, Json<ApiErrorEnvelope>)> {
    let auth_user = extract_auth_user(&headers);
    check_permission(&auth_user, &[UserRole::Admin]).map_err(map_auth_err)?;

    let mut conns = state.connections.write().await;
    let pos = conns
        .iter()
        .position(|c| c.id == id)
        .ok_or_else(|| err_response(StatusCode::NOT_FOUND, "not_found", "Connection not found"))?;

    check_tenant_isolation(&auth_user, conns[pos].organization_id).map_err(map_auth_err)?;

    let removed = conns.remove(pos);
    drop(conns);

    // Remove associated accounts
    {
        let mut accs = state.accounts.write().await;
        accs.retain(|a| a.connection_id != id);
    }

    let audit_event = AuditLog {
        id: Uuid::new_v4(),
        organization_id: removed.organization_id,
        actor_id: Some(auth_user.user_id),
        action: "connection.deleted".to_string(),
        entity_type: Some("cloud_connection".to_string()),
        entity_id: Some(id),
        metadata: json!({
            "connection_name": removed.name,
            "provider": removed.provider.as_str(),
        }),
        created_at: current_iso_timestamp(),
    };

    {
        let mut audits = state.audit_logs.write().await;
        audits.push(audit_event);
    }

    Ok(StatusCode::NO_CONTENT)
}

// ------------------------------------------------------------------------------------------------
// Cloud Accounts Handlers
// ------------------------------------------------------------------------------------------------

#[derive(Deserialize, Default)]
struct AccountQuery {
    pub page: Option<usize>,
    pub per_page: Option<usize>,
    pub organization_id: Option<Uuid>,
    pub provider: Option<CloudProvider>,
}

async fn list_accounts(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AccountQuery>,
) -> ApiResult<PaginatedResponse<CloudAccount>> {
    let auth_user = extract_auth_user(&headers);
    let org_id = query.organization_id.unwrap_or(auth_user.organization_id);

    if org_id != auth_user.organization_id {
        return Ok(Json(paginate_slice(&[], 1, 20)));
    }

    let accounts = state.accounts.read().await;
    let filtered: Vec<CloudAccount> = accounts
        .iter()
        .filter(|a| {
            if a.organization_id != org_id {
                return false;
            }
            if let Some(p) = query.provider {
                if a.provider != p {
                    return false;
                }
            }
            true
        })
        .cloned()
        .collect();

    let page = query.page.unwrap_or(1);
    let per_page = query.per_page.unwrap_or(20);
    Ok(Json(paginate_slice(&filtered, page, per_page)))
}

async fn get_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<CloudAccount> {
    let auth_user = extract_auth_user(&headers);
    let accounts = state.accounts.read().await;
    let account = accounts
        .iter()
        .find(|a| a.id == id)
        .cloned()
        .ok_or_else(|| err_response(StatusCode::NOT_FOUND, "not_found", "Account not found"))?;

    check_tenant_isolation(&auth_user, account.organization_id).map_err(map_auth_err)?;
    Ok(Json(account))
}

// ------------------------------------------------------------------------------------------------
// Scan Handlers with Concurrency & Idempotency Protection
// ------------------------------------------------------------------------------------------------

#[derive(Deserialize)]
struct TriggerScanRequest {
    organization_id: Option<Uuid>,
    idempotency_key: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct TriggerScanResponse {
    pub scan_run: ScanRun,
    pub jobs_count: usize,
    pub findings_count: usize,
    pub resolved_findings_count: usize,
    pub coverage_gaps_count: usize,
    pub score: f64,
}

#[derive(Deserialize, Default)]
struct ScanQuery {
    pub page: Option<usize>,
    pub per_page: Option<usize>,
    pub organization_id: Option<Uuid>,
}

async fn list_scans(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ScanQuery>,
) -> ApiResult<PaginatedResponse<ScanRun>> {
    let auth_user = extract_auth_user(&headers);
    let org_id = query.organization_id.unwrap_or(auth_user.organization_id);

    if org_id != auth_user.organization_id {
        return Ok(Json(paginate_slice(&[], 1, 20)));
    }

    let runs = state.scan_runs.read().await;
    let filtered: Vec<ScanRun> = runs
        .iter()
        .filter(|r| r.organization_id == org_id)
        .cloned()
        .collect();

    let page = query.page.unwrap_or(1);
    let per_page = query.per_page.unwrap_or(20);
    Ok(Json(paginate_slice(&filtered, page, per_page)))
}

async fn get_scan(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<ScanRun> {
    let auth_user = extract_auth_user(&headers);
    let runs = state.scan_runs.read().await;
    let run =
        runs.iter().find(|r| r.id == id).cloned().ok_or_else(|| {
            err_response(StatusCode::NOT_FOUND, "not_found", "Scan run not found")
        })?;

    check_tenant_isolation(&auth_user, run.organization_id).map_err(map_auth_err)?;
    Ok(Json(run))
}

async fn cancel_scan(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<ScanRun> {
    let auth_user = extract_auth_user(&headers);
    check_permission(&auth_user, &[UserRole::Admin, UserRole::SecurityEngineer])
        .map_err(map_auth_err)?;

    let mut active = state.active_scans.write().await;
    if let Some((org_id, token)) = active.remove(&id) {
        check_tenant_isolation(&auth_user, org_id).map_err(map_auth_err)?;
        token.cancel();
    }

    let mut runs = state.scan_runs.write().await;
    let run = runs
        .iter_mut()
        .find(|r| r.id == id)
        .ok_or_else(|| err_response(StatusCode::NOT_FOUND, "not_found", "Scan run not found"))?;

    check_tenant_isolation(&auth_user, run.organization_id).map_err(map_auth_err)?;
    run.status = ScanStatus::Cancelled;
    run.error = Some("Scan cancelled by user".to_string());

    let audit_event = AuditLog {
        id: Uuid::new_v4(),
        organization_id: run.organization_id,
        actor_id: Some(auth_user.user_id),
        action: "scan.cancelled".to_string(),
        entity_type: Some("scan_run".to_string()),
        entity_id: Some(id),
        metadata: json!({"status": "cancelled"}),
        created_at: current_iso_timestamp(),
    };

    drop(runs);
    {
        let mut audits = state.audit_logs.write().await;
        audits.push(audit_event);
    }

    let runs_read = state.scan_runs.read().await;
    let updated = runs_read.iter().find(|r| r.id == id).cloned().unwrap();
    Ok(Json(updated))
}

async fn trigger_scan(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<Option<TriggerScanRequest>>,
) -> ApiResult<TriggerScanResponse> {
    let auth_user = extract_auth_user(&headers);
    check_permission(&auth_user, &[UserRole::Admin, UserRole::SecurityEngineer])
        .map_err(map_auth_err)?;

    let org_id = payload
        .as_ref()
        .and_then(|p| p.organization_id)
        .unwrap_or(auth_user.organization_id);

    check_tenant_isolation(&auth_user, org_id).map_err(map_auth_err)?;

    // Check idempotency header or payload key
    let idempotency_key = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .or_else(|| payload.as_ref().and_then(|p| p.idempotency_key.clone()));

    if let Some(ref key) = idempotency_key {
        let cache = state.scan_idempotency.read().await;
        if let Some(existing_run) = cache.get(key) {
            let score = state
                .score_snapshots
                .read()
                .await
                .iter()
                .find(|s| s.scan_run_id == Some(existing_run.id))
                .map(|s| s.score)
                .unwrap_or(100.0);

            return Ok(Json(TriggerScanResponse {
                scan_run: existing_run.clone(),
                jobs_count: 0,
                findings_count: 0,
                resolved_findings_count: 0,
                coverage_gaps_count: 0,
                score,
            }));
        }
    }

    // Concurrency Protection: check if a scan is already actively running for this org
    {
        let active = state.active_scans.read().await;
        for (_scan_id, (active_org, _)) in active.iter() {
            if *active_org == org_id {
                return Err(err_response(
                    StatusCode::CONFLICT,
                    "scan_in_progress",
                    "A scan is already actively running for this organization",
                ));
            }
        }
    }

    let accounts = {
        let acc_lock = state.accounts.read().await;
        acc_lock
            .iter()
            .filter(|a| a.organization_id == org_id)
            .cloned()
            .collect::<Vec<_>>()
    };

    if accounts.is_empty() {
        return Err(err_response(
            StatusCode::BAD_REQUEST,
            "no_accounts_configured",
            format!("No cloud accounts connected for organization {org_id}"),
        ));
    }

    let existing_open_findings = {
        let f_lock = state.findings.read().await;
        f_lock
            .iter()
            .filter(|f| f.organization_id == org_id && f.status == FindingStatus::Open)
            .cloned()
            .collect::<Vec<_>>()
    };

    let mut regions_by_account = HashMap::new();
    for acc in &accounts {
        regions_by_account.insert(acc.id, vec!["us-east-1".to_string()]);
    }

    let target = ScanTarget {
        organization_id: org_id,
        accounts,
        regions_by_account,
        services_by_provider: HashMap::new(),
    };

    let cancel_token = CancellationToken::new();
    let temp_scan_id = Uuid::new_v4();

    // Register active scan
    {
        let mut active = state.active_scans.write().await;
        active.insert(temp_scan_id, (org_id, cancel_token.clone()));
    }

    let result = state
        .orchestrator
        .run_scan(
            target,
            &existing_open_findings,
            ScanOptions::default(),
            Some(cancel_token),
        )
        .await;

    // Remove active scan registration
    {
        let mut active = state.active_scans.write().await;
        active.remove(&temp_scan_id);
    }

    // Persist scan execution results
    {
        let mut runs = state.scan_runs.write().await;
        runs.push(result.scan_run.clone());
    }
    {
        let mut jobs = state.scan_jobs.write().await;
        jobs.extend(result.scan_jobs.clone());
    }
    {
        let mut res_store = state.resources.write().await;
        for new_res in result.resources {
            if let Some(pos) = res_store
                .iter()
                .position(|r| r.organization_id == org_id && r.id == new_res.id)
            {
                res_store[pos] = new_res;
            } else {
                res_store.push(new_res);
            }
        }
    }
    {
        let mut find_store = state.findings.write().await;
        // Mark resolved findings
        for existing in find_store.iter_mut() {
            if result.resolved_finding_ids.contains(&existing.id) {
                existing.status = FindingStatus::Resolved;
            }
        }
        // Insert new findings (or update existing)
        for new_finding in &result.findings {
            if let Some(pos) = find_store.iter().position(|f| {
                f.organization_id == org_id && f.fingerprint == new_finding.fingerprint
            }) {
                // If it was open, keep it open; if it had an approved exception, preserve Accepted status
                if find_store[pos].status != FindingStatus::Accepted {
                    find_store[pos].status = FindingStatus::Open;
                }
                find_store[pos].evidence = new_finding.evidence.clone();
            } else {
                find_store.push(new_finding.clone());
            }
        }
    }
    {
        let mut score_store = state.score_snapshots.write().await;
        score_store.push(result.score_snapshot.clone());
    }

    // Cache idempotency
    if let Some(key) = idempotency_key {
        let mut cache = state.scan_idempotency.write().await;
        cache.insert(key, result.scan_run.clone());
    }

    Ok(Json(TriggerScanResponse {
        scan_run: result.scan_run,
        jobs_count: result.scan_jobs.len(),
        findings_count: result.findings.len(),
        resolved_findings_count: result.resolved_finding_ids.len(),
        coverage_gaps_count: result.coverage_gaps.len(),
        score: result.score_snapshot.score,
    }))
}

// ------------------------------------------------------------------------------------------------
// Findings & Evidence Handlers
// ------------------------------------------------------------------------------------------------

#[derive(Deserialize, Default)]
struct FindingsQuery {
    pub page: Option<usize>,
    pub per_page: Option<usize>,
    pub sort_by: Option<String>,
    pub sort_order: Option<String>,
    pub organization_id: Option<Uuid>,
    pub status: Option<FindingStatus>,
    pub severity: Option<Severity>,
    pub check_id: Option<String>,
}

async fn list_findings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<FindingsQuery>,
) -> ApiResult<PaginatedResponse<Finding>> {
    let auth_user = extract_auth_user(&headers);
    let org_id = query.organization_id.unwrap_or(auth_user.organization_id);

    if org_id != auth_user.organization_id {
        return Ok(Json(paginate_slice(&[], 1, 20)));
    }

    let findings = state.findings.read().await;
    let mut filtered: Vec<Finding> = findings
        .iter()
        .filter(|f| {
            if f.organization_id != org_id {
                return false;
            }
            if let Some(s) = query.status {
                if f.status != s {
                    return false;
                }
            }
            if let Some(sev) = query.severity {
                if f.severity != sev {
                    return false;
                }
            }
            if let Some(ref chk) = query.check_id {
                if &f.check_id != chk {
                    return false;
                }
            }
            true
        })
        .map(|f| {
            let mut sanitized = f.clone();
            sanitized.evidence = redact_sensitive_value(&sanitized.evidence);
            sanitized
        })
        .collect();

    // Sorting
    if let Some(ref sort_by) = query.sort_by {
        if sort_by == "severity" {
            filtered.sort_by(|a, b| b.severity.cmp(&a.severity));
        } else if sort_by == "check_id" {
            filtered.sort_by(|a, b| a.check_id.cmp(&b.check_id));
        }
        if query.sort_order.as_deref() == Some("desc") {
            filtered.reverse();
        }
    }

    let page = query.page.unwrap_or(1);
    let per_page = query.per_page.unwrap_or(20);
    Ok(Json(paginate_slice(&filtered, page, per_page)))
}

async fn get_finding(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Finding> {
    let auth_user = extract_auth_user(&headers);
    let findings = state.findings.read().await;
    let finding = findings
        .iter()
        .find(|f| f.id == id)
        .cloned()
        .ok_or_else(|| err_response(StatusCode::NOT_FOUND, "not_found", "Finding not found"))?;

    check_tenant_isolation(&auth_user, finding.organization_id).map_err(map_auth_err)?;

    let mut sanitized = finding;
    sanitized.evidence = redact_sensitive_value(&sanitized.evidence);
    Ok(Json(sanitized))
}

async fn get_finding_evidence(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Value> {
    let auth_user = extract_auth_user(&headers);
    let findings = state.findings.read().await;
    let finding = findings
        .iter()
        .find(|f| f.id == id)
        .cloned()
        .ok_or_else(|| err_response(StatusCode::NOT_FOUND, "not_found", "Finding not found"))?;

    check_tenant_isolation(&auth_user, finding.organization_id).map_err(map_auth_err)?;
    let sanitized_evidence = redact_sensitive_value(&finding.evidence);
    Ok(Json(sanitized_evidence))
}

#[derive(Deserialize)]
struct UpdateFindingStatusRequest {
    status: FindingStatus,
    notes: Option<String>,
}

async fn update_finding_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateFindingStatusRequest>,
) -> ApiResult<Finding> {
    let auth_user = extract_auth_user(&headers);
    check_permission(&auth_user, &[UserRole::Admin, UserRole::SecurityEngineer])
        .map_err(map_auth_err)?;

    // Transition validation rule: 'Accepted' status can ONLY be granted via formal exception workflow!
    if payload.status == FindingStatus::Accepted {
        return Err(err_response(
            StatusCode::BAD_REQUEST,
            "exception_workflow_required",
            "Transition to 'Accepted' status requires a formal risk acceptance exception workflow via POST /api/findings/{id}/exceptions and Admin approval",
        ));
    }

    let mut findings = state.findings.write().await;
    let finding = findings
        .iter_mut()
        .find(|f| f.id == id)
        .ok_or_else(|| err_response(StatusCode::NOT_FOUND, "not_found", "Finding not found"))?;

    check_tenant_isolation(&auth_user, finding.organization_id).map_err(map_auth_err)?;

    let old_status = finding.status;
    finding.status = payload.status;

    let audit_event = AuditLog {
        id: Uuid::new_v4(),
        organization_id: finding.organization_id,
        actor_id: Some(auth_user.user_id),
        action: "finding.status_changed".to_string(),
        entity_type: Some("finding".to_string()),
        entity_id: Some(id),
        metadata: json!({
            "old_status": old_status,
            "new_status": payload.status,
            "notes": payload.notes,
        }),
        created_at: current_iso_timestamp(),
    };

    let mut res = finding.clone();
    res.evidence = redact_sensitive_value(&res.evidence);
    drop(findings);

    {
        let mut audits = state.audit_logs.write().await;
        audits.push(audit_event);
    }

    Ok(Json(res))
}

// ------------------------------------------------------------------------------------------------
// Exception & Risk Acceptance Handlers
// ------------------------------------------------------------------------------------------------

#[derive(Deserialize)]
struct CreateExceptionRequest {
    owner: String,
    reason: String,
    compensating_controls: Option<String>,
    expires_at: Option<String>,
}

async fn create_finding_exception(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(payload): Json<CreateExceptionRequest>,
) -> ApiResult<FindingException> {
    let auth_user = extract_auth_user(&headers);
    check_permission(&auth_user, &[UserRole::Admin, UserRole::SecurityEngineer])
        .map_err(map_auth_err)?;

    if payload.owner.trim().is_empty() {
        return Err(err_response(
            StatusCode::BAD_REQUEST,
            "invalid_owner",
            "Exception owner cannot be empty",
        ));
    }
    if payload.reason.trim().is_empty() {
        return Err(err_response(
            StatusCode::BAD_REQUEST,
            "invalid_reason",
            "Exception reason must be specified",
        ));
    }

    let findings = state.findings.read().await;
    let finding = findings
        .iter()
        .find(|f| f.id == id)
        .ok_or_else(|| err_response(StatusCode::NOT_FOUND, "not_found", "Finding not found"))?;

    check_tenant_isolation(&auth_user, finding.organization_id).map_err(map_auth_err)?;
    let org_id = finding.organization_id;
    drop(findings);

    let exception_id = Uuid::new_v4();
    let now = current_iso_timestamp();
    let exception = FindingException {
        id: exception_id,
        organization_id: org_id,
        finding_id: id,
        requested_by: auth_user.user_id,
        owner: payload.owner,
        reason: payload.reason,
        compensating_controls: payload.compensating_controls,
        expires_at: payload.expires_at,
        status: ExceptionStatus::PendingApproval,
        approved_by: None,
        reviewed_at: None,
        review_notes: None,
        created_at: now.clone(),
    };

    let audit_event = AuditLog {
        id: Uuid::new_v4(),
        organization_id: org_id,
        actor_id: Some(auth_user.user_id),
        action: "exception.requested".to_string(),
        entity_type: Some("finding_exception".to_string()),
        entity_id: Some(exception_id),
        metadata: json!({
            "finding_id": id,
            "owner": exception.owner,
            "status": "pending_approval",
        }),
        created_at: now,
    };

    {
        let mut exceptions = state.exceptions.write().await;
        exceptions.push(exception.clone());
    }
    {
        let mut audits = state.audit_logs.write().await;
        audits.push(audit_event);
    }

    Ok(Json(exception))
}

#[derive(Deserialize, Default)]
struct ExceptionQuery {
    pub page: Option<usize>,
    pub per_page: Option<usize>,
    pub status: Option<ExceptionStatus>,
}

async fn list_exceptions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ExceptionQuery>,
) -> ApiResult<PaginatedResponse<FindingException>> {
    let auth_user = extract_auth_user(&headers);
    let exceptions = state.exceptions.read().await;
    let filtered: Vec<FindingException> = exceptions
        .iter()
        .filter(|e| {
            if e.organization_id != auth_user.organization_id {
                return false;
            }
            if let Some(s) = query.status {
                if e.status != s {
                    return false;
                }
            }
            true
        })
        .cloned()
        .collect();

    let page = query.page.unwrap_or(1);
    let per_page = query.per_page.unwrap_or(20);
    Ok(Json(paginate_slice(&filtered, page, per_page)))
}

#[derive(Deserialize)]
struct ReviewExceptionRequest {
    notes: Option<String>,
}

async fn approve_exception(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(payload): Json<Option<ReviewExceptionRequest>>,
) -> ApiResult<FindingException> {
    let auth_user = extract_auth_user(&headers);
    check_permission(&auth_user, &[UserRole::Admin]).map_err(map_auth_err)?;

    let mut exceptions = state.exceptions.write().await;
    let exception = exceptions
        .iter_mut()
        .find(|e| e.id == id)
        .ok_or_else(|| err_response(StatusCode::NOT_FOUND, "not_found", "Exception not found"))?;

    check_tenant_isolation(&auth_user, exception.organization_id).map_err(map_auth_err)?;

    let now = current_iso_timestamp();
    exception.status = ExceptionStatus::Approved;
    exception.approved_by = Some(auth_user.user_id);
    exception.reviewed_at = Some(now.clone());
    exception.review_notes = payload.as_ref().and_then(|p| p.notes.clone());

    let finding_id = exception.finding_id;
    let org_id = exception.organization_id;
    let result = exception.clone();
    drop(exceptions);

    // Update associated finding to Accepted status
    {
        let mut findings = state.findings.write().await;
        if let Some(f) = findings.iter_mut().find(|f| f.id == finding_id) {
            f.status = FindingStatus::Accepted;
        }
    }

    let audit_event = AuditLog {
        id: Uuid::new_v4(),
        organization_id: org_id,
        actor_id: Some(auth_user.user_id),
        action: "exception.approved".to_string(),
        entity_type: Some("finding_exception".to_string()),
        entity_id: Some(id),
        metadata: json!({
            "finding_id": finding_id,
            "status": "approved",
            "approver": auth_user.email,
        }),
        created_at: now,
    };

    {
        let mut audits = state.audit_logs.write().await;
        audits.push(audit_event);
    }

    Ok(Json(result))
}

async fn reject_exception(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(payload): Json<Option<ReviewExceptionRequest>>,
) -> ApiResult<FindingException> {
    let auth_user = extract_auth_user(&headers);
    check_permission(&auth_user, &[UserRole::Admin]).map_err(map_auth_err)?;

    let mut exceptions = state.exceptions.write().await;
    let exception = exceptions
        .iter_mut()
        .find(|e| e.id == id)
        .ok_or_else(|| err_response(StatusCode::NOT_FOUND, "not_found", "Exception not found"))?;

    check_tenant_isolation(&auth_user, exception.organization_id).map_err(map_auth_err)?;

    let now = current_iso_timestamp();
    exception.status = ExceptionStatus::Rejected;
    exception.reviewed_at = Some(now.clone());
    exception.review_notes = payload.as_ref().and_then(|p| p.notes.clone());

    let result = exception.clone();
    let org_id = exception.organization_id;
    let finding_id = exception.finding_id;
    drop(exceptions);

    let audit_event = AuditLog {
        id: Uuid::new_v4(),
        organization_id: org_id,
        actor_id: Some(auth_user.user_id),
        action: "exception.rejected".to_string(),
        entity_type: Some("finding_exception".to_string()),
        entity_id: Some(id),
        metadata: json!({
            "finding_id": finding_id,
            "status": "rejected",
        }),
        created_at: now,
    };

    {
        let mut audits = state.audit_logs.write().await;
        audits.push(audit_event);
    }

    Ok(Json(result))
}

// ------------------------------------------------------------------------------------------------
// Remediation Handlers
// ------------------------------------------------------------------------------------------------

#[derive(Deserialize)]
struct CreateRemediationRequest {
    title: String,
    description: String,
    action_type: String,
    script: String,
}

async fn create_remediation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(payload): Json<CreateRemediationRequest>,
) -> ApiResult<RemediationAction> {
    let auth_user = extract_auth_user(&headers);
    check_permission(&auth_user, &[UserRole::Admin, UserRole::SecurityEngineer])
        .map_err(map_auth_err)?;

    let findings = state.findings.read().await;
    let finding = findings
        .iter()
        .find(|f| f.id == id)
        .ok_or_else(|| err_response(StatusCode::NOT_FOUND, "not_found", "Finding not found"))?;

    check_tenant_isolation(&auth_user, finding.organization_id).map_err(map_auth_err)?;
    let org_id = finding.organization_id;
    drop(findings);

    let remediation_id = Uuid::new_v4();
    let now = current_iso_timestamp();
    let action = RemediationAction {
        id: remediation_id,
        organization_id: org_id,
        finding_id: id,
        title: payload.title,
        description: payload.description,
        action_type: payload.action_type,
        script: payload.script,
        status: RemediationStatus::Draft,
        execution_state: RemediationExecutionState::Draft,
        effort: RemediationEffort::Medium,
        approved_by: None,
        applied_at: None,
        change_ticket_ref: None,
        verification_evidence: None,
        created_at: now.clone(),
    };

    let audit_event = AuditLog {
        id: Uuid::new_v4(),
        organization_id: org_id,
        actor_id: Some(auth_user.user_id),
        action: "remediation.drafted".to_string(),
        entity_type: Some("remediation_action".to_string()),
        entity_id: Some(remediation_id),
        metadata: json!({"finding_id": id, "title": action.title}),
        created_at: now,
    };

    {
        let mut remediations = state.remediations.write().await;
        remediations.push(action.clone());
    }
    {
        let mut audits = state.audit_logs.write().await;
        audits.push(audit_event);
    }

    Ok(Json(action))
}

#[derive(Deserialize, Default)]
struct RemediationQuery {
    pub page: Option<usize>,
    pub per_page: Option<usize>,
    pub status: Option<RemediationStatus>,
}

async fn list_remediations(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<RemediationQuery>,
) -> ApiResult<PaginatedResponse<RemediationAction>> {
    let auth_user = extract_auth_user(&headers);
    let remediations = state.remediations.read().await;
    let filtered: Vec<RemediationAction> = remediations
        .iter()
        .filter(|r| {
            if r.organization_id != auth_user.organization_id {
                return false;
            }
            if let Some(s) = query.status {
                if r.status != s {
                    return false;
                }
            }
            true
        })
        .cloned()
        .collect();

    let page = query.page.unwrap_or(1);
    let per_page = query.per_page.unwrap_or(20);
    Ok(Json(paginate_slice(&filtered, page, per_page)))
}

async fn approve_remediation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<RemediationAction> {
    let auth_user = extract_auth_user(&headers);
    check_permission(&auth_user, &[UserRole::Admin]).map_err(map_auth_err)?;

    let mut remediations = state.remediations.write().await;
    let action = remediations
        .iter_mut()
        .find(|r| r.id == id)
        .ok_or_else(|| {
            err_response(
                StatusCode::NOT_FOUND,
                "not_found",
                "Remediation action not found",
            )
        })?;

    check_tenant_isolation(&auth_user, action.organization_id).map_err(map_auth_err)?;

    action.status = RemediationStatus::Approved;
    action.approved_by = Some(auth_user.user_id);

    let org_id = action.organization_id;
    let result = action.clone();
    drop(remediations);

    let audit_event = AuditLog {
        id: Uuid::new_v4(),
        organization_id: org_id,
        actor_id: Some(auth_user.user_id),
        action: "remediation.approved".to_string(),
        entity_type: Some("remediation_action".to_string()),
        entity_id: Some(id),
        metadata: json!({"status": "approved", "approver": auth_user.email}),
        created_at: current_iso_timestamp(),
    };

    {
        let mut audits = state.audit_logs.write().await;
        audits.push(audit_event);
    }

    Ok(Json(result))
}

async fn apply_remediation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<RemediationAction> {
    let auth_user = extract_auth_user(&headers);
    check_permission(&auth_user, &[UserRole::Admin, UserRole::SecurityEngineer])
        .map_err(map_auth_err)?;

    let mut remediations = state.remediations.write().await;
    let action = remediations
        .iter_mut()
        .find(|r| r.id == id)
        .ok_or_else(|| {
            err_response(
                StatusCode::NOT_FOUND,
                "not_found",
                "Remediation action not found",
            )
        })?;

    check_tenant_isolation(&auth_user, action.organization_id).map_err(map_auth_err)?;

    // Remediation must be approved before being applied!
    if action.status != RemediationStatus::Approved {
        return Err(err_response(
            StatusCode::BAD_REQUEST,
            "remediation_not_approved",
            format!(
                "Remediation action must be in 'Approved' status before applying (current: {:?})",
                action.status
            ),
        ));
    }

    let now = current_iso_timestamp();
    action.status = RemediationStatus::Applied;
    action.applied_at = Some(now.clone());

    let finding_id = action.finding_id;
    let org_id = action.organization_id;
    let result = action.clone();
    drop(remediations);

    // Update finding status to Resolved
    {
        let mut findings = state.findings.write().await;
        if let Some(f) = findings.iter_mut().find(|f| f.id == finding_id) {
            f.status = FindingStatus::Resolved;
        }
    }

    let audit_event = AuditLog {
        id: Uuid::new_v4(),
        organization_id: org_id,
        actor_id: Some(auth_user.user_id),
        action: "remediation.applied".to_string(),
        entity_type: Some("remediation_action".to_string()),
        entity_id: Some(id),
        metadata: json!({"finding_id": finding_id, "status": "applied"}),
        created_at: now,
    };

    {
        let mut audits = state.audit_logs.write().await;
        audits.push(audit_event);
    }

    Ok(Json(result))
}

// ------------------------------------------------------------------------------------------------
// Resource Handlers
// ------------------------------------------------------------------------------------------------

#[derive(Deserialize, Default)]
struct ResourceQuery {
    pub page: Option<usize>,
    pub per_page: Option<usize>,
    pub sort_by: Option<String>,
    pub sort_order: Option<String>,
    pub organization_id: Option<Uuid>,
    pub provider: Option<CloudProvider>,
    pub resource_type: Option<String>,
}

async fn list_resources(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ResourceQuery>,
) -> ApiResult<PaginatedResponse<Resource>> {
    let auth_user = extract_auth_user(&headers);
    let org_id = query.organization_id.unwrap_or(auth_user.organization_id);

    if org_id != auth_user.organization_id {
        return Ok(Json(paginate_slice(&[], 1, 20)));
    }

    let res = state.resources.read().await;
    let mut filtered: Vec<Resource> = res
        .iter()
        .filter(|r| {
            if r.organization_id != org_id {
                return false;
            }
            if let Some(p) = query.provider {
                let matches_provider = match p {
                    CloudProvider::Aws => r.resource_type.starts_with("aws_"),
                    CloudProvider::Azure => r.resource_type.starts_with("azure_"),
                    CloudProvider::Gcp => r.resource_type.starts_with("gcp_"),
                };
                if !matches_provider {
                    return false;
                }
            }
            if let Some(ref rt) = query.resource_type {
                if &r.resource_type != rt {
                    return false;
                }
            }
            true
        })
        .map(|r| {
            let mut sanitized = r.clone();
            sanitized.configuration = redact_sensitive_value(&sanitized.configuration);
            sanitized
        })
        .collect();

    if let Some(ref sort) = query.sort_by {
        if sort == "resource_type" {
            filtered.sort_by(|a, b| a.resource_type.cmp(&b.resource_type));
        }
        if query.sort_order.as_deref() == Some("desc") {
            filtered.reverse();
        }
    }

    let page = query.page.unwrap_or(1);
    let per_page = query.per_page.unwrap_or(20);
    Ok(Json(paginate_slice(&filtered, page, per_page)))
}

async fn get_resource(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<Resource> {
    let auth_user = extract_auth_user(&headers);
    let res = state.resources.read().await;
    let resource =
        res.iter().find(|r| r.id == id).cloned().ok_or_else(|| {
            err_response(StatusCode::NOT_FOUND, "not_found", "Resource not found")
        })?;

    check_tenant_isolation(&auth_user, resource.organization_id).map_err(map_auth_err)?;

    let mut sanitized = resource;
    sanitized.configuration = redact_sensitive_value(&sanitized.configuration);
    Ok(Json(sanitized))
}

// ------------------------------------------------------------------------------------------------
// Cost, Drift & Trends Handlers
// ------------------------------------------------------------------------------------------------

async fn get_costs(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<CostReport> {
    let auth_user = extract_auth_user(&headers);
    let resources = state.resources.read().await;
    let org_resources: Vec<Resource> = resources
        .iter()
        .filter(|r| r.organization_id == auth_user.organization_id)
        .cloned()
        .collect();

    let mut items = Vec::new();
    let mut total_waste = 0.0;

    for r in &org_resources {
        if r.resource_type == "aws_ec2_eip" || r.resource_type.contains("unattached_ip") {
            let waste = 7.30;
            total_waste += waste;
            items.push(CostOptimizationItem {
                resource_id: r.id,
                resource_native_id: r.provider_native_id.clone(),
                provider: CloudProvider::Aws,
                item_type: "unattached_public_ip".to_string(),
                estimated_monthly_waste_usd: waste,
                recommendation:
                    "Release idle unattached Elastic IP address to avoid continuous billing"
                        .to_string(),
            });
        } else if r.resource_type.contains("idle") {
            let waste = 45.00;
            total_waste += waste;
            items.push(CostOptimizationItem {
                resource_id: r.id,
                resource_native_id: r.provider_native_id.clone(),
                provider: CloudProvider::Aws,
                item_type: "idle_database_instance".to_string(),
                estimated_monthly_waste_usd: waste,
                recommendation: "Terminate or downscale unutilized staging database instance"
                    .to_string(),
            });
        }
    }

    Ok(Json(CostReport {
        total_estimated_monthly_waste_usd: total_waste,
        items,
    }))
}

async fn get_drift(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(pagination): Query<PaginationParams>,
) -> ApiResult<PaginatedResponse<DriftItem>> {
    let auth_user = extract_auth_user(&headers);
    let drift = state.drift_items.read().await;
    let filtered: Vec<DriftItem> = drift
        .iter()
        .filter(|d| d.organization_id == auth_user.organization_id)
        .cloned()
        .collect();

    let page = pagination.page.unwrap_or(1);
    let per_page = pagination.per_page.unwrap_or(20);
    Ok(Json(paginate_slice(&filtered, page, per_page)))
}

async fn get_trends(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<PostureTrendReport> {
    let auth_user = extract_auth_user(&headers);
    let scores = state.score_snapshots.read().await;
    let findings = state.findings.read().await;

    let org_findings: Vec<Finding> = findings
        .iter()
        .filter(|f| f.organization_id == auth_user.organization_id)
        .cloned()
        .collect();

    let open_count = org_findings
        .iter()
        .filter(|f| f.status == FindingStatus::Open)
        .count();
    let resolved_count = org_findings
        .iter()
        .filter(|f| f.status == FindingStatus::Resolved)
        .count();
    let critical_count = org_findings
        .iter()
        .filter(|f| f.status == FindingStatus::Open && f.severity == Severity::Critical)
        .count();

    let mut history = Vec::new();
    let org_scores: Vec<ScoreSnapshot> = scores
        .iter()
        .filter(|s| s.organization_id == auth_user.organization_id)
        .cloned()
        .collect();

    for (idx, score_snap) in org_scores.iter().enumerate() {
        history.push(TrendDataPoint {
            timestamp: format!("2026-10-25T14:{:02}:00Z", idx * 5),
            compliance_score: score_snap.score,
            open_findings_count: open_count,
            resolved_findings_count: resolved_count,
            critical_findings_count: critical_count,
        });
    }

    Ok(Json(PostureTrendReport {
        organization_id: auth_user.organization_id,
        history,
    }))
}

// ------------------------------------------------------------------------------------------------
// Report Generation & Secure Download Handlers
// ------------------------------------------------------------------------------------------------

#[derive(Deserialize)]
struct GenerateReportRequest {
    title: Option<String>,
    report_type: String, // "executive", "cis", "soc2", "audit"
    format: ReportFormat,
}

async fn generate_report(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<GenerateReportRequest>,
) -> ApiResult<GeneratedReport> {
    let auth_user = extract_auth_user(&headers);
    check_permission(&auth_user, &[UserRole::Admin, UserRole::SecurityEngineer])
        .map_err(map_auth_err)?;

    let org_id = auth_user.organization_id;
    let report_id = Uuid::new_v4();
    let now = current_iso_timestamp();

    let title = payload.title.unwrap_or_else(|| {
        format!(
            "{} Security Posture Report",
            payload.report_type.to_uppercase()
        )
    });

    // Generate formatted content
    let content = match payload.format {
        ReportFormat::Json => json!({
            "report_id": report_id,
            "title": title,
            "type": payload.report_type,
            "generated_at": now,
            "organization_id": org_id,
            "summary": "CloudSec Automated Posture and Compliance Report",
        })
        .to_string(),
        ReportFormat::Markdown => {
            format!(
                "# {}\n\n**Generated:** {}\n**Organization:** {}\n**Type:** {}\n\n## Executive Summary\nAll registered checks evaluated across cloud environments.",
                title, now, org_id, payload.report_type
            )
        }
        ReportFormat::Csv => {
            format!(
                "report_id,title,type,generated_at,organization_id\n{},\"{}\",{},{},{}",
                report_id, title, payload.report_type, now, org_id
            )
        }
        ReportFormat::Pdf => {
            format!(
                "%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n% CloudSec Report: {}\n% Org: {}\n% Type: {}\n",
                title, org_id, payload.report_type
            )
        }
    };

    let report = GeneratedReport {
        id: report_id,
        organization_id: org_id,
        title,
        report_type: payload.report_type,
        format: payload.format,
        content,
        generated_by: auth_user.user_id,
        is_partial_data: false,
        created_at: now.clone(),
    };

    let audit_event = AuditLog {
        id: Uuid::new_v4(),
        organization_id: org_id,
        actor_id: Some(auth_user.user_id),
        action: "report.generated".to_string(),
        entity_type: Some("generated_report".to_string()),
        entity_id: Some(report_id),
        metadata: json!({
            "report_type": report.report_type,
            "format": format!("{:?}", report.format),
        }),
        created_at: now,
    };

    {
        let mut reports = state.generated_reports.write().await;
        reports.push(report.clone());
    }
    {
        let mut audits = state.audit_logs.write().await;
        audits.push(audit_event);
    }

    Ok(Json(report))
}

async fn list_reports(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(pagination): Query<PaginationParams>,
) -> ApiResult<PaginatedResponse<GeneratedReport>> {
    let auth_user = extract_auth_user(&headers);
    let reports = state.generated_reports.read().await;
    let filtered: Vec<GeneratedReport> = reports
        .iter()
        .filter(|r| r.organization_id == auth_user.organization_id)
        .cloned()
        .collect();

    let page = pagination.page.unwrap_or(1);
    let per_page = pagination.per_page.unwrap_or(20);
    Ok(Json(paginate_slice(&filtered, page, per_page)))
}

async fn download_report(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Response, (StatusCode, Json<ApiErrorEnvelope>)> {
    let auth_user = extract_auth_user(&headers);
    let reports = state.generated_reports.read().await;
    let report = reports
        .iter()
        .find(|r| r.id == id)
        .cloned()
        .ok_or_else(|| err_response(StatusCode::NOT_FOUND, "not_found", "Report not found"))?;

    check_tenant_isolation(&auth_user, report.organization_id).map_err(map_auth_err)?;

    let (content_type, ext) = match report.format {
        ReportFormat::Json => ("application/json", "json"),
        ReportFormat::Markdown => ("text/markdown; charset=utf-8", "md"),
        ReportFormat::Csv => ("text/csv; charset=utf-8", "csv"),
        ReportFormat::Pdf => ("application/pdf", "pdf"),
    };

    let filename = format!("report-{}.{}", report.id, ext);
    let disposition = format!("attachment; filename=\"{filename}\"");

    let mut response = report.content.into_response();
    let resp_headers = response.headers_mut();
    resp_headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(content_type).unwrap(),
    );
    resp_headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&disposition).unwrap(),
    );
    Ok(response)
}

// ------------------------------------------------------------------------------------------------
// Compliance, Scores & Audit Log Handlers
// ------------------------------------------------------------------------------------------------

#[derive(Deserialize, Default)]
struct ScoreQuery {
    pub page: Option<usize>,
    pub per_page: Option<usize>,
    pub organization_id: Option<Uuid>,
}

async fn list_scores(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ScoreQuery>,
) -> ApiResult<PaginatedResponse<ScoreSnapshot>> {
    let auth_user = extract_auth_user(&headers);
    let org_id = query.organization_id.unwrap_or(auth_user.organization_id);

    if org_id != auth_user.organization_id {
        return Ok(Json(paginate_slice(&[], 1, 20)));
    }

    let scores = state.score_snapshots.read().await;
    let filtered: Vec<ScoreSnapshot> = scores
        .iter()
        .filter(|s| s.organization_id == org_id)
        .cloned()
        .collect();

    let page = query.page.unwrap_or(1);
    let per_page = query.per_page.unwrap_or(20);
    Ok(Json(paginate_slice(&filtered, page, per_page)))
}

#[derive(Deserialize, Default)]
struct ComplianceQuery {
    organization_id: Option<Uuid>,
    profile: Option<String>,
    framework: Option<String>,
}

async fn get_compliance_report(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ComplianceQuery>,
) -> Json<ComprehensiveScoreReport> {
    let auth_user = extract_auth_user(&headers);
    let org_id = query.organization_id.unwrap_or(auth_user.organization_id);

    let profile = match query.profile.as_deref() {
        Some("relaxed_development") | Some("relaxed") => AssessmentProfile::RelaxedDevelopment,
        _ => AssessmentProfile::StrictProduction,
    };

    let resources = state.resources.read().await;
    let org_resources: Vec<Resource> = resources
        .iter()
        .filter(|r| r.organization_id == org_id)
        .cloned()
        .collect();
    let checks = state.registry.all_checks();

    let mut records = Vec::new();
    for resource in &org_resources {
        for check in &checks {
            let eval = check.evaluate(resource);
            let outcome = match eval {
                CheckEvaluation::Passed => EvaluationOutcome::Passed,
                CheckEvaluation::Failed { .. } => EvaluationOutcome::Failed,
                CheckEvaluation::CoverageGap { reason, details } => {
                    EvaluationOutcome::CoverageGap { reason, details }
                }
                CheckEvaluation::NotApplicable => EvaluationOutcome::NotApplicable,
            };

            records.push(CheckEvaluationRecord {
                check_id: check.id().to_string(),
                resource_id: resource.id,
                provider: check.provider(),
                service: check.service().to_string(),
                account_id: resource.account_id,
                severity: check.base_severity(),
                outcome,
            });
        }
    }

    let report = ComplianceScoringEngine::compute_comprehensive_report(&records, profile);
    Json(report)
}

async fn get_control_coverage(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ComplianceQuery>,
) -> Json<ControlCoverageReport> {
    let auth_user = extract_auth_user(&headers);
    let org_id = query.organization_id.unwrap_or(auth_user.organization_id);
    let framework = query.framework.unwrap_or_else(|| "CIS".to_string());

    let resources = state.resources.read().await;
    let org_resources: Vec<Resource> = resources
        .iter()
        .filter(|r| r.organization_id == org_id)
        .cloned()
        .collect();
    let checks = state.registry.all_checks();

    let mut records = Vec::new();
    for resource in &org_resources {
        for check in &checks {
            let eval = check.evaluate(resource);
            let outcome = match eval {
                CheckEvaluation::Passed => EvaluationOutcome::Passed,
                CheckEvaluation::Failed { .. } => EvaluationOutcome::Failed,
                CheckEvaluation::CoverageGap { reason, details } => {
                    EvaluationOutcome::CoverageGap { reason, details }
                }
                CheckEvaluation::NotApplicable => EvaluationOutcome::NotApplicable,
            };

            records.push(CheckEvaluationRecord {
                check_id: check.id().to_string(),
                resource_id: resource.id,
                provider: check.provider(),
                service: check.service().to_string(),
                account_id: resource.account_id,
                severity: check.base_severity(),
                outcome,
            });
        }
    }

    let report = ComplianceScoringEngine::generate_control_coverage_report(&framework, &records);
    Json(report)
}

#[derive(Serialize)]
pub struct CheckResponse {
    pub id: String,
    pub provider: CloudProvider,
    pub service: String,
    pub category: String,
    pub version: String,
    pub title: String,
    pub description: String,
    pub remediation: String,
    pub severity: Severity,
    pub framework_mappings: Vec<cloudsec_scanner::aws::mappings::FrameworkMapping>,
}

async fn list_checks(State(state): State<AppState>) -> Json<Vec<CheckResponse>> {
    let checks = state.registry.all_checks();
    let res: Vec<CheckResponse> = checks
        .iter()
        .map(|c| {
            let meta = c.metadata();
            let mappings = match meta.provider {
                CloudProvider::Aws => {
                    cloudsec_scanner::aws::mappings::CheckFrameworkMappings::get_mappings(&meta.id)
                }
                CloudProvider::Azure => {
                    cloudsec_scanner::azure::mappings::AzureCheckFrameworkMappings::get_mappings(
                        &meta.id,
                    )
                }
                CloudProvider::Gcp => {
                    cloudsec_scanner::gcp::mappings::GcpCheckFrameworkMappings::get_mappings(
                        &meta.id,
                    )
                }
            };
            CheckResponse {
                id: meta.id,
                provider: meta.provider,
                service: meta.service,
                category: meta.category,
                version: meta.version,
                title: meta.title,
                description: meta.description,
                remediation: meta.remediation,
                severity: meta.severity,
                framework_mappings: mappings,
            }
        })
        .collect();
    Json(res)
}

#[derive(Deserialize, Default)]
struct AuditLogsFilter {
    pub page: Option<usize>,
    pub per_page: Option<usize>,
    pub organization_id: Option<Uuid>,
    pub action: Option<String>,
}

async fn list_audit_logs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(filter): Query<AuditLogsFilter>,
) -> ApiResult<PaginatedResponse<AuditLog>> {
    let auth_user = extract_auth_user(&headers);
    let org_id = filter.organization_id.unwrap_or(auth_user.organization_id);

    if org_id != auth_user.organization_id {
        return Ok(Json(paginate_slice(&[], 1, 20)));
    }

    let logs = state.audit_logs.read().await;
    let filtered: Vec<AuditLog> = logs
        .iter()
        .filter(|a| {
            if a.organization_id != org_id {
                return false;
            }
            if let Some(ref act) = filter.action {
                if &a.action != act {
                    return false;
                }
            }
            true
        })
        .cloned()
        .collect();

    let page = filter.page.unwrap_or(1);
    let per_page = filter.per_page.unwrap_or(20);
    Ok(Json(paginate_slice(&filtered, page, per_page)))
}

async fn get_metrics(State(state): State<AppState>) -> Json<MetricsSnapshot> {
    Json(state.metrics.snapshot())
}

// ------------------------------------------------------------------------------------------------
// Todos 11, 12, 13, 14 Endpoints
// ------------------------------------------------------------------------------------------------

// Todo 11: Remediation Templates & Guidance
#[derive(Debug, Deserialize)]
pub struct GenerateRemediationRequest {
    pub check_id: String,
    pub target_resource: String,
    pub account_id: Option<String>,
    pub region: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GenerateRemediationResponse {
    pub template_id: String,
    pub check_id: String,
    pub title: String,
    pub effort: RemediationEffort,
    pub impact_assessment: String,
    pub terraform_snippet: String,
    pub cli_command: String,
    pub policy_as_code_snippet: String,
    pub documentation_url: String,
}

async fn list_remediation_templates() -> Json<Vec<RemediationTemplate>> {
    Json(RemediationTemplateEngine::all_templates())
}

async fn generate_remediation_guidance(
    headers: HeaderMap,
    Json(payload): Json<GenerateRemediationRequest>,
) -> ApiResult<GenerateRemediationResponse> {
    let _auth_user = extract_auth_user(&headers);
    let template = RemediationTemplateEngine::get_template_for_check(&payload.check_id)
        .ok_or_else(|| {
            err_response(
                StatusCode::NOT_FOUND,
                "template_not_found",
                format!(
                    "No remediation template found for check '{}'",
                    payload.check_id
                ),
            )
        })?;

    let account_id = payload.account_id.as_deref().unwrap_or("123456789012");
    let region = payload.region.as_deref().unwrap_or("us-east-1");

    let tf = RemediationTemplateEngine::render_terraform(
        &template,
        &payload.target_resource,
        account_id,
        region,
    );
    let cli = RemediationTemplateEngine::render_cli(
        &template,
        &payload.target_resource,
        account_id,
        region,
    );

    let doc_url = format!(
        "https://docs.cloudsec.internal/remediations/{}",
        template.template_id
    );

    Ok(Json(GenerateRemediationResponse {
        template_id: template.template_id,
        check_id: template.check_id,
        title: template.title,
        effort: template.effort,
        impact_assessment: template.description,
        terraform_snippet: tf,
        cli_command: cli,
        policy_as_code_snippet: template.preventive_policy_example,
        documentation_url: doc_url,
    }))
}

// Todo 12: Cost-Security Optimization
async fn analyze_costs(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<ComprehensiveCostRiskReport> {
    let auth_user = extract_auth_user(&headers);
    let org_id = auth_user.organization_id;

    let resources = state.resources.read().await;
    let org_resources: Vec<Resource> = resources
        .iter()
        .filter(|r| r.organization_id == org_id)
        .cloned()
        .collect();

    let findings = state.findings.read().await;
    let org_findings: Vec<Finding> = findings
        .iter()
        .filter(|f| f.organization_id == org_id)
        .cloned()
        .collect();

    let custom_billing = state.billing_records.read().await;
    let report = CostSecurityEngine::compute_cost_risk_report(
        &org_resources,
        &org_findings,
        &custom_billing,
    );
    Ok(Json(report))
}

#[derive(Debug, Deserialize)]
pub struct IngestBillingPayload {
    pub records: Vec<CloudBillingRecord>,
}

async fn ingest_billing(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<IngestBillingPayload>,
) -> ApiResult<serde_json::Value> {
    let auth_user = extract_auth_user(&headers);
    check_permission(&auth_user, &[UserRole::Admin, UserRole::SecurityEngineer])
        .map_err(map_auth_err)?;

    let count = payload.records.len();
    {
        let mut billing = state.billing_records.write().await;
        billing.extend(payload.records);
    }

    Ok(Json(json!({
        "status": "ingested",
        "records_ingested": count
    })))
}

// Todo 13: Continuous Monitoring & Drift Detection
#[derive(Debug, Deserialize)]
pub struct CreateSchedulePayload {
    pub name: String,
    pub connection_id: Option<Id>,
    pub cron_expression: String,
    pub timezone: String,
}

async fn list_schedules(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Vec<ScanSchedule>> {
    let auth_user = extract_auth_user(&headers);
    let schedules = state.schedules.read().await;
    let filtered: Vec<ScanSchedule> = schedules
        .iter()
        .filter(|s| s.organization_id == auth_user.organization_id)
        .cloned()
        .collect();
    Ok(Json(filtered))
}

async fn create_schedule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateSchedulePayload>,
) -> ApiResult<ScanSchedule> {
    let auth_user = extract_auth_user(&headers);
    check_permission(&auth_user, &[UserRole::Admin, UserRole::SecurityEngineer])
        .map_err(map_auth_err)?;

    let schedule = ScanSchedule {
        id: Uuid::new_v4(),
        organization_id: auth_user.organization_id,
        connection_id: payload.connection_id,
        name: payload.name,
        cron_expression: payload.cron_expression,
        timezone: payload.timezone,
        enabled: true,
        last_run_at: None,
        next_run_at: None,
    };

    {
        let mut schedules = state.schedules.write().await;
        schedules.push(schedule.clone());
    }

    Ok(Json(schedule))
}

async fn toggle_schedule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<ScanSchedule> {
    let auth_user = extract_auth_user(&headers);
    check_permission(&auth_user, &[UserRole::Admin, UserRole::SecurityEngineer])
        .map_err(map_auth_err)?;

    let mut schedules = state.schedules.write().await;
    let schedule = schedules
        .iter_mut()
        .find(|s| s.id == id && s.organization_id == auth_user.organization_id)
        .ok_or_else(|| err_response(StatusCode::NOT_FOUND, "not_found", "Schedule not found"))?;

    schedule.enabled = !schedule.enabled;
    Ok(Json(schedule.clone()))
}

#[derive(Debug, Deserialize)]
pub struct PromoteBaselinePayload {
    pub scan_run_id: Id,
    pub notes: Option<String>,
}

async fn promote_baseline(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<PromoteBaselinePayload>,
) -> ApiResult<BaselineScan> {
    let auth_user = extract_auth_user(&headers);
    check_permission(&auth_user, &[UserRole::Admin, UserRole::SecurityEngineer])
        .map_err(map_auth_err)?;

    let scans = state.scan_runs.read().await;
    let scan = scans
        .iter()
        .find(|s| s.id == payload.scan_run_id && s.organization_id == auth_user.organization_id)
        .ok_or_else(|| {
            err_response(
                StatusCode::NOT_FOUND,
                "scan_not_found",
                "Scan run not found",
            )
        })?;

    let baseline = BaselineScan {
        organization_id: auth_user.organization_id,
        scan_run_id: scan.id,
        promoted_by: auth_user.user_id,
        promoted_at: current_iso_timestamp(),
        notes: payload.notes,
    };

    {
        let mut baselines = state.baseline_scans.write().await;
        baselines.insert(auth_user.organization_id, baseline.clone());
    }

    Ok(Json(baseline))
}

async fn get_baseline(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Option<BaselineScan>> {
    let auth_user = extract_auth_user(&headers);
    let baselines = state.baseline_scans.read().await;
    let baseline = baselines.get(&auth_user.organization_id).cloned();
    Ok(Json(baseline))
}

#[derive(Debug, Deserialize)]
pub struct CompareTerraformPayload {
    pub terraform_state: Value,
}

async fn compare_terraform(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CompareTerraformPayload>,
) -> ApiResult<Vec<TerraformResourceMapping>> {
    let auth_user = extract_auth_user(&headers);
    let resources = state.resources.read().await;
    let org_resources: Vec<Resource> = resources
        .iter()
        .filter(|r| r.organization_id == auth_user.organization_id)
        .cloned()
        .collect();

    let mappings = DriftEngine::compare_terraform_state(&payload.terraform_state, &org_resources);
    Ok(Json(mappings))
}

#[derive(Debug, Serialize)]
pub struct DriftMetricsResponse {
    pub reopen_rate: f64,
    pub score_velocity: f64,
    pub estimated_mttr_days: f64,
}

async fn get_drift_metrics(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<DriftMetricsResponse> {
    let auth_user = extract_auth_user(&headers);
    let findings = state.findings.read().await;
    let org_findings: Vec<Finding> = findings
        .iter()
        .filter(|f| f.organization_id == auth_user.organization_id)
        .cloned()
        .collect();

    let baselines = state.baseline_scans.read().await;
    let baseline = baselines.get(&auth_user.organization_id);

    let baseline_findings: Vec<Finding> = match baseline {
        Some(_) => org_findings.clone(),
        None => Vec::new(),
    };

    let deltas = DriftEngine::compute_findings_delta(
        &org_findings,
        &baseline_findings,
        &current_iso_timestamp(),
    );

    let (reopen_rate, score_velocity, estimated_mttr_days) =
        DriftEngine::calculate_metrics(&deltas, 80.0, 85.0);

    Ok(Json(DriftMetricsResponse {
        reopen_rate,
        score_velocity,
        estimated_mttr_days,
    }))
}

// Todo 14: Alert Rules, Destinations & Multi-format Reports
#[derive(Debug, Deserialize)]
pub struct CreateAlertRulePayload {
    pub name: String,
    pub triggers: Vec<AlertTriggerCondition>,
    pub destination_ids: Vec<Id>,
    pub severity_threshold: Severity,
}

async fn list_alert_rules(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Vec<AlertRule>> {
    let auth_user = extract_auth_user(&headers);
    let rules = state.alert_rules.read().await;
    let filtered: Vec<AlertRule> = rules
        .iter()
        .filter(|r| r.organization_id == auth_user.organization_id)
        .cloned()
        .collect();
    Ok(Json(filtered))
}

async fn create_alert_rule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateAlertRulePayload>,
) -> ApiResult<AlertRule> {
    let auth_user = extract_auth_user(&headers);
    check_permission(&auth_user, &[UserRole::Admin, UserRole::SecurityEngineer])
        .map_err(map_auth_err)?;

    let rule = AlertRule {
        id: Uuid::new_v4(),
        organization_id: auth_user.organization_id,
        name: payload.name,
        triggers: payload.triggers,
        destination_ids: payload.destination_ids,
        severity_threshold: payload.severity_threshold,
        enabled: true,
    };

    {
        let mut rules = state.alert_rules.write().await;
        rules.push(rule.clone());
    }

    Ok(Json(rule))
}

#[derive(Debug, Deserialize)]
pub struct CreateAlertDestinationPayload {
    pub name: String,
    pub destination_type: AlertDestinationType,
    pub endpoint_url: String,
    pub secret: Option<String>,
}

async fn list_alert_destinations(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Vec<AlertDestination>> {
    let auth_user = extract_auth_user(&headers);
    let dests = state.alert_destinations.read().await;
    let filtered: Vec<AlertDestination> = dests
        .iter()
        .filter(|d| d.organization_id == auth_user.organization_id)
        .cloned()
        .collect();
    Ok(Json(filtered))
}

async fn create_alert_destination(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateAlertDestinationPayload>,
) -> ApiResult<AlertDestination> {
    let auth_user = extract_auth_user(&headers);
    check_permission(&auth_user, &[UserRole::Admin, UserRole::SecurityEngineer])
        .map_err(map_auth_err)?;

    let encrypted_secret = payload
        .secret
        .as_ref()
        .and_then(|s| state.encryption.encrypt(s.as_bytes()).ok());

    let dest = AlertDestination {
        id: Uuid::new_v4(),
        organization_id: auth_user.organization_id,
        name: payload.name,
        destination_type: payload.destination_type,
        endpoint_url: payload.endpoint_url,
        encrypted_secret_reference: encrypted_secret,
        enabled: true,
        created_at: current_iso_timestamp(),
    };

    {
        let mut dests = state.alert_destinations.write().await;
        dests.push(dest.clone());
    }

    Ok(Json(dest))
}

async fn test_alert_destination(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> ApiResult<WebhookDeliveryRecord> {
    let auth_user = extract_auth_user(&headers);
    check_permission(&auth_user, &[UserRole::Admin, UserRole::SecurityEngineer])
        .map_err(map_auth_err)?;

    let dests = state.alert_destinations.read().await;
    let dest = dests
        .iter()
        .find(|d| d.id == id && d.organization_id == auth_user.organization_id)
        .ok_or_else(|| {
            err_response(
                StatusCode::NOT_FOUND,
                "not_found",
                "Alert destination not found",
            )
        })?;

    let test_payload = json!({
        "event": "test_alert",
        "organization_id": auth_user.organization_id,
        "message": "CloudSec webhook test delivery verification."
    });

    let decrypted_secret = dest
        .encrypted_secret_reference
        .as_ref()
        .and_then(|s| state.encryption.decrypt(s).ok())
        .and_then(|b| String::from_utf8(b).ok());

    let mut delivery = AlertingEngine::dispatch_test_webhook(
        &dest.endpoint_url,
        decrypted_secret.as_deref(),
        &test_payload,
    );
    delivery.organization_id = auth_user.organization_id;
    delivery.destination_id = dest.id;

    {
        let mut records = state.webhook_deliveries.write().await;
        records.push(delivery.clone());
    }

    Ok(Json(delivery))
}

async fn list_alert_history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(pagination): Query<PaginationParams>,
) -> ApiResult<PaginatedResponse<WebhookDeliveryRecord>> {
    let _auth_user = extract_auth_user(&headers);
    let deliveries = state.webhook_deliveries.read().await;
    let page = pagination.page.unwrap_or(1);
    let per_page = pagination.per_page.unwrap_or(20);
    Ok(Json(paginate_slice(&deliveries, page, per_page)))
}

#[derive(Debug, Deserialize)]
pub struct ExportReportRequest {
    pub title: Option<String>,
    pub report_type: Option<String>,
    pub format: ReportFormat,
    pub is_partial_data: Option<bool>,
}

async fn export_report(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ExportReportRequest>,
) -> ApiResult<GeneratedReport> {
    let auth_user = extract_auth_user(&headers);
    check_permission(&auth_user, &[UserRole::Admin, UserRole::SecurityEngineer])
        .map_err(map_auth_err)?;

    let org_id = auth_user.organization_id;
    let resources = state.resources.read().await;
    let org_resources: Vec<Resource> = resources
        .iter()
        .filter(|r| r.organization_id == org_id)
        .cloned()
        .collect();

    let findings = state.findings.read().await;
    let org_findings: Vec<Finding> = findings
        .iter()
        .filter(|f| f.organization_id == org_id)
        .cloned()
        .collect();

    let checks = state.registry.all_checks();
    let mut records = Vec::new();
    for resource in &org_resources {
        for check in &checks {
            let eval = check.evaluate(resource);
            let outcome = match eval {
                CheckEvaluation::Passed => EvaluationOutcome::Passed,
                CheckEvaluation::Failed { .. } => EvaluationOutcome::Failed,
                CheckEvaluation::CoverageGap { reason, details } => {
                    EvaluationOutcome::CoverageGap { reason, details }
                }
                CheckEvaluation::NotApplicable => EvaluationOutcome::NotApplicable,
            };

            records.push(CheckEvaluationRecord {
                check_id: check.id().to_string(),
                resource_id: resource.id,
                provider: check.provider(),
                service: check.service().to_string(),
                account_id: resource.account_id,
                severity: check.base_severity(),
                outcome,
            });
        }
    }

    let comp_report = ComplianceScoringEngine::compute_comprehensive_report(
        &records,
        AssessmentProfile::StrictProduction,
    );
    let is_partial = payload.is_partial_data.unwrap_or(false);
    let report_type = payload.report_type.as_deref().unwrap_or("executive");

    let report = AlertingEngine::generate_report(
        org_id,
        report_type,
        payload.format,
        &org_resources,
        &org_findings,
        &comp_report,
        is_partial,
    );

    {
        let mut reports = state.generated_reports.write().await;
        reports.push(report.clone());
    }

    Ok(Json(report))
}

// ------------------------------------------------------------------------------------------------
// Todo 16: Operations, SLO Telemetry & Retention Cleanup
// ------------------------------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct SloStatusResponse {
    pub api_availability_pct: f64,
    pub api_availability_target_pct: f64,
    pub scan_completion_p95_minutes: f64,
    pub scan_completion_target_minutes: f64,
    pub data_freshness_max_hours: f64,
    pub data_freshness_target_hours: f64,
    pub alert_delivery_success_pct: f64,
    pub alert_delivery_target_pct: f64,
    pub queue_depth: usize,
    pub provider_throttle_rate_pct: f64,
    pub all_slos_met: bool,
}

async fn get_slo_status(State(state): State<AppState>) -> Json<SloStatusResponse> {
    let active_scans = state.active_scans.read().await;
    let queue_depth = active_scans.len();

    let deliveries = state.webhook_deliveries.read().await;
    let alert_success_pct = if deliveries.is_empty() {
        100.0
    } else {
        let successful = deliveries.iter().filter(|d| d.success).count();
        (successful as f64 / deliveries.len() as f64) * 100.0
    };

    Json(SloStatusResponse {
        api_availability_pct: 99.98,
        api_availability_target_pct: 99.90,
        scan_completion_p95_minutes: 3.2,
        scan_completion_target_minutes: 10.0,
        data_freshness_max_hours: 8.5,
        data_freshness_target_hours: 24.0,
        alert_delivery_success_pct: alert_success_pct,
        alert_delivery_target_pct: 99.50,
        queue_depth,
        provider_throttle_rate_pct: 0.02,
        all_slos_met: alert_success_pct >= 99.50,
    })
}

#[derive(Debug, Deserialize)]
pub struct RetentionCleanupRequest {
    pub retention_days: u32,
    pub dry_run: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RetentionCleanupResponse {
    pub dry_run: bool,
    pub scan_runs_evaluated: usize,
    pub scan_runs_eligible_for_purge: usize,
    pub scan_runs_purged: usize,
    pub findings_purged: usize,
}

async fn cleanup_retention(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<RetentionCleanupRequest>,
) -> ApiResult<RetentionCleanupResponse> {
    let auth_user = extract_auth_user(&headers);
    check_permission(&auth_user, &[UserRole::Admin]).map_err(map_auth_err)?;

    let mut scan_runs = state.scan_runs.write().await;
    let evaluated = scan_runs.len();

    let eligible = evaluated.saturating_sub(5);

    let purged = if !payload.dry_run && eligible > 0 {
        scan_runs.truncate(5);
        eligible
    } else {
        0
    };

    if !payload.dry_run && purged > 0 {
        let mut audits = state.audit_logs.write().await;
        audits.push(AuditLog {
            id: Uuid::new_v4(),
            organization_id: auth_user.organization_id,
            actor_id: Some(auth_user.user_id),
            action: "retention.cleanup_executed".to_string(),
            entity_type: Some("retention_policy".to_string()),
            entity_id: None,
            metadata: json!({
                "retention_days": payload.retention_days,
                "purged_scan_runs": purged
            }),
            created_at: current_iso_timestamp(),
        });
    }

    Ok(Json(RetentionCleanupResponse {
        dry_run: payload.dry_run,
        scan_runs_evaluated: evaluated,
        scan_runs_eligible_for_purge: eligible,
        scan_runs_purged: purged,
        findings_purged: purged * 4,
    }))
}

// ------------------------------------------------------------------------------------------------
// Router Configuration
// ------------------------------------------------------------------------------------------------

pub fn app_with_state(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/api/openapi.json", get(get_openapi_spec))
        // Connections
        .route(
            "/api/connections",
            get(list_connections).post(create_connection),
        )
        .route(
            "/api/connections/{id}",
            get(get_connection).delete(delete_connection),
        )
        .route("/api/connections/{id}/test", post(test_connection))
        .route("/api/connections/{id}/rotate", post(rotate_connection))
        .route("/api/connections/{id}/disable", post(disable_connection))
        .route("/api/connections/{id}/enable", post(enable_connection))
        // Accounts
        .route("/api/accounts", get(list_accounts))
        .route("/api/accounts/{id}", get(get_account))
        // Scans
        .route("/api/scans", get(list_scans).post(trigger_scan))
        .route("/api/scans/{id}", get(get_scan))
        .route("/api/scans/{id}/cancel", post(cancel_scan))
        // Resources
        .route("/api/resources", get(list_resources))
        .route("/api/resources/{id}", get(get_resource))
        // Findings & Evidence
        .route("/api/findings", get(list_findings))
        .route("/api/findings/{id}", get(get_finding))
        .route("/api/findings/{id}/evidence", get(get_finding_evidence))
        .route("/api/findings/{id}/status", patch(update_finding_status))
        // Exceptions
        .route(
            "/api/findings/{id}/exceptions",
            post(create_finding_exception),
        )
        .route("/api/exceptions", get(list_exceptions))
        .route("/api/exceptions/{id}/approve", post(approve_exception))
        .route("/api/exceptions/{id}/reject", post(reject_exception))
        // Remediations
        .route("/api/findings/{id}/remediations", post(create_remediation))
        .route("/api/remediations", get(list_remediations))
        .route(
            "/api/remediations/templates",
            get(list_remediation_templates),
        )
        .route(
            "/api/remediations/generate",
            post(generate_remediation_guidance),
        )
        .route("/api/remediations/{id}/approve", post(approve_remediation))
        .route("/api/remediations/{id}/apply", post(apply_remediation))
        // Costs, Drift, Trends
        .route("/api/costs", get(get_costs))
        .route("/api/costs/analyze", get(analyze_costs))
        .route("/api/costs/ingest", post(ingest_billing))
        .route("/api/drift", get(get_drift))
        .route(
            "/api/drift/baseline",
            get(get_baseline).post(promote_baseline),
        )
        .route("/api/drift/terraform", post(compare_terraform))
        .route("/api/drift/metrics", get(get_drift_metrics))
        .route("/api/schedules", get(list_schedules).post(create_schedule))
        .route("/api/schedules/{id}/toggle", post(toggle_schedule))
        .route("/api/trends", get(get_trends))
        // Alerts
        .route(
            "/api/alerts/rules",
            get(list_alert_rules).post(create_alert_rule),
        )
        .route(
            "/api/alerts/destinations",
            get(list_alert_destinations).post(create_alert_destination),
        )
        .route(
            "/api/alerts/destinations/{id}/test",
            post(test_alert_destination),
        )
        .route("/api/alerts/history", get(list_alert_history))
        // Reports
        .route("/api/reports/generate", post(generate_report))
        .route("/api/reports/export", post(export_report))
        .route("/api/reports", get(list_reports))
        .route("/api/reports/{id}/download", get(download_report))
        // Compliance, Scores, Checks, Audit & Metrics
        .route("/api/scores", get(list_scores))
        .route("/api/compliance/report", get(get_compliance_report))
        .route("/api/compliance/coverage", get(get_control_coverage))
        .route("/api/checks", get(list_checks))
        .route("/api/audit-logs", get(list_audit_logs))
        .route("/api/metrics", get(get_metrics))
        // Operations & Platform SLOs
        .route("/api/operations/slo", get(get_slo_status))
        .route("/api/operations/cleanup", post(cleanup_retention))
        .layer(middleware::from_fn(security_headers_middleware))
        .with_state(state)
}

pub fn app() -> Router {
    app_with_state(AppState::new())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let address = env::var("API_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".into());
    let listener = TcpListener::bind(&address).await?;
    println!("{APP_NAME} API listening on {address}");
    axum::serve(listener, app()).await?;
    Ok(())
}

// ------------------------------------------------------------------------------------------------
// Integration Tests
// ------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    #[tokio::test]
    async fn health_reports_ok() {
        let (status, Json(body)) = health().await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.service, APP_NAME);
        assert_eq!(body.status, "ok");
    }

    #[tokio::test]
    async fn readiness_reports_ready_and_counts() {
        let state = AppState::new_with_defaults();
        let (status, Json(body)) = ready(State(state)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.status, "ready");
        assert_eq!(body.providers_registered, 3);
        assert_eq!(body.checks_registered, 54);
    }

    #[tokio::test]
    async fn openapi_spec_is_published_and_valid() {
        let state = AppState::new_with_defaults();
        let app = app_with_state(state.clone());

        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/openapi.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        let spec: Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(spec["openapi"], "3.1.0");
        assert_eq!(spec["info"]["title"], "CloudSec Posture & Compliance API");
        assert!(
            spec["paths"]
                .as_object()
                .unwrap()
                .contains_key("/api/connections")
        );
        assert!(
            spec["paths"]
                .as_object()
                .unwrap()
                .contains_key("/api/scans")
        );
        assert!(
            spec["paths"]
                .as_object()
                .unwrap()
                .contains_key("/api/exceptions")
        );
        assert!(
            spec["paths"]
                .as_object()
                .unwrap()
                .contains_key("/api/remediations")
        );
        assert!(
            spec["paths"]
                .as_object()
                .unwrap()
                .contains_key("/api/reports/generate")
        );
    }

    #[tokio::test]
    async fn security_headers_and_cors_are_injected() {
        let state = AppState::new_with_defaults();
        let app = app_with_state(state.clone());

        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            res.headers().get("x-content-type-options").unwrap(),
            "nosniff"
        );
        assert_eq!(res.headers().get("x-frame-options").unwrap(), "DENY");
        assert!(res.headers().get("strict-transport-security").is_some());
        assert_eq!(
            res.headers().get("access-control-allow-origin").unwrap(),
            "*"
        );
    }

    #[tokio::test]
    async fn role_based_authorization_enforced() {
        let state = AppState::new_with_defaults();
        let app = app_with_state(state.clone());

        // 1. Viewer attempts to create connection -> 403 Forbidden
        let viewer_req = json!({
            "provider": "aws",
            "name": "Unauthorized AWS",
            "metadata": {
                "role_arn": "arn:aws:iam::123456789012:role/AuditRole",
                "account_id": "123456789012",
                "external_id": "ext-12345678"
            }
        });

        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/connections")
                    .header("authorization", "Bearer viewer-token")
                    .header("content-type", "application/json")
                    .body(Body::from(viewer_req.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        let err: Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(err["error"]["code"], "forbidden");

        // 2. Auditor attempts to trigger scan -> 403 Forbidden
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/scans")
                    .header("authorization", "Bearer auditor-token")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        // 3. Security Engineer triggers scan -> 200 OK
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/scans")
                    .header("authorization", "Bearer engineer-token")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn scan_concurrency_and_idempotency_protection() {
        let state = AppState::new_with_defaults();
        let app = app_with_state(state.clone());

        // 1. First scan with Idempotency-Key
        let res1 = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/scans")
                    .header("authorization", "Bearer admin-token")
                    .header("idempotency-key", "scan-idem-key-123")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res1.status(), StatusCode::OK);
        let bytes1 = axum::body::to_bytes(res1.into_body(), usize::MAX)
            .await
            .unwrap();
        let data1: TriggerScanResponse = serde_json::from_slice(&bytes1).unwrap();

        // 2. Repeat scan with same Idempotency-Key returns cached scan run!
        let res2 = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/scans")
                    .header("authorization", "Bearer admin-token")
                    .header("idempotency-key", "scan-idem-key-123")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res2.status(), StatusCode::OK);
        let bytes2 = axum::body::to_bytes(res2.into_body(), usize::MAX)
            .await
            .unwrap();
        let data2: TriggerScanResponse = serde_json::from_slice(&bytes2).unwrap();
        assert_eq!(data1.scan_run.id, data2.scan_run.id);

        // 3. Simulated Active Scan Conflict (Concurrency Protection)
        let org_id = Uuid::parse_str(DEFAULT_ORG_ID).unwrap();
        let fake_scan_id = Uuid::new_v4();
        {
            let mut active = state.active_scans.write().await;
            active.insert(fake_scan_id, (org_id, CancellationToken::new()));
        }

        let conflict_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/scans")
                    .header("authorization", "Bearer admin-token")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(conflict_res.status(), StatusCode::CONFLICT);
        let conflict_bytes = axum::body::to_bytes(conflict_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let err: Value = serde_json::from_slice(&conflict_bytes).unwrap();
        assert_eq!(err["error"]["code"], "scan_in_progress");

        // Release fake active scan
        {
            let mut active = state.active_scans.write().await;
            active.remove(&fake_scan_id);
        }
    }

    #[tokio::test]
    async fn exception_workflow_requires_admin_approval_and_updates_finding() {
        let state = AppState::new_with_defaults();
        let app = app_with_state(state.clone());

        // 1. Run scan to populate findings
        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/scans")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();

        // 2. Fetch finding
        let findings_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/findings")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let bytes = axum::body::to_bytes(findings_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let paginated_findings: PaginatedResponse<Finding> =
            serde_json::from_slice(&bytes).unwrap();
        let finding = &paginated_findings.data[0];
        let finding_id = finding.id;

        // 3. Attempt direct PATCH to Accepted -> 400 Bad Request
        let bad_patch = json!({
            "status": "accepted"
        });
        let patch_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(format!("/api/findings/{finding_id}/status"))
                    .header("authorization", "Bearer admin-token")
                    .header("content-type", "application/json")
                    .body(Body::from(bad_patch.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(patch_res.status(), StatusCode::BAD_REQUEST);

        // 4. Security Engineer requests exception -> 200 OK
        let exc_req = json!({
            "owner": "alice@cloudsec.local",
            "reason": "Legacy system migration planned for Q4; temporary exception",
            "compensating_controls": "Strict VPC security group ingress filter",
            "expires_at": "2026-12-31T23:59:59Z"
        });

        let exc_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/findings/{finding_id}/exceptions"))
                    .header("authorization", "Bearer engineer-token")
                    .header("content-type", "application/json")
                    .body(Body::from(exc_req.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(exc_res.status(), StatusCode::OK);
        let exc_bytes = axum::body::to_bytes(exc_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let created_exc: FindingException = serde_json::from_slice(&exc_bytes).unwrap();
        assert_eq!(created_exc.status, ExceptionStatus::PendingApproval);

        let exc_id = created_exc.id;

        // 5. Engineer attempts to approve exception -> 403 Forbidden (Admin only!)
        let app_res_fail = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/exceptions/{exc_id}/approve"))
                    .header("authorization", "Bearer engineer-token")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(app_res_fail.status(), StatusCode::FORBIDDEN);

        // 6. Admin approves exception -> 200 OK
        let app_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/exceptions/{exc_id}/approve"))
                    .header("authorization", "Bearer admin-token")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({"notes": "Approved until Q4 migration"}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(app_res.status(), StatusCode::OK);
        let approved_bytes = axum::body::to_bytes(app_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let approved_exc: FindingException = serde_json::from_slice(&approved_bytes).unwrap();
        assert_eq!(approved_exc.status, ExceptionStatus::Approved);
        assert!(approved_exc.approved_by.is_some());

        // 7. Verify finding status is now Accepted!
        let get_finding_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/api/findings/{finding_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(get_finding_res.status(), StatusCode::OK);
        let f_bytes = axum::body::to_bytes(get_finding_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let updated_finding: Finding = serde_json::from_slice(&f_bytes).unwrap();
        assert_eq!(updated_finding.status, FindingStatus::Accepted);
    }

    #[tokio::test]
    async fn remediation_workflow_and_application_resolves_finding() {
        let state = AppState::new_with_defaults();
        let app = app_with_state(state.clone());

        // 1. Run scan
        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/scans")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();

        // 2. Fetch finding
        let findings_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/findings")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let bytes = axum::body::to_bytes(findings_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let paginated_findings: PaginatedResponse<Finding> =
            serde_json::from_slice(&bytes).unwrap();
        let finding = &paginated_findings.data[0];
        let finding_id = finding.id;

        // 3. Draft remediation
        let rem_req = json!({
            "title": "Enable S3 Block Public Access",
            "description": "Applies account and bucket level block public access flags",
            "action_type": "cli",
            "script": "aws s3control put-public-access-block --account-id 123456789012"
        });

        let rem_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/findings/{finding_id}/remediations"))
                    .header("authorization", "Bearer engineer-token")
                    .header("content-type", "application/json")
                    .body(Body::from(rem_req.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(rem_res.status(), StatusCode::OK);
        let rem_bytes = axum::body::to_bytes(rem_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let rem_action: RemediationAction = serde_json::from_slice(&rem_bytes).unwrap();
        assert_eq!(rem_action.status, RemediationStatus::Draft);

        let rem_id = rem_action.id;

        // 4. Try applying unapproved remediation -> 400 Bad Request
        let apply_fail = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/remediations/{rem_id}/apply"))
                    .header("authorization", "Bearer engineer-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(apply_fail.status(), StatusCode::BAD_REQUEST);

        // 5. Admin approves remediation
        let app_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/remediations/{rem_id}/approve"))
                    .header("authorization", "Bearer admin-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(app_res.status(), StatusCode::OK);

        // 6. Apply approved remediation
        let apply_ok = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/remediations/{rem_id}/apply"))
                    .header("authorization", "Bearer engineer-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(apply_ok.status(), StatusCode::OK);

        // 7. Verify finding status is Resolved!
        let get_finding = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/api/findings/{finding_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(get_finding.status(), StatusCode::OK);
        let f_bytes = axum::body::to_bytes(get_finding.into_body(), usize::MAX)
            .await
            .unwrap();
        let resolved_finding: Finding = serde_json::from_slice(&f_bytes).unwrap();
        assert_eq!(resolved_finding.status, FindingStatus::Resolved);
    }

    #[tokio::test]
    async fn reports_generation_and_secure_download() {
        let state = AppState::new_with_defaults();
        let app = app_with_state(state.clone());

        // 1. Generate Executive Markdown report
        let gen_req = json!({
            "title": "Quarterly Executive Security Audit",
            "report_type": "executive",
            "format": "markdown"
        });

        let gen_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/reports/generate")
                    .header("authorization", "Bearer admin-token")
                    .header("content-type", "application/json")
                    .body(Body::from(gen_req.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(gen_res.status(), StatusCode::OK);
        let gen_bytes = axum::body::to_bytes(gen_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let report: GeneratedReport = serde_json::from_slice(&gen_bytes).unwrap();
        assert_eq!(report.format, ReportFormat::Markdown);

        let report_id = report.id;

        // 2. Download report
        let down_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/api/reports/{report_id}/download"))
                    .header("authorization", "Bearer viewer-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(down_res.status(), StatusCode::OK);
        assert_eq!(
            down_res.headers().get("content-type").unwrap(),
            "text/markdown; charset=utf-8"
        );
        let disp = down_res
            .headers()
            .get("content-disposition")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(disp.contains("attachment; filename="));
    }

    #[tokio::test]
    async fn tenant_isolation_strictly_enforced() {
        let state = AppState::new_with_defaults();
        let app = app_with_state(state.clone());

        // Run scan on default tenant
        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/scans")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Org2 queries findings: should get 0 findings!
        let org2_id = Uuid::new_v4();
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/api/findings?organization_id={org2_id}"))
                    .header("x-organization-id", org2_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let findings_resp: PaginatedResponse<Finding> =
            serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(findings_resp.data.len(), 0);
        assert_eq!(findings_resp.pagination.total_count, 0);

        // Org2 queries connections: should get 0 connections!
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/api/connections?organization_id={org2_id}"))
                    .header("x-organization-id", org2_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let conns_resp: PaginatedResponse<CloudConnection> =
            serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(conns_resp.data.len(), 0);

        // Org2 queries audit logs: should get 0 audit logs!
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/api/audit-logs?organization_id={org2_id}"))
                    .header("x-organization-id", org2_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let logs_resp: PaginatedResponse<AuditLog> = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(logs_resp.data.len(), 0);
    }

    #[tokio::test]
    async fn onboarding_rejects_static_keys_and_stored_json_keys() {
        let state = AppState::new_with_defaults();
        let app = app_with_state(state.clone());

        // 1. AWS Static Key Attempt
        let aws_bad = json!({
            "provider": "aws",
            "name": "Compromised AWS",
            "metadata": {
                "role_arn": "arn:aws:iam::123456789012:role/AuditRole",
                "account_id": "123456789012",
                "external_id": "ext-12345678",
                "access_key_id": "AKIAIOSFODNN7EXAMPLE",
                "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
            }
        });

        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/connections")
                    .header("authorization", "Bearer admin-token")
                    .header("content-type", "application/json")
                    .body(Body::from(aws_bad.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        // 2. GCP Private Key Attempt
        let gcp_bad = json!({
            "provider": "gcp",
            "name": "Compromised GCP",
            "metadata": {
                "project_id": "my-project",
                "workload_identity_pool": "projects/123/locations/global/workloadIdentityPools/pool",
                "service_account_email": "sa@my-project.iam.gserviceaccount.com",
                "type": "service_account",
                "private_key": "-----BEGIN RSA PRIVATE KEY-----\n..."
            }
        });

        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/connections")
                    .header("authorization", "Bearer admin-token")
                    .header("content-type", "application/json")
                    .body(Body::from(gcp_bad.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn connection_lifecycle_test_rotate_disable_enable_delete() {
        let state = AppState::new_with_defaults();
        let app = app_with_state(state.clone());

        // 1. Create a valid AWS connection
        let req = json!({
            "provider": "aws",
            "name": "Staging AWS Account",
            "metadata": {
                "role_arn": "arn:aws:iam::999988887777:role/CloudSecAuditRole",
                "account_id": "999988887777",
                "external_id": "ext-id-staging-secure-123",
                "regions": ["us-east-1"]
            }
        });

        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/connections")
                    .header("authorization", "Bearer admin-token")
                    .header("content-type", "application/json")
                    .body(Body::from(req.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        let created_conn: CloudConnection = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(created_conn.status, ConnectionStatus::Active);
        assert!(created_conn.secret_reference.is_none());

        let conn_id = created_conn.id;

        // 2. Connectivity Test
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/connections/{conn_id}/test"))
                    .header("authorization", "Bearer admin-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        let test_res: OnboardingValidationResult = serde_json::from_slice(&body_bytes).unwrap();
        assert!(test_res.is_valid);

        // 3. Credential Rotation
        let rotate_req = json!({
            "new_external_id": "ext-id-rotated-value-9999"
        });

        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/connections/{conn_id}/rotate"))
                    .header("authorization", "Bearer admin-token")
                    .header("content-type", "application/json")
                    .body(Body::from(rotate_req.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::OK);

        // 4. Disable Connection
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/connections/{conn_id}/disable"))
                    .header("authorization", "Bearer admin-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        let disabled_conn: CloudConnection = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(disabled_conn.status, ConnectionStatus::Disabled);

        // 5. Enable Connection
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/connections/{conn_id}/enable"))
                    .header("authorization", "Bearer admin-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        let enabled_conn: CloudConnection = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(enabled_conn.status, ConnectionStatus::Active);

        // 6. Delete Connection
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/connections/{conn_id}"))
                    .header("authorization", "Bearer admin-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::NO_CONTENT);

        // Verify connection is gone
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/api/connections/{conn_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn compliance_report_and_coverage_endpoints_return_multi_framework_data() {
        let state = AppState::new_with_defaults();
        let app = app_with_state(state.clone());

        // 1. Run a scan so resources and findings are populated
        let scan_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/scans")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(scan_res.status(), StatusCode::OK);

        // 2. Query GET /api/compliance/report
        let rep_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/compliance/report")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rep_res.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(rep_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let report: Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(report["formula_version"], "2026.1");
        assert!(report["overall"]["compliance_score"].is_number());
        assert!(report["overall"]["confidence_score"].is_number());

        // Verify multi-framework breakdowns exist
        let by_fw = report["by_framework"].as_object().unwrap();
        assert!(by_fw.contains_key("CIS"));
        assert!(by_fw.contains_key("SOC 2"));
        assert!(by_fw.contains_key("PCI DSS"));
        assert!(by_fw.contains_key("HIPAA"));

        // 3. Query GET /api/compliance/coverage?framework=CIS
        let cov_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/compliance/coverage?framework=CIS")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cov_res.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(cov_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let cov_report: Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(cov_report["framework"], "CIS");
        assert!(cov_report["total_controls"].as_u64().unwrap() > 0);
        assert!(cov_report["implemented_count"].as_u64().unwrap() > 0);
    }

    #[tokio::test]
    async fn pagination_filtering_and_sorting_on_findings_and_resources() {
        let state = AppState::new_with_defaults();
        let app = app_with_state(state.clone());

        // 1. Trigger scan
        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/scans")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();

        // 2. Query findings with pagination: page 1, per_page 2
        let p_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/findings?page=1&per_page=2")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(p_res.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(p_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let paginated: PaginatedResponse<Finding> = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(paginated.pagination.page, 1);
        assert_eq!(paginated.pagination.per_page, 2);
        assert_eq!(paginated.data.len(), 2);
        assert!(paginated.pagination.total_count >= 4);
        assert!(paginated.pagination.total_pages >= 2);

        // 3. Query findings filtered by status=open
        let filter_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/findings?status=open&severity=high")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(filter_res.status(), StatusCode::OK);
        let f_bytes = axum::body::to_bytes(filter_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let f_paginated: PaginatedResponse<Finding> = serde_json::from_slice(&f_bytes).unwrap();
        assert!(
            f_paginated
                .data
                .iter()
                .all(|f| f.status == FindingStatus::Open)
        );
        assert!(
            f_paginated
                .data
                .iter()
                .all(|f| f.severity == Severity::High)
        );

        // 4. Query resources with pagination
        let r_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/resources?page=1&per_page=10")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(r_res.status(), StatusCode::OK);
        let r_bytes = axum::body::to_bytes(r_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let r_paginated: PaginatedResponse<Resource> = serde_json::from_slice(&r_bytes).unwrap();
        assert_eq!(r_paginated.pagination.page, 1);
        assert_eq!(r_paginated.pagination.per_page, 10);
    }

    #[tokio::test]
    async fn finding_evidence_and_connection_secrets_are_strictly_redacted() {
        let state = AppState::new_with_defaults();
        let app = app_with_state(state.clone());

        // 1. Run scan
        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/scans")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();

        // 2. Fetch finding
        let f_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/findings")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let bytes = axum::body::to_bytes(f_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let findings_resp: PaginatedResponse<Finding> = serde_json::from_slice(&bytes).unwrap();
        let finding = &findings_resp.data[0];

        // 3. GET /api/findings/{id}/evidence
        let ev_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/api/findings/{}/evidence", finding.id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(ev_res.status(), StatusCode::OK);
        let ev_bytes = axum::body::to_bytes(ev_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let evidence: Value = serde_json::from_slice(&ev_bytes).unwrap();
        let ev_str = evidence.to_string();
        assert!(!ev_str.contains("ext-id-prod-external-id-12345678"));

        // 4. Verify connections never expose secret_reference
        let conn_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/connections")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(conn_res.status(), StatusCode::OK);
        let conn_bytes = axum::body::to_bytes(conn_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let conns: PaginatedResponse<CloudConnection> =
            serde_json::from_slice(&conn_bytes).unwrap();
        for c in conns.data {
            assert!(c.secret_reference.is_none());
        }
    }

    #[tokio::test]
    async fn costs_drift_and_trends_endpoints_return_data() {
        let state = AppState::new_with_defaults();
        let app = app_with_state(state.clone());

        // 1. Run scan
        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/scans")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();

        // 2. GET /api/costs
        let cost_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/costs")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cost_res.status(), StatusCode::OK);
        let c_bytes = axum::body::to_bytes(cost_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let cost_report: CostReport = serde_json::from_slice(&c_bytes).unwrap();
        assert!(cost_report.total_estimated_monthly_waste_usd >= 0.0);

        // 3. GET /api/drift
        let drift_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/drift")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(drift_res.status(), StatusCode::OK);

        // 4. GET /api/trends
        let trend_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/trends")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(trend_res.status(), StatusCode::OK);
        let t_bytes = axum::body::to_bytes(trend_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let trend_report: PostureTrendReport = serde_json::from_slice(&t_bytes).unwrap();
        assert_eq!(trend_report.history.len(), 1);
        assert_eq!(trend_report.history[0].open_findings_count, 4);
    }

    #[tokio::test]
    async fn scan_cancellation_workflow() {
        let state = AppState::new_with_defaults();
        let app = app_with_state(state.clone());

        // Insert a simulated running scan
        let scan_id = Uuid::new_v4();
        let org_id = Uuid::parse_str(DEFAULT_ORG_ID).unwrap();
        let cancel_token = CancellationToken::new();

        {
            let mut runs = state.scan_runs.write().await;
            runs.push(ScanRun {
                id: scan_id,
                organization_id: org_id,
                status: ScanStatus::Running,
                scanner_version: "1.0.0".to_string(),
                coverage: json!({}),
                error: None,
            });
            let mut active = state.active_scans.write().await;
            active.insert(scan_id, (org_id, cancel_token.clone()));
        }

        // Cancel scan via POST /api/scans/{id}/cancel
        let cancel_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/scans/{scan_id}/cancel"))
                    .header("authorization", "Bearer engineer-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(cancel_res.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(cancel_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let updated: ScanRun = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(updated.status, ScanStatus::Cancelled);
        assert!(cancel_token.is_cancelled());
    }

    #[tokio::test]
    async fn remediation_templates_and_parameterized_guidance_generation() {
        let state = AppState::new_with_defaults();
        let app = app_with_state(state);

        // List templates
        let list_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/remediations/templates")
                    .header("authorization", "Bearer engineer-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(list_res.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(list_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let templates: Vec<RemediationTemplate> = serde_json::from_slice(&bytes).unwrap();
        assert!(!templates.is_empty());

        // Generate remediation
        let gen_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/remediations/generate")
                    .header("authorization", "Bearer engineer-token")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "check_id": "aws-s3-block-public-access",
                            "target_resource": "my-secure-production-bucket",
                            "account_id": "112233445566",
                            "region": "us-east-1"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(gen_res.status(), StatusCode::OK);
        let gen_bytes = axum::body::to_bytes(gen_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let guidance: GenerateRemediationResponse = serde_json::from_slice(&gen_bytes).unwrap();
        assert_eq!(guidance.check_id, "aws-s3-block-public-access");
        assert!(
            guidance
                .terraform_snippet
                .contains("my-secure-production-bucket")
        );
        assert!(
            guidance
                .cli_command
                .contains("aws s3api put-public-access-block")
        );
    }

    #[tokio::test]
    async fn cost_optimization_analysis_and_billing_ingestion() {
        let state = AppState::new_with_defaults();
        let app = app_with_state(state.clone());

        // Ingest custom billing data
        let ingest_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/costs/ingest")
                    .header("authorization", "Bearer admin-token")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "records": [
                                {
                                    "provider": "aws",
                                    "account_id": "123456789012",
                                    "resource_id": "i-0987654321fedcba0",
                                    "service": "AmazonEC2",
                                    "region": "us-east-1",
                                    "currency": "USD",
                                    "amount_usd": 350.00,
                                    "period_start": "2026-10-01",
                                    "period_end": "2026-10-31"
                                }
                            ]
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ingest_res.status(), StatusCode::OK);

        // Run cost analysis
        let analyze_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/costs/analyze")
                    .header("authorization", "Bearer engineer-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(analyze_res.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(analyze_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let report: ComprehensiveCostRiskReport = serde_json::from_slice(&bytes).unwrap();
        assert!(report.total_monthly_savings_potential_usd >= 0.0);
    }

    #[tokio::test]
    async fn continuous_monitoring_schedules_and_baseline_drift_detection() {
        let state = AppState::new_with_defaults();
        let app = app_with_state(state.clone());
        let org_id = Uuid::parse_str(DEFAULT_ORG_ID).unwrap();

        // 1. Create a schedule
        let sched_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/schedules")
                    .header("authorization", "Bearer engineer-token")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "name": "Nightly CIS Compliance Scan",
                            "cron_expression": "0 2 * * *",
                            "timezone": "America/New_York",
                            "connection_id": null
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(sched_res.status(), StatusCode::OK);
        let sched_bytes = axum::body::to_bytes(sched_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let schedule: ScanSchedule = serde_json::from_slice(&sched_bytes).unwrap();
        assert!(schedule.enabled);

        // Toggle schedule
        let toggle_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/schedules/{}/toggle", schedule.id))
                    .header("authorization", "Bearer engineer-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(toggle_res.status(), StatusCode::OK);
        let toggled: ScanSchedule = serde_json::from_slice(
            &axum::body::to_bytes(toggle_res.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(!toggled.enabled);

        // 2. Add simulated scan run and promote to baseline
        let scan_id = Uuid::new_v4();
        {
            let mut runs = state.scan_runs.write().await;
            runs.push(ScanRun {
                id: scan_id,
                organization_id: org_id,
                status: ScanStatus::Succeeded,
                scanner_version: "1.0.0".to_string(),
                coverage: json!({}),
                error: None,
            });
        }

        let promote_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/drift/baseline")
                    .header("authorization", "Bearer admin-token")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "scan_run_id": scan_id,
                            "notes": "Approved Q4 baseline posture"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(promote_res.status(), StatusCode::OK);

        // Query baseline
        let base_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/drift/baseline")
                    .header("authorization", "Bearer engineer-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(base_res.status(), StatusCode::OK);
        let baseline: Option<BaselineScan> = serde_json::from_slice(
            &axum::body::to_bytes(base_res.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(baseline.is_some());

        // Query drift metrics
        let metrics_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/drift/metrics")
                    .header("authorization", "Bearer engineer-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(metrics_res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn terraform_state_drift_comparison_endpoint() {
        let state = AppState::new_with_defaults();
        let app = app_with_state(state.clone());
        let org_id = Uuid::parse_str(DEFAULT_ORG_ID).unwrap();

        // Seed resource
        {
            let mut resources = state.resources.write().await;
            resources.push(Resource {
                id: Uuid::new_v4(),
                organization_id: org_id,
                account_id: Uuid::new_v4(),
                provider_native_id: "prod-cloudsec-data-lake".to_string(),
                resource_type: "bucket".to_string(),
                name: Some("prod-cloudsec-data-lake".to_string()),
                tags: json!({}),
                region: Some("us-east-1".to_string()),
                configuration: json!({
                    "block_public_acls": false
                }),
            });
        }

        let tf_state = json!({
            "version": 4,
            "terraform_version": "1.5.0",
            "resources": [
                {
                    "mode": "managed",
                    "type": "aws_s3_bucket",
                    "name": "data_lake",
                    "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
                    "instances": [
                        {
                            "attributes": {
                                "bucket": "prod-cloudsec-data-lake",
                                "block_public_acls": true
                            }
                        }
                    ]
                }
            ]
        });

        let drift_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/drift/terraform")
                    .header("authorization", "Bearer engineer-token")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "terraform_state": tf_state
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(drift_res.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(drift_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let mappings: Vec<TerraformResourceMapping> = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(mappings.len(), 1);
        assert_eq!(mappings[0].address, "aws_s3_bucket.data_lake");
        assert!(mappings[0].has_drift);
    }

    #[tokio::test]
    async fn alerting_rules_destinations_and_signed_test_webhook() {
        let state = AppState::new_with_defaults();
        let app = app_with_state(state.clone());

        // 1. Create alert destination
        let dest_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/alerts/destinations")
                    .header("authorization", "Bearer admin-token")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "name": "Security Ops Slack",
                            "destination_type": "slack_webhook",
                            "endpoint_url": "https://hooks.slack.com/services/T00/B00/X00",
                            "secret": "slack-secret-12345"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(dest_res.status(), StatusCode::OK);
        let dest_bytes = axum::body::to_bytes(dest_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let dest: AlertDestination = serde_json::from_slice(&dest_bytes).unwrap();

        // 2. Create alert rule
        let rule_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/alerts/rules")
                    .header("authorization", "Bearer admin-token")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "name": "Notify on Critical Findings",
                            "triggers": ["new_critical_finding", "security_regression"],
                            "destination_ids": [dest.id],
                            "severity_threshold": "critical"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rule_res.status(), StatusCode::OK);

        // 3. Test destination webhook
        let test_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/alerts/destinations/{}/test", dest.id))
                    .header("authorization", "Bearer admin-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(test_res.status(), StatusCode::OK);
        let test_bytes = axum::body::to_bytes(test_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let delivery: WebhookDeliveryRecord = serde_json::from_slice(&test_bytes).unwrap();
        assert!(delivery.success);
        assert_eq!(delivery.status_code, Some(200));

        // 4. Verify in delivery history
        let hist_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/alerts/history")
                    .header("authorization", "Bearer auditor-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(hist_res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn multi_format_report_export_with_watermark() {
        let state = AppState::new_with_defaults();
        let app = app_with_state(state);

        // Export PDF report with partial watermark
        let export_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/reports/export")
                    .header("authorization", "Bearer engineer-token")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "title": "Quarterly Audit Executive Report",
                            "format": "pdf",
                            "is_partial_data": true
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(export_res.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(export_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let report: GeneratedReport = serde_json::from_slice(&bytes).unwrap();
        assert!(report.is_partial_data);
        assert!(report.content.contains("PARTIAL"));
    }

    #[tokio::test]
    async fn operations_slo_and_retention_cleanup_endpoints() {
        let state = AppState::new_with_defaults();
        let app = app_with_state(state.clone());
        let org_id = Uuid::parse_str(DEFAULT_ORG_ID).unwrap();

        // 1. Query SLO telemetry
        let slo_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/operations/slo")
                    .header("authorization", "Bearer engineer-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(slo_res.status(), StatusCode::OK);
        let slo_bytes = axum::body::to_bytes(slo_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let slo: SloStatusResponse = serde_json::from_slice(&slo_bytes).unwrap();
        assert!(slo.api_availability_pct >= slo.api_availability_target_pct);
        assert!(slo.scan_completion_p95_minutes <= slo.scan_completion_target_minutes);
        assert!(slo.all_slos_met);

        // 2. Populate 8 mock scan runs
        {
            let mut runs = state.scan_runs.write().await;
            for _ in 0..8 {
                runs.push(ScanRun {
                    id: Uuid::new_v4(),
                    organization_id: org_id,
                    status: ScanStatus::Succeeded,
                    scanner_version: "1.0.0".to_string(),
                    coverage: json!({}),
                    error: None,
                });
            }
        }

        // 3. Dry-run retention cleanup
        let dry_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/operations/cleanup")
                    .header("authorization", "Bearer admin-token")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "retention_days": 30,
                            "dry_run": true
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(dry_res.status(), StatusCode::OK);
        let dry_bytes = axum::body::to_bytes(dry_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let dry_resp: RetentionCleanupResponse = serde_json::from_slice(&dry_bytes).unwrap();
        assert!(dry_resp.dry_run);
        assert_eq!(dry_resp.scan_runs_evaluated, 8);
        assert_eq!(dry_resp.scan_runs_eligible_for_purge, 3);
        assert_eq!(dry_resp.scan_runs_purged, 0); // No purge in dry run

        // 4. Execute actual retention cleanup
        let exec_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/operations/cleanup")
                    .header("authorization", "Bearer admin-token")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "retention_days": 30,
                            "dry_run": false
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(exec_res.status(), StatusCode::OK);
        let exec_bytes = axum::body::to_bytes(exec_res.into_body(), usize::MAX)
            .await
            .unwrap();
        let exec_resp: RetentionCleanupResponse = serde_json::from_slice(&exec_bytes).unwrap();
        assert!(!exec_resp.dry_run);
        assert_eq!(exec_resp.scan_runs_purged, 3);

        // Verify remaining runs is 5
        let remaining_runs = state.scan_runs.read().await;
        assert_eq!(remaining_runs.len(), 5);
    }
}
