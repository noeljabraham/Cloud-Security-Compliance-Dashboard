use cloudsec_domain::{CloudProvider, Resource, Severity};
use serde_json::{Value, json};

use crate::check::{Check, CheckEvaluation};

/// Check: GCP IAM Does Not Use Primitive Roles or Wildcard Custom Roles
pub struct GcpIamNoPrimitiveRolesAndWildcardCustomRolesCheck;

impl Check for GcpIamNoPrimitiveRolesAndWildcardCustomRolesCheck {
    fn id(&self) -> &str {
        "gcp-iam-no-primitive-roles-and-wildcard-custom-roles"
    }

    fn provider(&self) -> CloudProvider {
        CloudProvider::Gcp
    }

    fn service(&self) -> &str {
        "iam"
    }

    fn category(&self) -> &str {
        "identity_and_access_management"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn title(&self) -> &str {
        "Ensure Primitive Roles (Owner/Editor/Viewer) and Wildcard Custom Roles are Not Used"
    }

    fn description(&self) -> &str {
        "Verify that IAM policies do not assign legacy primitive roles (roles/owner, roles/editor, roles/viewer) and custom roles do not contain wildcard '*' permissions."
    }

    fn remediation(&self) -> &str {
        "Replace primitive roles with predefined least-privilege roles, and remove wildcard '*' permissions from custom IAM roles."
    }

    fn base_severity(&self) -> Severity {
        Severity::High
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type == "gcp_iam_policy"
            || resource.resource_type == "cloudresourcemanager.googleapis.com/Project"
        {
            let config = &resource.configuration;
            let bindings = config.get("bindings").and_then(Value::as_array);

            let mut primitive_roles = Vec::new();

            if let Some(bind_arr) = bindings {
                for b in bind_arr {
                    let role = b.get("role").and_then(Value::as_str).unwrap_or("");
                    if role == "roles/owner" || role == "roles/editor" || role == "roles/viewer" {
                        let members = b
                            .get("members")
                            .and_then(Value::as_array)
                            .map(|m| m.len())
                            .unwrap_or(0);
                        primitive_roles.push(format!("{role} ({members} members)"));
                    }
                }
            }

            if primitive_roles.is_empty() {
                CheckEvaluation::Passed
            } else {
                CheckEvaluation::Failed {
                    severity: self.base_severity(),
                    evidence: json!({
                        "primitive_roles": primitive_roles,
                    }),
                    message: format!(
                        "IAM policy for '{}' assigns legacy primitive roles instead of least-privilege predefined roles",
                        resource
                            .name
                            .as_deref()
                            .unwrap_or(&resource.provider_native_id)
                    ),
                }
            }
        } else if resource.resource_type == "gcp_iam_custom_role"
            || resource.resource_type == "iam.googleapis.com/Role"
        {
            let config = &resource.configuration;
            let permissions = config
                .get("included_permissions")
                .or_else(|| config.get("includedPermissions"))
                .and_then(Value::as_array);

            let mut wildcard_perms = Vec::new();
            if let Some(perms) = permissions {
                for p in perms.iter().filter_map(Value::as_str) {
                    if p == "*" || p.ends_with(".*") {
                        wildcard_perms.push(p.to_string());
                    }
                }
            }

            if wildcard_perms.is_empty() {
                CheckEvaluation::Passed
            } else {
                CheckEvaluation::Failed {
                    severity: Severity::Critical,
                    evidence: json!({
                        "wildcard_permissions": wildcard_perms,
                    }),
                    message: format!(
                        "Custom IAM role '{}' contains dangerous wildcard permissions",
                        resource
                            .name
                            .as_deref()
                            .unwrap_or(&resource.provider_native_id)
                    ),
                }
            }
        } else {
            CheckEvaluation::NotApplicable
        }
    }
}

/// Check: GCP IAM Disallows Public Principals, Stale Service Account Keys, and Impersonation
pub struct GcpIamNoPublicPrincipalsAndStaleKeysCheck;

impl Check for GcpIamNoPublicPrincipalsAndStaleKeysCheck {
    fn id(&self) -> &str {
        "gcp-iam-no-public-principals-and-stale-keys"
    }

    fn provider(&self) -> CloudProvider {
        CloudProvider::Gcp
    }

    fn service(&self) -> &str {
        "iam"
    }

    fn category(&self) -> &str {
        "identity_and_access_management"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn title(&self) -> &str {
        "Ensure No Public Principals, Stale Service Account Keys (>90 Days), or Unrestricted Impersonation"
    }

    fn description(&self) -> &str {
        "Verify that IAM policies do not include public principals (allUsers), service account keys are rotated within 90 days, and service account impersonation is restricted."
    }

    fn remediation(&self) -> &str {
        "Delete public IAM bindings, rotate or delete user-managed service account keys older than 90 days, and add IAM conditions to serviceAccountUser roles."
    }

    fn base_severity(&self) -> Severity {
        Severity::High
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type == "gcp_iam_policy"
            || resource.resource_type == "cloudresourcemanager.googleapis.com/Project"
        {
            let config = &resource.configuration;
            let bindings = config.get("bindings").and_then(Value::as_array);

            let mut violations = Vec::new();

            if let Some(bind_arr) = bindings {
                for b in bind_arr {
                    let role = b.get("role").and_then(Value::as_str).unwrap_or("");
                    let members = b.get("members").and_then(Value::as_array);
                    let condition = b.get("condition");

                    if let Some(mem_arr) = members {
                        for m in mem_arr.iter().filter_map(Value::as_str) {
                            if m == "allUsers" || m == "allAuthenticatedUsers" {
                                violations
                                    .push(format!("Public principal '{m}' granted role '{role}'"));
                            }
                            if (role == "roles/iam.serviceAccountUser"
                                || role == "roles/iam.serviceAccountTokenCreator")
                                && condition.is_none()
                            {
                                violations.push(format!(
                                    "Unrestricted service account impersonation granted to '{m}'"
                                ));
                            }
                        }
                    }
                }
            }

            if violations.is_empty() {
                CheckEvaluation::Passed
            } else {
                CheckEvaluation::Failed {
                    severity: self.base_severity(),
                    evidence: json!({
                        "violations": violations,
                    }),
                    message: format!(
                        "IAM policy for '{}' has public principals or unrestricted service account impersonation",
                        resource
                            .name
                            .as_deref()
                            .unwrap_or(&resource.provider_native_id)
                    ),
                }
            }
        } else if resource.resource_type == "gcp_service_account"
            || resource.resource_type == "iam.googleapis.com/ServiceAccount"
        {
            let config = &resource.configuration;
            let keys = config.get("keys").and_then(Value::as_array);

            let mut stale_keys = Vec::new();

            if let Some(key_arr) = keys {
                for k in key_arr {
                    let key_type = k
                        .get("key_type")
                        .or_else(|| k.get("keyType"))
                        .and_then(Value::as_str)
                        .unwrap_or("USER_MANAGED");

                    if key_type == "USER_MANAGED" {
                        let age_days = k.get("age_days").and_then(Value::as_u64).unwrap_or(0);
                        let is_stale = k.get("is_stale").and_then(Value::as_bool).unwrap_or(false);

                        if age_days > 90 || is_stale {
                            let key_id = k.get("name").and_then(Value::as_str).unwrap_or("key");
                            stale_keys.push(format!("{key_id} ({age_days} days old)"));
                        }
                    }
                }
            }

            if stale_keys.is_empty() {
                CheckEvaluation::Passed
            } else {
                CheckEvaluation::Failed {
                    severity: Severity::Medium,
                    evidence: json!({
                        "stale_user_managed_keys": stale_keys,
                    }),
                    message: format!(
                        "Service account '{}' has user-managed keys older than 90 days that require rotation",
                        resource
                            .name
                            .as_deref()
                            .unwrap_or(&resource.provider_native_id)
                    ),
                }
            }
        } else {
            CheckEvaluation::NotApplicable
        }
    }
}

/// Check: GCP Cloud Audit Logging Configured for Data Access and Log Sinks Enabled
pub struct GcpLoggingDataAccessAuditAndSinksCheck;

impl Check for GcpLoggingDataAccessAuditAndSinksCheck {
    fn id(&self) -> &str {
        "gcp-logging-data-access-audit-and-sinks"
    }

    fn provider(&self) -> CloudProvider {
        CloudProvider::Gcp
    }

    fn service(&self) -> &str {
        "logging"
    }

    fn category(&self) -> &str {
        "audit_logging"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn title(&self) -> &str {
        "Ensure Data Access Audit Logs are Enabled and Centralized Log Sinks Configured"
    }

    fn description(&self) -> &str {
        "Verify that Cloud Audit Logging is enabled for DATA_READ and DATA_WRITE across critical services and centralized log sinks export logs for security analysis."
    }

    fn remediation(&self) -> &str {
        "Enable DATA_READ and DATA_WRITE in the project's auditConfigs for 'allServices' and configure a central logging sink to BigQuery, Cloud Storage, or Pub/Sub."
    }

    fn base_severity(&self) -> Severity {
        Severity::High
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type != "gcp_audit_config"
            && resource.resource_type != "logging.googleapis.com/AuditConfig"
            && resource.resource_type != "gcp_logging_project_settings"
        {
            return CheckEvaluation::NotApplicable;
        }

        let config = &resource.configuration;

        let audit_configs = config
            .get("audit_configs")
            .or_else(|| config.get("auditConfigs"))
            .and_then(Value::as_array);

        let mut data_read_enabled = false;
        let mut data_write_enabled = false;

        if let Some(configs) = audit_configs {
            for c in configs {
                let service = c.get("service").and_then(Value::as_str).unwrap_or("");
                if service == "allServices" || service == "all" {
                    let log_types = c
                        .get("audit_log_configs")
                        .or_else(|| c.get("auditLogConfigs"))
                        .and_then(Value::as_array);

                    if let Some(types) = log_types {
                        for lt in types {
                            let t = lt
                                .get("log_type")
                                .or_else(|| lt.get("logType"))
                                .and_then(Value::as_str)
                                .unwrap_or("");
                            if t.eq_ignore_ascii_case("DATA_READ") {
                                data_read_enabled = true;
                            }
                            if t.eq_ignore_ascii_case("DATA_WRITE") {
                                data_write_enabled = true;
                            }
                        }
                    }
                }
            }
        }

        // Also accept boolean flags if pre-processed
        if config
            .get("data_access_logs_enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            data_read_enabled = true;
            data_write_enabled = true;
        }

        let sinks_count = config
            .get("log_sinks")
            .or_else(|| config.get("sinks"))
            .and_then(Value::as_array)
            .map(|s| s.len())
            .unwrap_or(0);

        let has_central_sink = sinks_count > 0
            || config
                .get("has_log_sink")
                .and_then(Value::as_bool)
                .unwrap_or(false);

        if data_read_enabled && data_write_enabled && has_central_sink {
            CheckEvaluation::Passed
        } else {
            CheckEvaluation::Failed {
                severity: self.base_severity(),
                evidence: json!({
                    "data_read_audit_enabled": data_read_enabled,
                    "data_write_audit_enabled": data_write_enabled,
                    "central_log_sinks_count": sinks_count,
                    "has_central_sink": has_central_sink,
                }),
                message: format!(
                    "Audit configuration for '{}' lacks DATA_READ/DATA_WRITE audit logs or central log sink",
                    resource
                        .name
                        .as_deref()
                        .unwrap_or(&resource.provider_native_id)
                ),
            }
        }
    }
}
