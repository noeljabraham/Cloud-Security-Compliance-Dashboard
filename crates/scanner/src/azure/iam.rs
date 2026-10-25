use cloudsec_domain::{CloudProvider, CoverageGapReason, Resource, Severity};
use serde_json::{Value, json};

use crate::check::{Check, CheckEvaluation};

/// Check: Azure RBAC Disallow Direct User Role Assignments for Owner or Contributor
pub struct AzureRbacNoDirectUserOwnerAssignmentsCheck;

impl Check for AzureRbacNoDirectUserOwnerAssignmentsCheck {
    fn id(&self) -> &str {
        "azure-rbac-no-direct-user-owner-assignments"
    }

    fn provider(&self) -> CloudProvider {
        CloudProvider::Azure
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
        "Ensure No Direct User Role Assignments for Owner or Contributor at Subscription Scope"
    }

    fn description(&self) -> &str {
        "Verify that Owner and Contributor roles are assigned to managed groups or Privileged Identity Management (PIM) rather than directly to individual user accounts."
    }

    fn remediation(&self) -> &str {
        "Remove direct user assignments for Owner and Contributor. Assign roles to dedicated security groups and use PIM for just-in-time elevation."
    }

    fn base_severity(&self) -> Severity {
        Severity::High
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type != "azure_role_assignment"
            && resource.resource_type != "Microsoft.Authorization/roleAssignments"
        {
            return CheckEvaluation::NotApplicable;
        }

        let config = &resource.configuration;

        let principal_type = config
            .get("principal_type")
            .or_else(|| config.get("principalType"))
            .and_then(Value::as_str)
            .unwrap_or("");

        let role_name = config
            .get("role_definition_name")
            .or_else(|| config.get("roleName"))
            .and_then(Value::as_str)
            .unwrap_or("");

        let scope = config.get("scope").and_then(Value::as_str).unwrap_or("");

        let is_stale = config
            .get("is_stale")
            .or_else(|| config.get("is_inactive"))
            .and_then(Value::as_bool)
            .unwrap_or(false);

        let is_broad_role = role_name.eq_ignore_ascii_case("Owner")
            || role_name.eq_ignore_ascii_case("Contributor");

        let is_direct_user = principal_type.eq_ignore_ascii_case("User");
        let is_broad_scope = scope.is_empty()
            || scope.starts_with("/subscriptions/") && !scope.contains("/resourceGroups/");

        if is_stale {
            return CheckEvaluation::Failed {
                severity: Severity::Medium,
                evidence: json!({
                    "role_name": role_name,
                    "principal_type": principal_type,
                    "scope": scope,
                    "is_stale": is_stale,
                }),
                message: format!(
                    "Role assignment '{}' is stale or inactive and should be removed",
                    resource
                        .name
                        .as_deref()
                        .unwrap_or(&resource.provider_native_id)
                ),
            };
        }

        if is_direct_user && is_broad_role && is_broad_scope {
            CheckEvaluation::Failed {
                severity: self.base_severity(),
                evidence: json!({
                    "role_name": role_name,
                    "principal_type": principal_type,
                    "scope": scope,
                }),
                message: format!(
                    "Role assignment '{}' directly assigns privileged role '{}' to an individual user at subscription scope",
                    resource
                        .name
                        .as_deref()
                        .unwrap_or(&resource.provider_native_id),
                    role_name
                ),
            }
        } else {
            CheckEvaluation::Passed
        }
    }
}

/// Check: Azure RBAC Custom Roles Do Not Grant Wildcard or High-Risk Permissions
pub struct AzureRbacNoWildcardCustomRolesCheck;

impl Check for AzureRbacNoWildcardCustomRolesCheck {
    fn id(&self) -> &str {
        "azure-rbac-no-wildcard-custom-roles"
    }

    fn provider(&self) -> CloudProvider {
        CloudProvider::Azure
    }

    fn service(&self) -> &str {
        "iam"
    }

    fn category(&self) -> &str {
        "least_privilege"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn title(&self) -> &str {
        "Ensure Custom RBAC Roles Do Not Grant Wildcard or High-Risk Permissions"
    }

    fn description(&self) -> &str {
        "Verify that custom Azure role definitions do not grant wildcard '*' actions or broad write permissions across critical resource providers."
    }

    fn remediation(&self) -> &str {
        "Refactor custom role definitions to specify explicit, least-privilege actions rather than wildcards ('*')."
    }

    fn base_severity(&self) -> Severity {
        Severity::Critical
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type != "azure_role_definition"
            && resource.resource_type != "Microsoft.Authorization/roleDefinitions"
        {
            return CheckEvaluation::NotApplicable;
        }

        let config = &resource.configuration;

        let role_type = config
            .get("role_type")
            .or_else(|| config.get("type"))
            .and_then(Value::as_str)
            .unwrap_or("");

        let is_custom = config
            .get("is_custom")
            .or_else(|| config.get("isCustom"))
            .and_then(Value::as_bool)
            .unwrap_or_else(|| role_type.eq_ignore_ascii_case("CustomRole"));

        // Only evaluate custom roles
        if !is_custom {
            return CheckEvaluation::Passed;
        }

        let actions = config
            .get("actions")
            .or_else(|| {
                config
                    .get("permissions")
                    .and_then(|p| p.get(0))
                    .and_then(|p0| p0.get("actions"))
            })
            .and_then(Value::as_array);

        let mut high_risk_actions = Vec::new();

        if let Some(act_list) = actions {
            for act in act_list.iter().filter_map(Value::as_str) {
                let trimmed = act.trim();
                if trimmed == "*"
                    || trimmed.eq_ignore_ascii_case("Microsoft.Authorization/*")
                    || trimmed.eq_ignore_ascii_case("Microsoft.Authorization/*/write")
                    || trimmed.eq_ignore_ascii_case("Microsoft.Compute/*")
                    || trimmed.eq_ignore_ascii_case("Microsoft.Storage/*")
                    || trimmed.eq_ignore_ascii_case("Microsoft.KeyVault/*")
                {
                    high_risk_actions.push(trimmed.to_string());
                }
            }
        }

        if high_risk_actions.is_empty() {
            CheckEvaluation::Passed
        } else {
            CheckEvaluation::Failed {
                severity: self.base_severity(),
                evidence: json!({
                    "is_custom_role": is_custom,
                    "high_risk_actions": high_risk_actions,
                }),
                message: format!(
                    "Custom role '{}' grants excessive or wildcard permissions: {:?}",
                    resource
                        .name
                        .as_deref()
                        .unwrap_or(&resource.provider_native_id),
                    high_risk_actions
                ),
            }
        }
    }
}

/// Check: Microsoft Entra ID Privileged Role Governance and MFA/Guest Access
pub struct AzureEntraPrivilegedRoleGovernanceCheck;

impl Check for AzureEntraPrivilegedRoleGovernanceCheck {
    fn id(&self) -> &str {
        "azure-entra-privileged-role-governance"
    }

    fn provider(&self) -> CloudProvider {
        CloudProvider::Azure
    }

    fn service(&self) -> &str {
        "iam"
    }

    fn category(&self) -> &str {
        "identity_governance"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn title(&self) -> &str {
        "Ensure Privileged Identity Governance, Multi-Factor Authentication, and Guest Access Restrictions"
    }

    fn description(&self) -> &str {
        "Verify that privileged administrative roles require MFA, conditional access policies are enforced, and guest users do not hold permanent administrative roles."
    }

    fn remediation(&self) -> &str {
        "Enforce Conditional Access requiring MFA for administrative roles, remove guest users from privileged roles, and use Privileged Identity Management (PIM)."
    }

    fn base_severity(&self) -> Severity {
        Severity::High
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type != "azure_entra_governance"
            && resource.resource_type != "azure_entra_user"
            && resource.resource_type != "azure_entra_tenant"
        {
            return CheckEvaluation::NotApplicable;
        }

        let config = &resource.configuration;

        // Check for guest user with privileged roles
        let user_type = config
            .get("user_type")
            .or_else(|| config.get("userType"))
            .and_then(Value::as_str)
            .unwrap_or("Member");

        let has_privileged_roles = config
            .get("has_privileged_roles")
            .or_else(|| config.get("is_admin"))
            .and_then(Value::as_bool)
            .unwrap_or(false);

        if user_type.eq_ignore_ascii_case("Guest") && has_privileged_roles {
            return CheckEvaluation::Failed {
                severity: Severity::Critical,
                evidence: json!({
                    "user_type": user_type,
                    "has_privileged_roles": has_privileged_roles,
                }),
                message: format!(
                    "Guest user '{}' holds privileged administrative roles in Microsoft Entra ID",
                    resource
                        .name
                        .as_deref()
                        .unwrap_or(&resource.provider_native_id)
                ),
            };
        }

        // Check MFA / Conditional Access for tenant governance
        let mfa_enforced = config
            .get("mfa_enforced_for_admins")
            .or_else(|| config.get("mfa_enforced"))
            .and_then(Value::as_bool)
            .unwrap_or(true);

        let conditional_access_active = config
            .get("conditional_access_policies_active")
            .and_then(Value::as_bool)
            .unwrap_or(true);

        let pim_enabled = config
            .get("pim_enabled_for_privileged_roles")
            .or_else(|| config.get("pim_enabled"))
            .and_then(Value::as_bool)
            .unwrap_or(true);

        if mfa_enforced && conditional_access_active && pim_enabled {
            CheckEvaluation::Passed
        } else {
            CheckEvaluation::Failed {
                severity: self.base_severity(),
                evidence: json!({
                    "mfa_enforced_for_admins": mfa_enforced,
                    "conditional_access_policies_active": conditional_access_active,
                    "pim_enabled": pim_enabled,
                }),
                message: format!(
                    "Entra ID identity governance '{}' lacks MFA enforcement, active Conditional Access, or PIM for privileged roles",
                    resource
                        .name
                        .as_deref()
                        .unwrap_or(&resource.provider_native_id)
                ),
            }
        }
    }
}

/// Check: Microsoft Entra ID and Governance Coverage Status
pub struct AzureEntraIdentityCoverageCheck;

impl Check for AzureEntraIdentityCoverageCheck {
    fn id(&self) -> &str {
        "azure-entra-identity-coverage"
    }

    fn provider(&self) -> CloudProvider {
        CloudProvider::Azure
    }

    fn service(&self) -> &str {
        "iam"
    }

    fn category(&self) -> &str {
        "identity_governance"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn title(&self) -> &str {
        "Report Microsoft Entra ID and Governance Coverage Status"
    }

    fn description(&self) -> &str {
        "Report unavailable identity governance checks as coverage gaps when Microsoft Graph permissions or Entra ID P1/P2 licensing are missing."
    }

    fn remediation(&self) -> &str {
        "Grant 'Directory.Read.All' or 'Policy.Read.All' permissions in Microsoft Graph and ensure Entra ID P1/P2 licensing is active for the tenant."
    }

    fn base_severity(&self) -> Severity {
        Severity::Medium
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type != "azure_entra_governance"
            && resource.resource_type != "azure_entra_user"
            && resource.resource_type != "azure_entra_tenant"
        {
            return CheckEvaluation::NotApplicable;
        }

        let config = &resource.configuration;

        // Check if API access or licensing is unavailable
        let api_status = config
            .get("api_status")
            .and_then(Value::as_str)
            .unwrap_or("ok");

        let licensing_status = config
            .get("licensing_status")
            .and_then(Value::as_str)
            .unwrap_or("ok");

        let mfa_evidence_available = config
            .get("mfa_evidence_available")
            .and_then(Value::as_bool)
            .unwrap_or(true);

        if api_status.eq_ignore_ascii_case("permission_denied") {
            return CheckEvaluation::CoverageGap {
                reason: CoverageGapReason::PermissionDenied,
                details: "Microsoft Graph Directory.Read.All or Policy.Read.All permission denied while evaluating Entra ID governance".to_string(),
            };
        }

        if licensing_status.eq_ignore_ascii_case("insufficient_licensing")
            || licensing_status.eq_ignore_ascii_case("missing_p1_p2")
            || !mfa_evidence_available
        {
            return CheckEvaluation::CoverageGap {
                reason: CoverageGapReason::UnsupportedService,
                details: "Entra ID P1/P2 license or Identity Protection API is not available on this tenant; reporting coverage gap rather than false pass".to_string(),
            };
        }

        CheckEvaluation::Passed
    }
}
