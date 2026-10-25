use cloudsec_domain::{CloudProvider, Resource, Severity};
use serde_json::{Value, json};

use crate::check::{Check, CheckEvaluation};

/// Check: Root MFA is enabled and no active root access keys exist
pub struct AwsIamRootMfaAndKeysCheck;

impl Check for AwsIamRootMfaAndKeysCheck {
    fn id(&self) -> &str {
        "aws-iam-root-mfa-and-keys"
    }
    fn provider(&self) -> CloudProvider {
        CloudProvider::Aws
    }
    fn service(&self) -> &str {
        "iam"
    }
    fn category(&self) -> &str {
        "identity"
    }
    fn version(&self) -> &str {
        "1.0.0"
    }
    fn title(&self) -> &str {
        "Ensure Root User has MFA enabled and no active access keys"
    }
    fn description(&self) -> &str {
        "The root user account has full administrative control; it should be protected by hardware/virtual MFA and have zero active access keys."
    }
    fn remediation(&self) -> &str {
        "Enable hardware/virtual MFA on the root account and delete any existing root access keys via AWS Console."
    }
    fn base_severity(&self) -> Severity {
        Severity::Critical
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type != "aws_iam_account_summary" {
            return CheckEvaluation::NotApplicable;
        }

        let config = &resource.configuration;
        let root_mfa_enabled = config
            .get("account_mfa_enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let root_access_keys = config
            .get("account_access_keys_present")
            .and_then(Value::as_u64)
            .unwrap_or(0);

        if root_mfa_enabled && root_access_keys == 0 {
            CheckEvaluation::Passed
        } else {
            CheckEvaluation::Failed {
                severity: self.base_severity(),
                evidence: json!({
                    "account_mfa_enabled": root_mfa_enabled,
                    "account_access_keys_present": root_access_keys,
                }),
                message: format!(
                    "Root user security violation: MFA enabled: {root_mfa_enabled}, Active access keys: {root_access_keys}"
                ),
            }
        }
    }
}

/// Check: IAM Console Users have MFA enabled
pub struct AwsIamUserMfaEnabledCheck;

impl Check for AwsIamUserMfaEnabledCheck {
    fn id(&self) -> &str {
        "aws-iam-user-mfa-enabled"
    }
    fn provider(&self) -> CloudProvider {
        CloudProvider::Aws
    }
    fn service(&self) -> &str {
        "iam"
    }
    fn category(&self) -> &str {
        "identity"
    }
    fn version(&self) -> &str {
        "1.0.0"
    }
    fn title(&self) -> &str {
        "Ensure MFA is enabled for all IAM users with console passwords"
    }
    fn description(&self) -> &str {
        "Multi-Factor Authentication (MFA) adds an extra layer of protection on top of a user name and password."
    }
    fn remediation(&self) -> &str {
        "aws iam create-virtual-mfa-device --virtual-mfa-device-name <name> and enable-mfa-device --user-name <user>"
    }
    fn base_severity(&self) -> Severity {
        Severity::High
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type != "aws_iam_user" {
            return CheckEvaluation::NotApplicable;
        }

        let config = &resource.configuration;
        let password_enabled = config
            .get("password_enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let mfa_active = config
            .get("mfa_active")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        // If user has no console password, MFA requirement does not apply
        if !password_enabled || mfa_active {
            CheckEvaluation::Passed
        } else {
            CheckEvaluation::Failed {
                severity: self.base_severity(),
                evidence: json!({
                    "password_enabled": password_enabled,
                    "mfa_active": mfa_active,
                }),
                message: format!(
                    "IAM User '{}' has console password enabled without an active MFA device",
                    resource
                        .name
                        .as_deref()
                        .unwrap_or(&resource.provider_native_id)
                ),
            }
        }
    }
}

/// Check: IAM Password Policy meets complexity and length requirements
pub struct AwsIamPasswordPolicyCheck;

impl Check for AwsIamPasswordPolicyCheck {
    fn id(&self) -> &str {
        "aws-iam-password-policy"
    }
    fn provider(&self) -> CloudProvider {
        CloudProvider::Aws
    }
    fn service(&self) -> &str {
        "iam"
    }
    fn category(&self) -> &str {
        "identity"
    }
    fn version(&self) -> &str {
        "1.0.0"
    }
    fn title(&self) -> &str {
        "Ensure IAM password policy meets length and complexity standards"
    }
    fn description(&self) -> &str {
        "Password policies should require a minimum length of 14 characters, uppercase, lowercase, numbers, and symbols."
    }
    fn remediation(&self) -> &str {
        "aws iam update-account-password-policy --minimum-password-length 14 --require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters"
    }
    fn base_severity(&self) -> Severity {
        Severity::Medium
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type != "aws_iam_password_policy" {
            return CheckEvaluation::NotApplicable;
        }

        let config = &resource.configuration;
        let min_length = config
            .get("minimum_password_length")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let require_symbols = config
            .get("require_symbols")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let require_numbers = config
            .get("require_numbers")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let require_uppercase = config
            .get("require_uppercase_characters")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let require_lowercase = config
            .get("require_lowercase_characters")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        if min_length >= 14
            && require_symbols
            && require_numbers
            && require_uppercase
            && require_lowercase
        {
            CheckEvaluation::Passed
        } else {
            CheckEvaluation::Failed {
                severity: self.base_severity(),
                evidence: json!({
                    "minimum_password_length": min_length,
                    "require_symbols": require_symbols,
                    "require_numbers": require_numbers,
                    "require_uppercase_characters": require_uppercase,
                    "require_lowercase_characters": require_lowercase,
                }),
                message:
                    "Account IAM password policy does not meet CIS minimum complexity standards"
                        .to_string(),
            }
        }
    }
}

/// Check: Access keys rotated within 90 days
pub struct AwsIamOldAccessKeysCheck;

impl Check for AwsIamOldAccessKeysCheck {
    fn id(&self) -> &str {
        "aws-iam-old-access-keys"
    }
    fn provider(&self) -> CloudProvider {
        CloudProvider::Aws
    }
    fn service(&self) -> &str {
        "iam"
    }
    fn category(&self) -> &str {
        "identity"
    }
    fn version(&self) -> &str {
        "1.0.0"
    }
    fn title(&self) -> &str {
        "Ensure IAM access keys older than 90 days are rotated"
    }
    fn description(&self) -> &str {
        "Access keys should be rotated every 90 days to reduce the window of opportunity for compromised keys."
    }
    fn remediation(&self) -> &str {
        "aws iam update-access-key --access-key-id <key-id> --status Inactive and create a new key."
    }
    fn base_severity(&self) -> Severity {
        Severity::Medium
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type != "aws_iam_access_key" {
            return CheckEvaluation::NotApplicable;
        }

        let config = &resource.configuration;
        let status = config
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("Active");
        let age_days = config.get("age_days").and_then(Value::as_u64).unwrap_or(0);

        if status != "Active" || age_days <= 90 {
            CheckEvaluation::Passed
        } else {
            CheckEvaluation::Failed {
                severity: self.base_severity(),
                evidence: json!({
                    "status": status,
                    "age_days": age_days,
                }),
                message: format!(
                    "Access key '{}' is active and {} days old (> 90 days)",
                    resource.provider_native_id, age_days
                ),
            }
        }
    }
}

/// Check: Dormant/Inactive IAM Users (> 90 days)
pub struct AwsIamInactiveUsersCheck;

impl Check for AwsIamInactiveUsersCheck {
    fn id(&self) -> &str {
        "aws-iam-inactive-users"
    }
    fn provider(&self) -> CloudProvider {
        CloudProvider::Aws
    }
    fn service(&self) -> &str {
        "iam"
    }
    fn category(&self) -> &str {
        "identity"
    }
    fn version(&self) -> &str {
        "1.0.0"
    }
    fn title(&self) -> &str {
        "Ensure inactive IAM users (> 90 days) are disabled or removed"
    }
    fn description(&self) -> &str {
        "Accounts that have not been logged in or used for more than 90 days represent unnecessary attack surface."
    }
    fn remediation(&self) -> &str {
        "aws iam delete-login-profile --user-name <user> or deactivate keys."
    }
    fn base_severity(&self) -> Severity {
        Severity::Low
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type != "aws_iam_user" {
            return CheckEvaluation::NotApplicable;
        }

        let config = &resource.configuration;
        let days_since_last_activity = config
            .get("days_since_last_activity")
            .and_then(Value::as_u64)
            .unwrap_or(0);

        if days_since_last_activity <= 90 {
            CheckEvaluation::Passed
        } else {
            CheckEvaluation::Failed {
                severity: self.base_severity(),
                evidence: json!({
                    "days_since_last_activity": days_since_last_activity,
                }),
                message: format!(
                    "IAM user '{}' has had no activity for {} days",
                    resource
                        .name
                        .as_deref()
                        .unwrap_or(&resource.provider_native_id),
                    days_since_last_activity
                ),
            }
        }
    }
}

/// Check: IAM Policies do not grant full wildcard administrative access
pub struct AwsIamNoWildcardAdminPoliciesCheck;

impl Check for AwsIamNoWildcardAdminPoliciesCheck {
    fn id(&self) -> &str {
        "aws-iam-no-wildcard-admin-policies"
    }
    fn provider(&self) -> CloudProvider {
        CloudProvider::Aws
    }
    fn service(&self) -> &str {
        "iam"
    }
    fn category(&self) -> &str {
        "identity"
    }
    fn version(&self) -> &str {
        "1.0.0"
    }
    fn title(&self) -> &str {
        "Ensure IAM policies do not grant wildcard administrative access"
    }
    fn description(&self) -> &str {
        "Customer-managed and inline IAM policies should not grant Action: '*' on Resource: '*'."
    }
    fn remediation(&self) -> &str {
        "Scope down IAM policy statements to specific actions and resources required for job responsibilities."
    }
    fn base_severity(&self) -> Severity {
        Severity::High
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type != "aws_iam_policy" {
            return CheckEvaluation::NotApplicable;
        }

        let config = &resource.configuration;
        let grants_wildcard_admin = config
            .get("grants_wildcard_admin")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        if !grants_wildcard_admin {
            CheckEvaluation::Passed
        } else {
            CheckEvaluation::Failed {
                severity: self.base_severity(),
                evidence: json!({
                    "grants_wildcard_admin": true,
                }),
                message: format!(
                    "IAM Policy '{}' grants unrestricted wildcard admin access (Action: *, Resource: *)",
                    resource
                        .name
                        .as_deref()
                        .unwrap_or(&resource.provider_native_id)
                ),
            }
        }
    }
}

/// Check: IAM Role Trust Policy restricts cross-account access and specifies conditions
pub struct AwsIamRoleTrustPolicyCheck;

impl Check for AwsIamRoleTrustPolicyCheck {
    fn id(&self) -> &str {
        "aws-iam-role-trust-policy"
    }
    fn provider(&self) -> CloudProvider {
        CloudProvider::Aws
    }
    fn service(&self) -> &str {
        "iam"
    }
    fn category(&self) -> &str {
        "identity"
    }
    fn version(&self) -> &str {
        "1.0.0"
    }
    fn title(&self) -> &str {
        "Ensure IAM Role Trust Policies do not allow public or unconditioned cross-account access"
    }
    fn description(&self) -> &str {
        "Role trust policies should never allow Principal: '*' and should enforce ExternalId or other condition checks for cross-account trust."
    }
    fn remediation(&self) -> &str {
        "Update the role assume role policy document to specify trusted principals and conditions."
    }
    fn base_severity(&self) -> Severity {
        Severity::High
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type != "aws_iam_role" {
            return CheckEvaluation::NotApplicable;
        }

        let config = &resource.configuration;
        let allows_wildcard_principal = config
            .get("allows_wildcard_principal")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let missing_cross_account_condition = config
            .get("missing_cross_account_condition")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        if !allows_wildcard_principal && !missing_cross_account_condition {
            CheckEvaluation::Passed
        } else {
            CheckEvaluation::Failed {
                severity: self.base_severity(),
                evidence: json!({
                    "allows_wildcard_principal": allows_wildcard_principal,
                    "missing_cross_account_condition": missing_cross_account_condition,
                }),
                message: format!(
                    "IAM Role '{}' has risky trust policy allowing wildcard principal or missing cross-account conditions",
                    resource
                        .name
                        .as_deref()
                        .unwrap_or(&resource.provider_native_id)
                ),
            }
        }
    }
}
