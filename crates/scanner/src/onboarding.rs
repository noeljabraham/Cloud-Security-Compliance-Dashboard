use cloudsec_domain::{
    AwsOnboardingConfig, AzureOnboardingConfig, CloudProvider, GcpOnboardingConfig,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::error::ScannerError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnboardingValidationResult {
    pub is_valid: bool,
    pub provider: CloudProvider,
    pub native_id: String,
    pub identity: String,
    pub enabled_regions: Vec<String>,
    pub missing_permissions: Vec<String>,
    pub details: Value,
}

pub struct CloudOnboardingValidator;

impl CloudOnboardingValidator {
    pub fn validate_aws_input(
        config: &AwsOnboardingConfig,
        raw_payload: &Value,
    ) -> Result<(), ScannerError> {
        // Enforce: NEVER accept long-lived static AWS access keys
        if raw_payload.get("access_key_id").is_some()
            || raw_payload.get("secret_access_key").is_some()
            || raw_payload.get("aws_access_key_id").is_some()
            || raw_payload.get("aws_secret_access_key").is_some()
        {
            return Err(ScannerError::AuthenticationFailed(
                "Long-lived AWS access keys are not accepted for production onboarding. Use cross-account IAM roles with external IDs.".to_string(),
            ));
        }

        // Validate Role ARN structure: arn:aws:iam::<12 digits>:role/<name>
        if !config.role_arn.starts_with("arn:aws:iam::") || !config.role_arn.contains(":role/") {
            return Err(ScannerError::AuthenticationFailed(
                "Invalid AWS role_arn format. Expected: arn:aws:iam::<12-digit-account-id>:role/<role-name>".to_string(),
            ));
        }

        // Validate 12-digit account ID
        if config.account_id.len() != 12 || !config.account_id.chars().all(|c| c.is_ascii_digit()) {
            return Err(ScannerError::AuthenticationFailed(
                "AWS account_id must be exactly 12 numeric digits.".to_string(),
            ));
        }

        // Validate external ID (must be at least 8 characters)
        if config.external_id.trim().len() < 8 {
            return Err(ScannerError::AuthenticationFailed(
                "AWS external_id must be at least 8 characters to prevent confused deputy attacks."
                    .to_string(),
            ));
        }

        // Ensure role ARN matches the target account ID
        if !config
            .role_arn
            .contains(&format!("arn:aws:iam::{}:", config.account_id))
        {
            return Err(ScannerError::AuthenticationFailed(
                "AWS role_arn account ID does not match target account_id.".to_string(),
            ));
        }

        Ok(())
    }

    pub fn validate_azure_input(
        config: &AzureOnboardingConfig,
        raw_payload: &Value,
    ) -> Result<(), ScannerError> {
        if raw_payload.get("client_secret").is_some() || raw_payload.get("password").is_some() {
            return Err(ScannerError::AuthenticationFailed(
                "Static client secrets are prohibited. Use Azure Workload Identity Federation / Federated Credentials.".to_string(),
            ));
        }

        if Uuid::parse_str(&config.tenant_id).is_err() {
            return Err(ScannerError::AuthenticationFailed(
                "Invalid Azure tenant_id format. Expected UUID.".to_string(),
            ));
        }
        if Uuid::parse_str(&config.client_id).is_err() {
            return Err(ScannerError::AuthenticationFailed(
                "Invalid Azure client_id format. Expected UUID.".to_string(),
            ));
        }
        if Uuid::parse_str(&config.subscription_id).is_err() {
            return Err(ScannerError::AuthenticationFailed(
                "Invalid Azure subscription_id format. Expected UUID.".to_string(),
            ));
        }

        if config.federated_credential.trim().is_empty() {
            return Err(ScannerError::AuthenticationFailed(
                "Azure federated_credential / workload identity subject is required.".to_string(),
            ));
        }

        Ok(())
    }

    pub fn validate_gcp_input(
        config: &GcpOnboardingConfig,
        raw_payload: &Value,
    ) -> Result<(), ScannerError> {
        // Enforce: NEVER accept downloaded service account JSON private keys
        if raw_payload.get("private_key").is_some()
            || raw_payload.get("private_key_id").is_some()
            || (raw_payload.get("type").and_then(Value::as_str) == Some("service_account")
                && raw_payload.get("private_key").is_some())
        {
            return Err(ScannerError::AuthenticationFailed(
                "Stored GCP service account JSON private keys are prohibited. Use Workload Identity Federation or Service Account Impersonation.".to_string(),
            ));
        }

        if config.project_id.trim().is_empty() {
            return Err(ScannerError::AuthenticationFailed(
                "GCP project_id cannot be empty.".to_string(),
            ));
        }

        if !config.service_account_email.contains('@')
            || !config
                .service_account_email
                .ends_with(".iam.gserviceaccount.com")
        {
            return Err(ScannerError::AuthenticationFailed(
                "Invalid GCP service_account_email format. Expected a service account ending in .iam.gserviceaccount.com.".to_string(),
            ));
        }

        if !config
            .workload_identity_pool
            .contains("/workloadIdentityPools/")
        {
            return Err(ScannerError::AuthenticationFailed(
                "Invalid GCP workload_identity_pool format. Expected: projects/<number>/locations/global/workloadIdentityPools/<pool-id>".to_string(),
            ));
        }

        Ok(())
    }

    pub fn test_aws_connectivity(
        config: &AwsOnboardingConfig,
        simulated_missing_perms: &[&str],
    ) -> Result<OnboardingValidationResult, ScannerError> {
        let required_perms = [
            "s3:GetBucketPublicAccessBlock",
            "s3:GetBucketPolicy",
            "iam:GetAccountSummary",
            "ec2:DescribeSecurityGroups",
            "cloudtrail:DescribeTrails",
        ];

        let missing: Vec<String> = simulated_missing_perms
            .iter()
            .map(|&s| s.to_string())
            .collect();

        if !missing.is_empty() {
            return Ok(OnboardingValidationResult {
                is_valid: false,
                provider: CloudProvider::Aws,
                native_id: config.account_id.clone(),
                identity: config.role_arn.clone(),
                enabled_regions: config.regions.clone(),
                missing_permissions: missing,
                details: json!({
                    "role_assumption": "succeeded",
                    "permissions_check": "failed",
                    "required_permissions": required_perms,
                }),
            });
        }

        Ok(OnboardingValidationResult {
            is_valid: true,
            provider: CloudProvider::Aws,
            native_id: config.account_id.clone(),
            identity: config.role_arn.clone(),
            enabled_regions: if config.regions.is_empty() {
                vec!["us-east-1".to_string()]
            } else {
                config.regions.clone()
            },
            missing_permissions: Vec::new(),
            details: json!({
                "role_assumption": "succeeded",
                "identity_verified": true,
                "external_id_verified": true,
                "permissions_check": "passed",
                "assumed_role_arn": format!("{}/cloudsec-scanner-session", config.role_arn),
            }),
        })
    }

    pub fn test_azure_connectivity(
        config: &AzureOnboardingConfig,
        simulated_missing_perms: &[&str],
    ) -> Result<OnboardingValidationResult, ScannerError> {
        let missing: Vec<String> = simulated_missing_perms
            .iter()
            .map(|&s| s.to_string())
            .collect();

        if !missing.is_empty() {
            return Ok(OnboardingValidationResult {
                is_valid: false,
                provider: CloudProvider::Azure,
                native_id: config.subscription_id.clone(),
                identity: format!("spn:{}", config.client_id),
                enabled_regions: vec!["eastus".to_string()],
                missing_permissions: missing,
                details: json!({
                    "token_acquisition": "succeeded",
                    "permissions_check": "failed",
                }),
            });
        }

        Ok(OnboardingValidationResult {
            is_valid: true,
            provider: CloudProvider::Azure,
            native_id: config.subscription_id.clone(),
            identity: format!("spn:{}", config.client_id),
            enabled_regions: vec!["eastus".to_string()],
            missing_permissions: Vec::new(),
            details: json!({
                "token_acquisition": "succeeded",
                "tenant_verified": true,
                "subscription_accessible": true,
                "permissions_check": "passed",
                "role_assignments": ["Reader"],
            }),
        })
    }

    pub fn test_gcp_connectivity(
        config: &GcpOnboardingConfig,
        simulated_missing_perms: &[&str],
    ) -> Result<OnboardingValidationResult, ScannerError> {
        let missing: Vec<String> = simulated_missing_perms
            .iter()
            .map(|&s| s.to_string())
            .collect();

        if !missing.is_empty() {
            return Ok(OnboardingValidationResult {
                is_valid: false,
                provider: CloudProvider::Gcp,
                native_id: config.project_id.clone(),
                identity: config.service_account_email.clone(),
                enabled_regions: vec!["us-central1".to_string()],
                missing_permissions: missing,
                details: json!({
                    "federation_token_exchange": "succeeded",
                    "permissions_check": "failed",
                }),
            });
        }

        Ok(OnboardingValidationResult {
            is_valid: true,
            provider: CloudProvider::Gcp,
            native_id: config.project_id.clone(),
            identity: config.service_account_email.clone(),
            enabled_regions: vec!["us-central1".to_string()],
            missing_permissions: Vec::new(),
            details: json!({
                "federation_token_exchange": "succeeded",
                "impersonation_verified": true,
                "project_accessible": true,
                "permissions_check": "passed",
            }),
        })
    }
}
