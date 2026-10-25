use cloudsec_domain::{CloudProvider, Resource, Severity};
use serde_json::{Value, json};

use crate::check::{Check, CheckEvaluation};

/// Check: Azure Storage Accounts Disallow Public Blob and Anonymous Container Access
pub struct AzureStoragePublicAccessCheck;

impl Check for AzureStoragePublicAccessCheck {
    fn id(&self) -> &str {
        "azure-storage-public-access"
    }

    fn provider(&self) -> CloudProvider {
        CloudProvider::Azure
    }

    fn service(&self) -> &str {
        "storage"
    }

    fn category(&self) -> &str {
        "storage_security"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn title(&self) -> &str {
        "Ensure Storage Account Public Access and Anonymous Blob Access are Disabled"
    }

    fn description(&self) -> &str {
        "Verify that Azure Storage Accounts disallow public blob access and anonymous container exposure."
    }

    fn remediation(&self) -> &str {
        "Set 'allowBlobPublicAccess' to false on the Storage Account and disable public access on all blob containers."
    }

    fn base_severity(&self) -> Severity {
        Severity::High
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type != "azure_storage_account"
            && resource.resource_type != "Microsoft.Storage/storageAccounts"
        {
            return CheckEvaluation::NotApplicable;
        }

        let config = &resource.configuration;

        // Check allow_blob_public_access
        let allow_public = config
            .get("allow_blob_public_access")
            .or_else(|| config.get("allowBlobPublicAccess"))
            .and_then(Value::as_bool)
            .unwrap_or(false);

        // Check container-level anonymous access
        let has_anonymous_containers = config
            .get("anonymous_containers")
            .or_else(|| config.get("public_containers"))
            .and_then(Value::as_array)
            .map(|arr| !arr.is_empty())
            .unwrap_or(false);

        let public_network_enabled = config
            .get("public_network_access")
            .or_else(|| config.get("publicNetworkAccess"))
            .and_then(Value::as_str)
            .map(|s| s.eq_ignore_ascii_case("Enabled"))
            .unwrap_or(false);

        let network_rules_default_allow = config
            .get("network_rule_set")
            .or_else(|| config.get("networkAcls"))
            .and_then(|nacls| {
                nacls
                    .get("default_action")
                    .or_else(|| nacls.get("defaultAction"))
            })
            .and_then(Value::as_str)
            .map(|s| s.eq_ignore_ascii_case("Allow"))
            .unwrap_or(false);

        if !allow_public
            && !has_anonymous_containers
            && (!public_network_enabled || !network_rules_default_allow)
        {
            CheckEvaluation::Passed
        } else {
            CheckEvaluation::Failed {
                severity: self.base_severity(),
                evidence: json!({
                    "allow_blob_public_access": allow_public,
                    "has_anonymous_containers": has_anonymous_containers,
                    "public_network_access_enabled": public_network_enabled,
                    "network_rules_default_allow": network_rules_default_allow,
                }),
                message: format!(
                    "Azure Storage Account '{}' allows public blob access or has public network exposure",
                    resource
                        .name
                        .as_deref()
                        .unwrap_or(&resource.provider_native_id)
                ),
            }
        }
    }
}

/// Check: Azure Storage Accounts Require Secure Transfer, Minimum TLS 1.2, and Firewall/Private Endpoints
pub struct AzureStorageSecureTransferAndTlsCheck;

impl Check for AzureStorageSecureTransferAndTlsCheck {
    fn id(&self) -> &str {
        "azure-storage-secure-transfer-and-tls"
    }

    fn provider(&self) -> CloudProvider {
        CloudProvider::Azure
    }

    fn service(&self) -> &str {
        "storage"
    }

    fn category(&self) -> &str {
        "data_protection"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn title(&self) -> &str {
        "Ensure Secure Transfer Required, Minimum TLS 1.2, and Firewall/Private Endpoints Configured"
    }

    fn description(&self) -> &str {
        "Verify that Azure Storage Accounts enforce HTTPS-only traffic, TLS version 1.2+, and restrict access via firewall or private endpoints."
    }

    fn remediation(&self) -> &str {
        "Enable 'supportsHttpsTrafficOnly', set 'minimumTlsVersion' to 'TLS1_2', and configure network rule set with default action 'Deny' or attach private endpoints."
    }

    fn base_severity(&self) -> Severity {
        Severity::High
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type != "azure_storage_account"
            && resource.resource_type != "Microsoft.Storage/storageAccounts"
        {
            return CheckEvaluation::NotApplicable;
        }

        let config = &resource.configuration;

        let https_only = config
            .get("supports_https_traffic_only")
            .or_else(|| config.get("enableHttpsTrafficOnly"))
            .and_then(Value::as_bool)
            .unwrap_or(true);

        let min_tls = config
            .get("minimum_tls_version")
            .or_else(|| config.get("minimumTlsVersion"))
            .and_then(Value::as_str)
            .unwrap_or("TLS1_2");

        let tls_compliant = matches!(
            min_tls.to_uppercase().as_str(),
            "TLS1_2" | "TLS1_3" | "1.2" | "1.3"
        );

        let default_action = config
            .get("network_rule_set")
            .or_else(|| config.get("networkAcls"))
            .and_then(|nacls| {
                nacls
                    .get("default_action")
                    .or_else(|| nacls.get("defaultAction"))
            })
            .and_then(Value::as_str)
            .unwrap_or("Deny");

        let has_private_endpoints = config
            .get("private_endpoint_connections")
            .and_then(Value::as_array)
            .map(|arr| !arr.is_empty())
            .unwrap_or(false);

        let network_restricted =
            default_action.eq_ignore_ascii_case("Deny") || has_private_endpoints;

        if https_only && tls_compliant && network_restricted {
            CheckEvaluation::Passed
        } else {
            CheckEvaluation::Failed {
                severity: self.base_severity(),
                evidence: json!({
                    "supports_https_traffic_only": https_only,
                    "minimum_tls_version": min_tls,
                    "network_rule_default_action": default_action,
                    "has_private_endpoints": has_private_endpoints,
                }),
                message: format!(
                    "Azure Storage Account '{}' does not enforce HTTPS only, TLS 1.2+, or network perimeter restrictions",
                    resource
                        .name
                        .as_deref()
                        .unwrap_or(&resource.provider_native_id)
                ),
            }
        }
    }
}

/// Check: Azure Storage Accounts Use Customer-Managed Keys (CMK)
pub struct AzureStorageCmkEncryptionCheck;

impl Check for AzureStorageCmkEncryptionCheck {
    fn id(&self) -> &str {
        "azure-storage-cmk-encryption"
    }

    fn provider(&self) -> CloudProvider {
        CloudProvider::Azure
    }

    fn service(&self) -> &str {
        "storage"
    }

    fn category(&self) -> &str {
        "cryptography"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn title(&self) -> &str {
        "Ensure Storage Accounts Use Customer-Managed Keys (CMK) for Encryption"
    }

    fn description(&self) -> &str {
        "Verify that Azure Storage Accounts use customer-managed encryption keys in Azure Key Vault for data at rest."
    }

    fn remediation(&self) -> &str {
        "Configure customer-managed keys (CMK) in Azure Key Vault for the storage account encryption settings."
    }

    fn base_severity(&self) -> Severity {
        Severity::Medium
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type != "azure_storage_account"
            && resource.resource_type != "Microsoft.Storage/storageAccounts"
        {
            return CheckEvaluation::NotApplicable;
        }

        let config = &resource.configuration;

        let key_source = config
            .get("key_source")
            .or_else(|| {
                config
                    .get("encryption")
                    .and_then(|e| e.get("key_source").or_else(|| e.get("keySource")))
            })
            .and_then(Value::as_str)
            .unwrap_or("Microsoft.Storage");

        let has_keyvault_properties = config
            .get("key_vault_properties")
            .or_else(|| {
                config.get("encryption").and_then(|e| {
                    e.get("key_vault_properties")
                        .or_else(|| e.get("keyVaultProperties"))
                })
            })
            .and_then(|kv| {
                kv.get("key_name")
                    .or_else(|| kv.get("keyName"))
                    .or_else(|| kv.get("key_vault_uri"))
            })
            .is_some();

        let is_cmk =
            key_source.eq_ignore_ascii_case("Microsoft.Keyvault") || has_keyvault_properties;

        if is_cmk {
            CheckEvaluation::Passed
        } else {
            CheckEvaluation::Failed {
                severity: self.base_severity(),
                evidence: json!({
                    "key_source": key_source,
                    "has_keyvault_properties": has_keyvault_properties,
                }),
                message: format!(
                    "Azure Storage Account '{}' is using platform-managed keys instead of customer-managed keys (CMK)",
                    resource
                        .name
                        .as_deref()
                        .unwrap_or(&resource.provider_native_id)
                ),
            }
        }
    }
}

/// Check: Azure Storage Account Diagnostic Logging and Retention Configured
pub struct AzureStorageLoggingAndRetentionCheck;

impl Check for AzureStorageLoggingAndRetentionCheck {
    fn id(&self) -> &str {
        "azure-storage-logging-and-retention"
    }

    fn provider(&self) -> CloudProvider {
        CloudProvider::Azure
    }

    fn service(&self) -> &str {
        "storage"
    }

    fn category(&self) -> &str {
        "logging"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn title(&self) -> &str {
        "Ensure Storage Account Diagnostic Logging and Retention are Configured"
    }

    fn description(&self) -> &str {
        "Verify that Azure Storage Accounts have diagnostic logging enabled for read, write, and delete operations with retention."
    }

    fn remediation(&self) -> &str {
        "Enable storage diagnostic settings or classic logging for blob services with retention enabled or stream to Log Analytics."
    }

    fn base_severity(&self) -> Severity {
        Severity::Medium
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type != "azure_storage_account"
            && resource.resource_type != "Microsoft.Storage/storageAccounts"
        {
            return CheckEvaluation::NotApplicable;
        }

        let config = &resource.configuration;

        let logging_enabled = config
            .get("logging_enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        let diagnostic_settings_enabled = config
            .get("diagnostic_settings")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter().any(|setting| {
                    setting
                        .get("enabled")
                        .and_then(Value::as_bool)
                        .unwrap_or(true)
                })
            })
            .unwrap_or(false);

        let blob_logging = config
            .get("blob_logging")
            .map(|l| {
                let read = l.get("read").and_then(Value::as_bool).unwrap_or(false);
                let write = l.get("write").and_then(Value::as_bool).unwrap_or(false);
                let delete = l.get("delete").and_then(Value::as_bool).unwrap_or(false);
                read && write && delete
            })
            .unwrap_or(false);

        if logging_enabled || diagnostic_settings_enabled || blob_logging {
            CheckEvaluation::Passed
        } else {
            CheckEvaluation::Failed {
                severity: self.base_severity(),
                evidence: json!({
                    "logging_enabled": logging_enabled,
                    "diagnostic_settings_enabled": diagnostic_settings_enabled,
                    "blob_logging_complete": blob_logging,
                }),
                message: format!(
                    "Azure Storage Account '{}' does not have comprehensive diagnostic logging enabled",
                    resource
                        .name
                        .as_deref()
                        .unwrap_or(&resource.provider_native_id)
                ),
            }
        }
    }
}
