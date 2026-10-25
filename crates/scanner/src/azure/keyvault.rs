use cloudsec_domain::{CloudProvider, Resource, Severity};
use serde_json::{Value, json};

use crate::check::{Check, CheckEvaluation};

/// Check: Azure Key Vault Network Access Restricted and RBAC Enabled
pub struct AzureKeyVaultNetworkAndRbacCheck;

impl Check for AzureKeyVaultNetworkAndRbacCheck {
    fn id(&self) -> &str {
        "azure-keyvault-network-and-rbac"
    }

    fn provider(&self) -> CloudProvider {
        CloudProvider::Azure
    }

    fn service(&self) -> &str {
        "keyvault"
    }

    fn category(&self) -> &str {
        "secrets_management"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn title(&self) -> &str {
        "Ensure Key Vault Restricts Public Network Access and Uses Azure RBAC Authorization"
    }

    fn description(&self) -> &str {
        "Verify that Azure Key Vault has public network access disabled or restricted via firewall/private endpoints and uses Azure RBAC for authorization."
    }

    fn remediation(&self) -> &str {
        "Disable public network access or configure firewall rules with default action 'Deny', attach private endpoints, and enable 'enableRbacAuthorization'."
    }

    fn base_severity(&self) -> Severity {
        Severity::High
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type != "azure_key_vault"
            && resource.resource_type != "Microsoft.KeyVault/vaults"
        {
            return CheckEvaluation::NotApplicable;
        }

        let config = &resource.configuration;

        let public_network_access = config
            .get("public_network_access")
            .or_else(|| config.get("publicNetworkAccess"))
            .and_then(Value::as_str)
            .unwrap_or("Enabled");

        let default_action = config
            .get("network_acls")
            .or_else(|| config.get("networkAcls"))
            .and_then(|acls| {
                acls.get("default_action")
                    .or_else(|| acls.get("defaultAction"))
            })
            .and_then(Value::as_str)
            .unwrap_or("Allow");

        let has_private_endpoints = config
            .get("private_endpoint_connections")
            .or_else(|| config.get("privateEndpointConnections"))
            .and_then(Value::as_array)
            .map(|arr| !arr.is_empty())
            .unwrap_or(false);

        let network_secure = public_network_access.eq_ignore_ascii_case("Disabled")
            || (default_action.eq_ignore_ascii_case("Deny") || has_private_endpoints);

        let enable_rbac = config
            .get("enable_rbac_authorization")
            .or_else(|| config.get("enableRbacAuthorization"))
            .and_then(Value::as_bool)
            .unwrap_or(false);

        if network_secure && enable_rbac {
            CheckEvaluation::Passed
        } else {
            CheckEvaluation::Failed {
                severity: self.base_severity(),
                evidence: json!({
                    "public_network_access": public_network_access,
                    "network_acls_default_action": default_action,
                    "has_private_endpoints": has_private_endpoints,
                    "enable_rbac_authorization": enable_rbac,
                }),
                message: format!(
                    "Key Vault '{}' allows public network access or does not use Azure RBAC authorization",
                    resource
                        .name
                        .as_deref()
                        .unwrap_or(&resource.provider_native_id)
                ),
            }
        }
    }
}

/// Check: Azure Key Vault Soft Delete, Purge Protection, and Expiration Policy Enabled
pub struct AzureKeyVaultProtectionAndExpirationCheck;

impl Check for AzureKeyVaultProtectionAndExpirationCheck {
    fn id(&self) -> &str {
        "azure-keyvault-protection-and-expiration"
    }

    fn provider(&self) -> CloudProvider {
        CloudProvider::Azure
    }

    fn service(&self) -> &str {
        "keyvault"
    }

    fn category(&self) -> &str {
        "data_protection"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn title(&self) -> &str {
        "Ensure Key Vault Has Soft Delete, Purge Protection, and Expiration Policies Enabled"
    }

    fn description(&self) -> &str {
        "Verify that Key Vault has soft delete and purge protection enabled to prevent accidental deletion, and enforces expiration dates on keys and secrets."
    }

    fn remediation(&self) -> &str {
        "Enable 'enablePurgeProtection' and 'enableSoftDelete' on the Key Vault, and configure expiration dates for all stored keys and secrets."
    }

    fn base_severity(&self) -> Severity {
        Severity::High
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type != "azure_key_vault"
            && resource.resource_type != "Microsoft.KeyVault/vaults"
        {
            return CheckEvaluation::NotApplicable;
        }

        let config = &resource.configuration;

        let soft_delete = config
            .get("enable_soft_delete")
            .or_else(|| config.get("enableSoftDelete"))
            .and_then(Value::as_bool)
            .unwrap_or(true);

        let purge_protection = config
            .get("enable_purge_protection")
            .or_else(|| config.get("enablePurgeProtection"))
            .and_then(Value::as_bool)
            .unwrap_or(false);

        let keys_have_expiration = config
            .get("keys_have_expiration")
            .and_then(Value::as_bool)
            .unwrap_or(true);

        let secrets_have_expiration = config
            .get("secrets_have_expiration")
            .and_then(Value::as_bool)
            .unwrap_or(true);

        let logging_enabled = config
            .get("diagnostic_settings_enabled")
            .or_else(|| config.get("logging_enabled"))
            .and_then(Value::as_bool)
            .unwrap_or(true);

        if soft_delete
            && purge_protection
            && keys_have_expiration
            && secrets_have_expiration
            && logging_enabled
        {
            CheckEvaluation::Passed
        } else {
            CheckEvaluation::Failed {
                severity: self.base_severity(),
                evidence: json!({
                    "enable_soft_delete": soft_delete,
                    "enable_purge_protection": purge_protection,
                    "keys_have_expiration": keys_have_expiration,
                    "secrets_have_expiration": secrets_have_expiration,
                    "diagnostic_logging_enabled": logging_enabled,
                }),
                message: format!(
                    "Key Vault '{}' lacks purge protection, soft delete, diagnostic logging, or expiration policies",
                    resource
                        .name
                        .as_deref()
                        .unwrap_or(&resource.provider_native_id)
                ),
            }
        }
    }
}
