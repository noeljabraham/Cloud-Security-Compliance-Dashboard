use cloudsec_domain::{DiscoveredResource, Id, Resource};
use serde_json::json;

pub struct AzureTestFixtures;

impl AzureTestFixtures {
    // -------------------------------------------------------------
    // Storage Account Fixtures
    // -------------------------------------------------------------

    pub fn compliant_storage_account(org_id: Id, account_id: Id, name: &str) -> Resource {
        let disc = DiscoveredResource {
            provider_native_id: format!(
                "/subscriptions/sub-123/resourceGroups/rg-prod/providers/Microsoft.Storage/storageAccounts/{name}"
            ),
            resource_type: "azure_storage_account".to_string(),
            name: Some(name.to_string()),
            region: Some("eastus".to_string()),
            tags: json!({"env": "production", "owner": "sec-team"}),
            configuration: json!({
                "allow_blob_public_access": false,
                "supports_https_traffic_only": true,
                "minimum_tls_version": "TLS1_2",
                "public_network_access": "Disabled",
                "network_rule_set": {
                    "default_action": "Deny",
                    "bypass": "AzureServices"
                },
                "private_endpoint_connections": [
                    {"id": "pe-blob-01", "status": "Approved"}
                ],
                "key_source": "Microsoft.Keyvault",
                "key_vault_properties": {
                    "key_name": "prod-storage-cmk",
                    "key_vault_uri": "https://kv-prod-eastus.vault.azure.net"
                },
                "logging_enabled": true,
                "blob_logging": {
                    "read": true,
                    "write": true,
                    "delete": true,
                    "retention_days": 365
                }
            }),
        };
        disc.into_resource(org_id, account_id)
    }

    pub fn non_compliant_storage_account(org_id: Id, account_id: Id, name: &str) -> Resource {
        let disc = DiscoveredResource {
            provider_native_id: format!(
                "/subscriptions/sub-123/resourceGroups/rg-dev/providers/Microsoft.Storage/storageAccounts/{name}"
            ),
            resource_type: "azure_storage_account".to_string(),
            name: Some(name.to_string()),
            region: Some("eastus".to_string()),
            tags: json!({"env": "development"}),
            configuration: json!({
                "allow_blob_public_access": true,
                "supports_https_traffic_only": false,
                "minimum_tls_version": "TLS1_0",
                "public_network_access": "Enabled",
                "network_rule_set": {
                    "default_action": "Allow"
                },
                "private_endpoint_connections": [],
                "key_source": "Microsoft.Storage",
                "logging_enabled": false
            }),
        };
        disc.into_resource(org_id, account_id)
    }

    // -------------------------------------------------------------
    // IAM & RBAC Fixtures
    // -------------------------------------------------------------

    pub fn compliant_role_assignment(org_id: Id, account_id: Id, name: &str) -> Resource {
        let disc = DiscoveredResource {
            provider_native_id: format!(
                "/subscriptions/sub-123/providers/Microsoft.Authorization/roleAssignments/{name}"
            ),
            resource_type: "azure_role_assignment".to_string(),
            name: Some(name.to_string()),
            region: None,
            tags: json!({}),
            configuration: json!({
                "role_definition_name": "Reader",
                "principal_type": "Group",
                "scope": "/subscriptions/sub-123/resourceGroups/rg-workloads",
                "is_stale": false
            }),
        };
        disc.into_resource(org_id, account_id)
    }

    pub fn direct_user_owner_assignment(org_id: Id, account_id: Id, name: &str) -> Resource {
        let disc = DiscoveredResource {
            provider_native_id: format!(
                "/subscriptions/sub-123/providers/Microsoft.Authorization/roleAssignments/{name}"
            ),
            resource_type: "azure_role_assignment".to_string(),
            name: Some(name.to_string()),
            region: None,
            tags: json!({}),
            configuration: json!({
                "role_definition_name": "Owner",
                "principal_type": "User",
                "scope": "/subscriptions/sub-123",
                "is_stale": false
            }),
        };
        disc.into_resource(org_id, account_id)
    }

    pub fn compliant_custom_role(org_id: Id, account_id: Id, name: &str) -> Resource {
        let disc = DiscoveredResource {
            provider_native_id: format!(
                "/subscriptions/sub-123/providers/Microsoft.Authorization/roleDefinitions/{name}"
            ),
            resource_type: "azure_role_definition".to_string(),
            name: Some(name.to_string()),
            region: None,
            tags: json!({}),
            configuration: json!({
                "role_type": "CustomRole",
                "is_custom": true,
                "actions": [
                    "Microsoft.Compute/virtualMachines/read",
                    "Microsoft.Compute/virtualMachines/restart/action"
                ]
            }),
        };
        disc.into_resource(org_id, account_id)
    }

    pub fn wildcard_custom_role(org_id: Id, account_id: Id, name: &str) -> Resource {
        let disc = DiscoveredResource {
            provider_native_id: format!(
                "/subscriptions/sub-123/providers/Microsoft.Authorization/roleDefinitions/{name}"
            ),
            resource_type: "azure_role_definition".to_string(),
            name: Some(name.to_string()),
            region: None,
            tags: json!({}),
            configuration: json!({
                "role_type": "CustomRole",
                "is_custom": true,
                "actions": [
                    "*"
                ]
            }),
        };
        disc.into_resource(org_id, account_id)
    }

    // -------------------------------------------------------------
    // Microsoft Entra ID Fixtures
    // -------------------------------------------------------------

    pub fn compliant_entra_governance(org_id: Id, account_id: Id) -> Resource {
        let disc = DiscoveredResource {
            provider_native_id: "tenant-entra-governance-prod".to_string(),
            resource_type: "azure_entra_governance".to_string(),
            name: Some("Entra ID Tenant Governance".to_string()),
            region: None,
            tags: json!({}),
            configuration: json!({
                "mfa_enforced_for_admins": true,
                "conditional_access_policies_active": true,
                "pim_enabled_for_privileged_roles": true,
                "api_status": "ok",
                "licensing_status": "ok",
                "mfa_evidence_available": true
            }),
        };
        disc.into_resource(org_id, account_id)
    }

    pub fn non_compliant_entra_governance(org_id: Id, account_id: Id) -> Resource {
        let disc = DiscoveredResource {
            provider_native_id: "tenant-entra-governance-legacy".to_string(),
            resource_type: "azure_entra_governance".to_string(),
            name: Some("Entra ID Tenant Governance Legacy".to_string()),
            region: None,
            tags: json!({}),
            configuration: json!({
                "mfa_enforced_for_admins": false,
                "conditional_access_policies_active": false,
                "pim_enabled_for_privileged_roles": false,
                "api_status": "ok",
                "licensing_status": "ok",
                "mfa_evidence_available": true
            }),
        };
        disc.into_resource(org_id, account_id)
    }

    pub fn coverage_gap_entra_governance(org_id: Id, account_id: Id) -> Resource {
        let disc = DiscoveredResource {
            provider_native_id: "tenant-entra-governance-unlicensed".to_string(),
            resource_type: "azure_entra_governance".to_string(),
            name: Some("Entra ID Unlicensed Tenant".to_string()),
            region: None,
            tags: json!({}),
            configuration: json!({
                "api_status": "permission_denied",
                "licensing_status": "insufficient_licensing",
                "mfa_evidence_available": false
            }),
        };
        disc.into_resource(org_id, account_id)
    }

    // -------------------------------------------------------------
    // NSG Fixtures
    // -------------------------------------------------------------

    pub fn compliant_nsg(org_id: Id, account_id: Id, name: &str) -> Resource {
        let disc = DiscoveredResource {
            provider_native_id: format!(
                "/subscriptions/sub-123/resourceGroups/rg-prod/providers/Microsoft.Network/networkSecurityGroups/{name}"
            ),
            resource_type: "azure_network_security_group".to_string(),
            name: Some(name.to_string()),
            region: Some("eastus".to_string()),
            tags: json!({}),
            configuration: json!({
                "subnets": [{"id": "subnet-prod-app"}],
                "network_interfaces": [{"id": "nic-app-01"}],
                "security_rules": [
                    {
                        "name": "AllowHttpsInbound",
                        "access": "Allow",
                        "direction": "Inbound",
                        "priority": 100,
                        "source_address_prefix": "Internet",
                        "destination_port_range": "443"
                    },
                    {
                        "name": "AllowInternalSsh",
                        "access": "Allow",
                        "direction": "Inbound",
                        "priority": 200,
                        "source_address_prefix": "10.0.0.0/16",
                        "destination_port_range": "22"
                    }
                ]
            }),
        };
        disc.into_resource(org_id, account_id)
    }

    pub fn open_admin_ports_nsg(org_id: Id, account_id: Id, name: &str) -> Resource {
        let disc = DiscoveredResource {
            provider_native_id: format!(
                "/subscriptions/sub-123/resourceGroups/rg-dev/providers/Microsoft.Network/networkSecurityGroups/{name}"
            ),
            resource_type: "azure_network_security_group".to_string(),
            name: Some(name.to_string()),
            region: Some("eastus".to_string()),
            tags: json!({}),
            configuration: json!({
                "subnets": [{"id": "subnet-dev-app"}],
                "network_interfaces": [],
                "security_rules": [
                    {
                        "name": "AllowAllInternetSsh",
                        "access": "Allow",
                        "direction": "Inbound",
                        "priority": 100,
                        "source_address_prefix": "*",
                        "destination_port_range": "22"
                    },
                    {
                        "name": "AllowAllInternetRdp",
                        "access": "Allow",
                        "direction": "Inbound",
                        "priority": 110,
                        "source_address_prefix": "Internet",
                        "destination_port_range": "3389"
                    }
                ]
            }),
        };
        disc.into_resource(org_id, account_id)
    }

    pub fn stale_broad_nsg(org_id: Id, account_id: Id, name: &str) -> Resource {
        let disc = DiscoveredResource {
            provider_native_id: format!(
                "/subscriptions/sub-123/resourceGroups/rg-dev/providers/Microsoft.Network/networkSecurityGroups/{name}"
            ),
            resource_type: "azure_network_security_group".to_string(),
            name: Some(name.to_string()),
            region: Some("eastus".to_string()),
            tags: json!({}),
            configuration: json!({
                "subnets": [],
                "network_interfaces": [],
                "is_stale": true,
                "security_rules": [
                    {
                        "name": "AllowAllPortsAny",
                        "access": "Allow",
                        "direction": "Inbound",
                        "priority": 500,
                        "source_address_prefix": "*",
                        "destination_port_range": "*",
                        "is_stale": true
                    }
                ]
            }),
        };
        disc.into_resource(org_id, account_id)
    }

    // -------------------------------------------------------------
    // Key Vault Fixtures
    // -------------------------------------------------------------

    pub fn compliant_key_vault(org_id: Id, account_id: Id, name: &str) -> Resource {
        let disc = DiscoveredResource {
            provider_native_id: format!(
                "/subscriptions/sub-123/resourceGroups/rg-prod/providers/Microsoft.KeyVault/vaults/{name}"
            ),
            resource_type: "azure_key_vault".to_string(),
            name: Some(name.to_string()),
            region: Some("eastus".to_string()),
            tags: json!({"env": "production"}),
            configuration: json!({
                "public_network_access": "Disabled",
                "enable_rbac_authorization": true,
                "enable_soft_delete": true,
                "enable_purge_protection": true,
                "keys_have_expiration": true,
                "secrets_have_expiration": true,
                "diagnostic_settings_enabled": true,
                "network_acls": {
                    "default_action": "Deny"
                },
                "private_endpoint_connections": [
                    {"id": "pe-kv-01"}
                ]
            }),
        };
        disc.into_resource(org_id, account_id)
    }

    pub fn non_compliant_key_vault(org_id: Id, account_id: Id, name: &str) -> Resource {
        let disc = DiscoveredResource {
            provider_native_id: format!(
                "/subscriptions/sub-123/resourceGroups/rg-dev/providers/Microsoft.KeyVault/vaults/{name}"
            ),
            resource_type: "azure_key_vault".to_string(),
            name: Some(name.to_string()),
            region: Some("eastus".to_string()),
            tags: json!({"env": "development"}),
            configuration: json!({
                "public_network_access": "Enabled",
                "enable_rbac_authorization": false,
                "enable_soft_delete": true,
                "enable_purge_protection": false,
                "keys_have_expiration": false,
                "secrets_have_expiration": false,
                "diagnostic_settings_enabled": false,
                "network_acls": {
                    "default_action": "Allow"
                }
            }),
        };
        disc.into_resource(org_id, account_id)
    }

    // -------------------------------------------------------------
    // General Edge-case Fixtures
    // -------------------------------------------------------------

    pub fn malformed_resource(org_id: Id, account_id: Id, resource_type: &str) -> Resource {
        let disc = DiscoveredResource {
            provider_native_id: "corrupted-azure-id".to_string(),
            resource_type: resource_type.to_string(),
            name: None,
            region: None,
            tags: json!(null),
            configuration: json!({}),
        };
        disc.into_resource(org_id, account_id)
    }

    pub fn wrong_provider_resource(org_id: Id, account_id: Id) -> Resource {
        let disc = DiscoveredResource {
            provider_native_id: "gcp-storage-bucket-not-azure".to_string(),
            resource_type: "gcp_storage_bucket".to_string(),
            name: Some("not-azure-bucket".to_string()),
            region: Some("us-central1".to_string()),
            tags: json!({}),
            configuration: json!({}),
        };
        disc.into_resource(org_id, account_id)
    }
}
