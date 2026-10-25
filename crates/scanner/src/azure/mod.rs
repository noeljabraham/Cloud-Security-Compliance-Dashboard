pub mod fixtures;
pub mod iam;
pub mod keyvault;
pub mod mappings;
pub mod nsg;
pub mod storage;

use std::sync::Arc;

use crate::{
    azure::{
        iam::{
            AzureEntraIdentityCoverageCheck, AzureEntraPrivilegedRoleGovernanceCheck,
            AzureRbacNoDirectUserOwnerAssignmentsCheck, AzureRbacNoWildcardCustomRolesCheck,
        },
        keyvault::{AzureKeyVaultNetworkAndRbacCheck, AzureKeyVaultProtectionAndExpirationCheck},
        nsg::{AzureNsgNoBroadRangesOrStaleRulesCheck, AzureNsgNoOpenAdminOrDbPortsCheck},
        storage::{
            AzureStorageCmkEncryptionCheck, AzureStorageLoggingAndRetentionCheck,
            AzureStoragePublicAccessCheck, AzureStorageSecureTransferAndTlsCheck,
        },
    },
    check::Check,
    registry::ProviderRegistry,
};

pub fn get_all_azure_checks() -> Vec<Arc<dyn Check>> {
    vec![
        // Storage Accounts (4 checks)
        Arc::new(AzureStoragePublicAccessCheck),
        Arc::new(AzureStorageSecureTransferAndTlsCheck),
        Arc::new(AzureStorageCmkEncryptionCheck),
        Arc::new(AzureStorageLoggingAndRetentionCheck),
        // RBAC & Microsoft Entra ID (4 checks)
        Arc::new(AzureRbacNoDirectUserOwnerAssignmentsCheck),
        Arc::new(AzureRbacNoWildcardCustomRolesCheck),
        Arc::new(AzureEntraPrivilegedRoleGovernanceCheck),
        Arc::new(AzureEntraIdentityCoverageCheck),
        // Network Security Groups (2 checks)
        Arc::new(AzureNsgNoOpenAdminOrDbPortsCheck),
        Arc::new(AzureNsgNoBroadRangesOrStaleRulesCheck),
        // Key Vault (2 checks)
        Arc::new(AzureKeyVaultNetworkAndRbacCheck),
        Arc::new(AzureKeyVaultProtectionAndExpirationCheck),
    ]
}

pub fn register_all_azure_checks(registry: &mut ProviderRegistry) {
    for check in get_all_azure_checks() {
        registry.register_check(check);
    }
}
