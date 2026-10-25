pub mod compute;
pub mod fixtures;
pub mod iam;
pub mod mappings;
pub mod sql;
pub mod storage;

use std::sync::Arc;

use crate::{
    check::Check,
    gcp::{
        compute::{
            GcpComputeFirewallNoOpenAdminOrDbPortsCheck,
            GcpComputeFirewallTargetLoggingAndDefaultNetworkCheck,
            GcpComputeNoUnattachedOrDirectExternalIpsCheck,
        },
        iam::{
            GcpIamNoPrimitiveRolesAndWildcardCustomRolesCheck,
            GcpIamNoPublicPrincipalsAndStaleKeysCheck, GcpLoggingDataAccessAuditAndSinksCheck,
        },
        sql::{GcpSqlBackupCmekAndFlagsCheck, GcpSqlNoPublicIpAndAuthorizedNetworksCheck},
        storage::{
            GcpStorageEncryptionLoggingRetentionCheck, GcpStorageNoPublicIamBindingsCheck,
            GcpStorageUniformAccessAndPapCheck,
        },
    },
    registry::ProviderRegistry,
};

pub fn get_all_gcp_checks() -> Vec<Arc<dyn Check>> {
    vec![
        // Storage (3 checks)
        Arc::new(GcpStorageNoPublicIamBindingsCheck),
        Arc::new(GcpStorageUniformAccessAndPapCheck),
        Arc::new(GcpStorageEncryptionLoggingRetentionCheck),
        // Compute Engine & VPC (3 checks)
        Arc::new(GcpComputeFirewallNoOpenAdminOrDbPortsCheck),
        Arc::new(GcpComputeFirewallTargetLoggingAndDefaultNetworkCheck),
        Arc::new(GcpComputeNoUnattachedOrDirectExternalIpsCheck),
        // Cloud SQL (2 checks)
        Arc::new(GcpSqlNoPublicIpAndAuthorizedNetworksCheck),
        Arc::new(GcpSqlBackupCmekAndFlagsCheck),
        // IAM & Audit Logging (3 checks)
        Arc::new(GcpIamNoPrimitiveRolesAndWildcardCustomRolesCheck),
        Arc::new(GcpIamNoPublicPrincipalsAndStaleKeysCheck),
        Arc::new(GcpLoggingDataAccessAuditAndSinksCheck),
    ]
}

pub fn register_all_gcp_checks(registry: &mut ProviderRegistry) {
    for check in get_all_gcp_checks() {
        registry.register_check(check);
    }
}
