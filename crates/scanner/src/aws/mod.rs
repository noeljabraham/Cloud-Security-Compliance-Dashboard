pub mod cloudtrail;
pub mod ec2;
pub mod fixtures;
pub mod iam;
pub mod lambda;
pub mod mappings;
pub mod rds;
pub mod s3;

use std::sync::Arc;

use crate::{
    aws::{
        cloudtrail::{
            AwsCloudTrailCloudWatchLogsCheck, AwsCloudTrailLogValidationAndEncryptionCheck,
            AwsCloudTrailMultiRegionTrailCheck,
        },
        ec2::{
            AwsEc2DefaultSgRestrictsAllCheck, AwsEc2EbsEncryptionEnabledCheck,
            AwsEc2Imdsv2EnforcedCheck, AwsEc2SgNoOpenAdminPortsCheck,
            AwsEc2SgUnrestrictedTrafficCheck, AwsEc2SgUnusedCheck, AwsEc2UnattachedElasticIpCheck,
            AwsVpcFlowLogsEnabledCheck,
        },
        iam::{
            AwsIamInactiveUsersCheck, AwsIamNoWildcardAdminPoliciesCheck, AwsIamOldAccessKeysCheck,
            AwsIamPasswordPolicyCheck, AwsIamRoleTrustPolicyCheck, AwsIamRootMfaAndKeysCheck,
            AwsIamUserMfaEnabledCheck,
        },
        lambda::{
            AwsLambdaExecutionRoleLeastPrivilegeCheck, AwsLambdaNoPublicUrlsCheck,
            AwsLambdaRuntimeAndEncryptionCheck, AwsLambdaVpcAttachmentPolicyCheck,
        },
        rds::{
            AwsRdsBackupAndDeletionProtectionCheck, AwsRdsEnhancedLoggingCheck,
            AwsRdsPublicAccessDisabledCheck, AwsRdsStorageEncryptedCheck,
        },
        s3::{
            AwsS3AccessLoggingCheck, AwsS3BucketPolicyPublicAccessCheck,
            AwsS3BucketVersioningCheck, AwsS3DefaultEncryptionCheck,
        },
    },
    check::{AwsS3BlockPublicAccessCheck, Check},
    registry::ProviderRegistry,
};

pub fn get_all_aws_checks() -> Vec<Arc<dyn Check>> {
    vec![
        // S3
        Arc::new(AwsS3BlockPublicAccessCheck),
        Arc::new(AwsS3BucketPolicyPublicAccessCheck),
        Arc::new(AwsS3DefaultEncryptionCheck),
        Arc::new(AwsS3AccessLoggingCheck),
        Arc::new(AwsS3BucketVersioningCheck),
        // IAM
        Arc::new(AwsIamRootMfaAndKeysCheck),
        Arc::new(AwsIamUserMfaEnabledCheck),
        Arc::new(AwsIamPasswordPolicyCheck),
        Arc::new(AwsIamOldAccessKeysCheck),
        Arc::new(AwsIamInactiveUsersCheck),
        Arc::new(AwsIamNoWildcardAdminPoliciesCheck),
        Arc::new(AwsIamRoleTrustPolicyCheck),
        // EC2 & VPC
        Arc::new(AwsEc2SgNoOpenAdminPortsCheck),
        Arc::new(AwsEc2SgUnrestrictedTrafficCheck),
        Arc::new(AwsEc2SgUnusedCheck),
        Arc::new(AwsEc2Imdsv2EnforcedCheck),
        Arc::new(AwsEc2EbsEncryptionEnabledCheck),
        Arc::new(AwsVpcFlowLogsEnabledCheck),
        Arc::new(AwsEc2DefaultSgRestrictsAllCheck),
        Arc::new(AwsEc2UnattachedElasticIpCheck),
        // RDS
        Arc::new(AwsRdsPublicAccessDisabledCheck),
        Arc::new(AwsRdsStorageEncryptedCheck),
        Arc::new(AwsRdsBackupAndDeletionProtectionCheck),
        Arc::new(AwsRdsEnhancedLoggingCheck),
        // CloudTrail
        Arc::new(AwsCloudTrailMultiRegionTrailCheck),
        Arc::new(AwsCloudTrailLogValidationAndEncryptionCheck),
        Arc::new(AwsCloudTrailCloudWatchLogsCheck),
        // Lambda
        Arc::new(AwsLambdaExecutionRoleLeastPrivilegeCheck),
        Arc::new(AwsLambdaNoPublicUrlsCheck),
        Arc::new(AwsLambdaVpcAttachmentPolicyCheck),
        Arc::new(AwsLambdaRuntimeAndEncryptionCheck),
    ]
}

pub fn register_all_aws_checks(registry: &mut ProviderRegistry) {
    for check in get_all_aws_checks() {
        registry.register_check(check);
    }
}
