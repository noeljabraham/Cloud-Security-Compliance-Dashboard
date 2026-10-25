use cloudsec_domain::{DiscoveredResource, Id, Resource};
use serde_json::json;

pub struct AwsTestFixtures;

impl AwsTestFixtures {
    pub fn compliant_s3_bucket(org_id: Id, account_id: Id, name: &str) -> Resource {
        let disc = DiscoveredResource {
            provider_native_id: name.to_string(),
            resource_type: "aws_s3_bucket".to_string(),
            name: Some(name.to_string()),
            region: Some("us-east-1".to_string()),
            tags: json!({"environment": "production"}),
            configuration: json!({
                "block_public_acls": true,
                "ignore_public_acls": true,
                "block_public_policy": true,
                "restrict_public_buckets": true,
                "policy_allows_public": false,
                "public_acl_grants": false,
                "encryption_enabled": true,
                "sse_algorithm": "aws:kms",
                "logging_enabled": true,
                "versioning_status": "Enabled"
            }),
        };
        disc.into_resource(org_id, account_id)
    }

    pub fn non_compliant_s3_bucket(org_id: Id, account_id: Id, name: &str) -> Resource {
        let disc = DiscoveredResource {
            provider_native_id: name.to_string(),
            resource_type: "aws_s3_bucket".to_string(),
            name: Some(name.to_string()),
            region: Some("us-east-1".to_string()),
            tags: json!({}),
            configuration: json!({
                "block_public_acls": false,
                "ignore_public_acls": false,
                "block_public_policy": false,
                "restrict_public_buckets": false,
                "policy_allows_public": true,
                "public_acl_grants": true,
                "encryption_enabled": false,
                "sse_algorithm": "none",
                "logging_enabled": false,
                "versioning_status": "Disabled"
            }),
        };
        disc.into_resource(org_id, account_id)
    }

    pub fn compliant_iam_summary(org_id: Id, account_id: Id) -> Resource {
        let disc = DiscoveredResource {
            provider_native_id: "iam-account-summary".to_string(),
            resource_type: "aws_iam_account_summary".to_string(),
            name: Some("IAM Account Summary".to_string()),
            region: Some("us-east-1".to_string()),
            tags: json!({}),
            configuration: json!({
                "account_mfa_enabled": true,
                "account_access_keys_present": 0
            }),
        };
        disc.into_resource(org_id, account_id)
    }

    pub fn non_compliant_iam_summary(org_id: Id, account_id: Id) -> Resource {
        let disc = DiscoveredResource {
            provider_native_id: "iam-account-summary".to_string(),
            resource_type: "aws_iam_account_summary".to_string(),
            name: Some("IAM Account Summary".to_string()),
            region: Some("us-east-1".to_string()),
            tags: json!({}),
            configuration: json!({
                "account_mfa_enabled": false,
                "account_access_keys_present": 1
            }),
        };
        disc.into_resource(org_id, account_id)
    }

    pub fn compliant_security_group(org_id: Id, account_id: Id, name: &str) -> Resource {
        let disc = DiscoveredResource {
            provider_native_id: name.to_string(),
            resource_type: "aws_security_group".to_string(),
            name: Some(name.to_string()),
            region: Some("us-east-1".to_string()),
            tags: json!({}),
            configuration: json!({
                "group_name": name,
                "attached_eni_count": 2,
                "ingress_rules": [
                    { "cidr": "10.0.0.0/16", "from_port": 22, "to_port": 22, "protocol": "tcp" },
                    { "cidr": "0.0.0.0/0", "from_port": 443, "to_port": 443, "protocol": "tcp" }
                ],
                "egress_rules": [
                    { "cidr": "0.0.0.0/0", "from_port": 0, "to_port": 65535, "protocol": "tcp" }
                ]
            }),
        };
        disc.into_resource(org_id, account_id)
    }

    pub fn open_admin_security_group(org_id: Id, account_id: Id, name: &str) -> Resource {
        let disc = DiscoveredResource {
            provider_native_id: name.to_string(),
            resource_type: "aws_security_group".to_string(),
            name: Some(name.to_string()),
            region: Some("us-east-1".to_string()),
            tags: json!({}),
            configuration: json!({
                "group_name": name,
                "attached_eni_count": 1,
                "ingress_rules": [
                    { "cidr": "0.0.0.0/0", "from_port": 22, "to_port": 22, "protocol": "tcp" },
                    { "cidr": "0.0.0.0/0", "from_port": 3389, "to_port": 3389, "protocol": "tcp" }
                ],
                "egress_rules": []
            }),
        };
        disc.into_resource(org_id, account_id)
    }

    pub fn compliant_rds_instance(org_id: Id, account_id: Id, name: &str) -> Resource {
        let disc = DiscoveredResource {
            provider_native_id: name.to_string(),
            resource_type: "aws_rds_instance".to_string(),
            name: Some(name.to_string()),
            region: Some("us-east-1".to_string()),
            tags: json!({}),
            configuration: json!({
                "publicly_accessible": false,
                "storage_encrypted": true,
                "backup_retention_period": 14,
                "deletion_protection": true,
                "enabled_cloudwatch_logs_exports": ["error", "slowquery", "audit"]
            }),
        };
        disc.into_resource(org_id, account_id)
    }

    pub fn non_compliant_rds_instance(org_id: Id, account_id: Id, name: &str) -> Resource {
        let disc = DiscoveredResource {
            provider_native_id: name.to_string(),
            resource_type: "aws_rds_instance".to_string(),
            name: Some(name.to_string()),
            region: Some("us-east-1".to_string()),
            tags: json!({}),
            configuration: json!({
                "publicly_accessible": true,
                "storage_encrypted": false,
                "backup_retention_period": 1,
                "deletion_protection": false,
                "enabled_cloudwatch_logs_exports": []
            }),
        };
        disc.into_resource(org_id, account_id)
    }

    pub fn compliant_cloudtrail(org_id: Id, account_id: Id, name: &str) -> Resource {
        let disc = DiscoveredResource {
            provider_native_id: name.to_string(),
            resource_type: "aws_cloudtrail_trail".to_string(),
            name: Some(name.to_string()),
            region: Some("us-east-1".to_string()),
            tags: json!({}),
            configuration: json!({
                "is_multi_region_trail": true,
                "is_logging": true,
                "include_global_service_events": true,
                "log_file_validation_enabled": true,
                "kms_key_id": "arn:aws:kms:us-east-1:123456789012:key/test-trail-key",
                "cloud_watch_logs_log_group_arn": "arn:aws:logs:us-east-1:123456789012:log-group:aws-cloudtrail:*"
            }),
        };
        disc.into_resource(org_id, account_id)
    }

    pub fn compliant_lambda_function(org_id: Id, account_id: Id, name: &str) -> Resource {
        let disc = DiscoveredResource {
            provider_native_id: name.to_string(),
            resource_type: "aws_lambda_function".to_string(),
            name: Some(name.to_string()),
            region: Some("us-east-1".to_string()),
            tags: json!({}),
            configuration: json!({
                "role_has_wildcard_admin": false,
                "has_function_url": true,
                "url_auth_type": "AWS_IAM",
                "requires_vpc": false,
                "in_vpc": false,
                "runtime": "python3.12",
                "has_environment_variables": true,
                "kms_key_arn": "arn:aws:kms:us-east-1:123456789012:key/lambda-env-key"
            }),
        };
        disc.into_resource(org_id, account_id)
    }

    pub fn malformed_resource(org_id: Id, account_id: Id) -> Resource {
        let disc = DiscoveredResource {
            provider_native_id: "malformed-empty".to_string(),
            resource_type: "aws_s3_bucket".to_string(),
            name: None,
            region: None,
            tags: json!(null),
            configuration: json!({}),
        };
        disc.into_resource(org_id, account_id)
    }
}
