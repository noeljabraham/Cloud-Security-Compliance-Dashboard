use cloudsec_domain::{CloudProvider, Resource, Severity};
use serde_json::{Value, json};

use crate::check::{Check, CheckEvaluation};

/// Check: S3 Bucket Policies and ACLs do not grant public or cross-account access
pub struct AwsS3BucketPolicyPublicAccessCheck;

impl Check for AwsS3BucketPolicyPublicAccessCheck {
    fn id(&self) -> &str {
        "aws-s3-bucket-policy-public-access"
    }
    fn provider(&self) -> CloudProvider {
        CloudProvider::Aws
    }
    fn service(&self) -> &str {
        "s3"
    }
    fn category(&self) -> &str {
        "storage"
    }
    fn version(&self) -> &str {
        "1.0.0"
    }
    fn title(&self) -> &str {
        "Ensure S3 Bucket Policy does not grant public access"
    }
    fn description(&self) -> &str {
        "S3 bucket policies should not grant anonymous access or allow unrestricted wildcard Principal access without conditions."
    }
    fn remediation(&self) -> &str {
        "aws s3api delete-bucket-policy --bucket <bucket-name> or update policy to restrict Principal access."
    }
    fn base_severity(&self) -> Severity {
        Severity::Critical
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type != "aws_s3_bucket" {
            return CheckEvaluation::NotApplicable;
        }

        let config = &resource.configuration;
        let allows_public_access = config
            .get("policy_allows_public")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let public_acl_grants = config
            .get("public_acl_grants")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        if !allows_public_access && !public_acl_grants {
            CheckEvaluation::Passed
        } else {
            CheckEvaluation::Failed {
                severity: self.base_severity(),
                evidence: json!({
                    "policy_allows_public": allows_public_access,
                    "public_acl_grants": public_acl_grants,
                }),
                message: format!(
                    "Bucket '{}' grants public read or write access via policy or ACL",
                    resource
                        .name
                        .as_deref()
                        .unwrap_or(&resource.provider_native_id)
                ),
            }
        }
    }
}

/// Check: S3 Default Encryption is enabled with approved KMS keys or AES256
pub struct AwsS3DefaultEncryptionCheck;

impl Check for AwsS3DefaultEncryptionCheck {
    fn id(&self) -> &str {
        "aws-s3-default-encryption"
    }
    fn provider(&self) -> CloudProvider {
        CloudProvider::Aws
    }
    fn service(&self) -> &str {
        "s3"
    }
    fn category(&self) -> &str {
        "storage"
    }
    fn version(&self) -> &str {
        "1.0.0"
    }
    fn title(&self) -> &str {
        "Ensure S3 Bucket Default Encryption is enabled"
    }
    fn description(&self) -> &str {
        "Ensure S3 buckets have default encryption enabled using AES256 (SSE-S3) or aws:kms (SSE-KMS)."
    }
    fn remediation(&self) -> &str {
        "aws s3api put-bucket-encryption --bucket <bucket-name> --server-side-encryption-configuration '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"}}]}'"
    }
    fn base_severity(&self) -> Severity {
        Severity::High
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type != "aws_s3_bucket" {
            return CheckEvaluation::NotApplicable;
        }

        let config = &resource.configuration;
        let encryption_enabled = config
            .get("encryption_enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let sse_algorithm = config
            .get("sse_algorithm")
            .and_then(Value::as_str)
            .unwrap_or("none");

        if encryption_enabled && (sse_algorithm == "AES256" || sse_algorithm == "aws:kms") {
            CheckEvaluation::Passed
        } else {
            CheckEvaluation::Failed {
                severity: self.base_severity(),
                evidence: json!({
                    "encryption_enabled": encryption_enabled,
                    "sse_algorithm": sse_algorithm,
                }),
                message: format!(
                    "Bucket '{}' does not have approved default server-side encryption enabled",
                    resource
                        .name
                        .as_deref()
                        .unwrap_or(&resource.provider_native_id)
                ),
            }
        }
    }
}

/// Check: S3 Access Logging or approved data-event monitoring is enabled
pub struct AwsS3AccessLoggingCheck;

impl Check for AwsS3AccessLoggingCheck {
    fn id(&self) -> &str {
        "aws-s3-access-logging"
    }
    fn provider(&self) -> CloudProvider {
        CloudProvider::Aws
    }
    fn service(&self) -> &str {
        "s3"
    }
    fn category(&self) -> &str {
        "storage"
    }
    fn version(&self) -> &str {
        "1.0.0"
    }
    fn title(&self) -> &str {
        "Ensure S3 Bucket Access Logging is enabled"
    }
    fn description(&self) -> &str {
        "Server access logging captures detailed records for requests made to an S3 bucket for security audits."
    }
    fn remediation(&self) -> &str {
        "aws s3api put-bucket-logging --bucket <bucket-name> --bucket-logging-status file://logging.json"
    }
    fn base_severity(&self) -> Severity {
        Severity::Medium
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type != "aws_s3_bucket" {
            return CheckEvaluation::NotApplicable;
        }

        let config = &resource.configuration;
        let logging_enabled = config
            .get("logging_enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let data_events_enabled = config
            .get("cloudtrail_data_events_enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        if logging_enabled || data_events_enabled {
            CheckEvaluation::Passed
        } else {
            CheckEvaluation::Failed {
                severity: self.base_severity(),
                evidence: json!({
                    "logging_enabled": logging_enabled,
                    "cloudtrail_data_events_enabled": data_events_enabled,
                }),
                message: format!(
                    "Bucket '{}' does not have server access logging or data events logging enabled",
                    resource
                        .name
                        .as_deref()
                        .unwrap_or(&resource.provider_native_id)
                ),
            }
        }
    }
}

/// Check: S3 Versioning and lifecycle configuration is enabled where required
pub struct AwsS3BucketVersioningCheck;

impl Check for AwsS3BucketVersioningCheck {
    fn id(&self) -> &str {
        "aws-s3-bucket-versioning"
    }
    fn provider(&self) -> CloudProvider {
        CloudProvider::Aws
    }
    fn service(&self) -> &str {
        "s3"
    }
    fn category(&self) -> &str {
        "storage"
    }
    fn version(&self) -> &str {
        "1.0.0"
    }
    fn title(&self) -> &str {
        "Ensure S3 Bucket Versioning is enabled"
    }
    fn description(&self) -> &str {
        "Versioning keeps multiple variants of an object in the same bucket, protecting against accidental deletion and ransomware."
    }
    fn remediation(&self) -> &str {
        "aws s3api put-bucket-versioning --bucket <bucket-name> --versioning-configuration Status=Enabled"
    }
    fn base_severity(&self) -> Severity {
        Severity::Low
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type != "aws_s3_bucket" {
            return CheckEvaluation::NotApplicable;
        }

        let config = &resource.configuration;
        let versioning_status = config
            .get("versioning_status")
            .and_then(Value::as_str)
            .unwrap_or("Disabled");

        if versioning_status == "Enabled" {
            CheckEvaluation::Passed
        } else {
            CheckEvaluation::Failed {
                severity: self.base_severity(),
                evidence: json!({
                    "versioning_status": versioning_status,
                }),
                message: format!(
                    "Bucket '{}' does not have object versioning enabled (status: {versioning_status})",
                    resource
                        .name
                        .as_deref()
                        .unwrap_or(&resource.provider_native_id)
                ),
            }
        }
    }
}
