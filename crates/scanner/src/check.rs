use cloudsec_domain::{CheckMetadata, CloudProvider, CoverageGapReason, Resource, Severity};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CheckEvaluation {
    Passed,
    Failed {
        severity: Severity,
        evidence: Value,
        message: String,
    },
    CoverageGap {
        reason: CoverageGapReason,
        details: String,
    },
    NotApplicable,
}

pub trait Check: Send + Sync {
    fn id(&self) -> &str;
    fn provider(&self) -> CloudProvider;
    fn service(&self) -> &str;
    fn category(&self) -> &str;
    fn version(&self) -> &str;
    fn title(&self) -> &str;
    fn description(&self) -> &str;
    fn remediation(&self) -> &str;
    fn base_severity(&self) -> Severity;

    fn metadata(&self) -> CheckMetadata {
        CheckMetadata {
            id: self.id().to_string(),
            provider: self.provider(),
            service: self.service().to_string(),
            category: self.category().to_string(),
            version: self.version().to_string(),
            title: self.title().to_string(),
            description: self.description().to_string(),
            remediation: self.remediation().to_string(),
            severity: self.base_severity(),
            enabled: true,
        }
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation;
}

/// CIS AWS 7.1.0 Check: S3 Block Public Access is enabled
pub struct AwsS3BlockPublicAccessCheck;

impl Check for AwsS3BlockPublicAccessCheck {
    fn id(&self) -> &str {
        "aws-s3-block-public-access"
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
        "Ensure S3 Bucket Block Public Access is fully enabled"
    }

    fn description(&self) -> &str {
        "Amazon S3 Block Public Access provides four settings to help you manage public access. All four settings (block_public_acls, ignore_public_acls, block_public_policy, restrict_public_buckets) must be set to true."
    }

    fn remediation(&self) -> &str {
        "aws s3api put-public-access-block --bucket <bucket-name> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
    }

    fn base_severity(&self) -> Severity {
        Severity::High
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type != "aws_s3_bucket" {
            return CheckEvaluation::NotApplicable;
        }

        let config = &resource.configuration;
        let block_public_acls = config
            .get("block_public_acls")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let ignore_public_acls = config
            .get("ignore_public_acls")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let block_public_policy = config
            .get("block_public_policy")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let restrict_public_buckets = config
            .get("restrict_public_buckets")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        if block_public_acls && ignore_public_acls && block_public_policy && restrict_public_buckets
        {
            CheckEvaluation::Passed
        } else {
            let evidence = json!({
                "block_public_acls": block_public_acls,
                "ignore_public_acls": ignore_public_acls,
                "block_public_policy": block_public_policy,
                "restrict_public_buckets": restrict_public_buckets,
            });

            CheckEvaluation::Failed {
                severity: self.base_severity(),
                evidence,
                message: format!(
                    "Bucket '{}' does not have all S3 Block Public Access controls enabled",
                    resource
                        .name
                        .as_deref()
                        .unwrap_or(&resource.provider_native_id)
                ),
            }
        }
    }
}
