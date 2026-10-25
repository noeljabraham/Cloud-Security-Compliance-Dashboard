use cloudsec_domain::{CloudProvider, Resource, Severity};
use serde_json::{Value, json};

use crate::check::{Check, CheckEvaluation};

/// Check: CloudTrail multi-region trail is enabled and logging management events
pub struct AwsCloudTrailMultiRegionTrailCheck;

impl Check for AwsCloudTrailMultiRegionTrailCheck {
    fn id(&self) -> &str {
        "aws-cloudtrail-multi-region-trail"
    }
    fn provider(&self) -> CloudProvider {
        CloudProvider::Aws
    }
    fn service(&self) -> &str {
        "cloudtrail"
    }
    fn category(&self) -> &str {
        "logging"
    }
    fn version(&self) -> &str {
        "1.0.0"
    }
    fn title(&self) -> &str {
        "Ensure CloudTrail is enabled across all regions"
    }
    fn description(&self) -> &str {
        "A multi-region trail ensures that all management events across all AWS regions are recorded for auditing and security analysis."
    }
    fn remediation(&self) -> &str {
        "aws cloudtrail update-trail --name <trail-name> --is-multi-region-trail --include-global-service-events"
    }
    fn base_severity(&self) -> Severity {
        Severity::High
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type != "aws_cloudtrail_trail" {
            return CheckEvaluation::NotApplicable;
        }

        let config = &resource.configuration;
        let is_multi_region = config
            .get("is_multi_region_trail")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let is_logging = config
            .get("is_logging")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let include_global_services = config
            .get("include_global_service_events")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        if is_multi_region && is_logging && include_global_services {
            CheckEvaluation::Passed
        } else {
            CheckEvaluation::Failed {
                severity: self.base_severity(),
                evidence: json!({
                    "is_multi_region_trail": is_multi_region,
                    "is_logging": is_logging,
                    "include_global_service_events": include_global_services,
                }),
                message: format!(
                    "CloudTrail trail '{}' is not a fully configured multi-region logging trail",
                    resource
                        .name
                        .as_deref()
                        .unwrap_or(&resource.provider_native_id)
                ),
            }
        }
    }
}

/// Check: CloudTrail log file validation and KMS encryption are enabled
pub struct AwsCloudTrailLogValidationAndEncryptionCheck;

impl Check for AwsCloudTrailLogValidationAndEncryptionCheck {
    fn id(&self) -> &str {
        "aws-cloudtrail-log-validation-and-encryption"
    }
    fn provider(&self) -> CloudProvider {
        CloudProvider::Aws
    }
    fn service(&self) -> &str {
        "cloudtrail"
    }
    fn category(&self) -> &str {
        "logging"
    }
    fn version(&self) -> &str {
        "1.0.0"
    }
    fn title(&self) -> &str {
        "Ensure CloudTrail log file validation and KMS encryption are enabled"
    }
    fn description(&self) -> &str {
        "Log file validation verifies that logs have not been modified or deleted. KMS encryption ensures confidentiality."
    }
    fn remediation(&self) -> &str {
        "aws cloudtrail update-trail --name <name> --enable-log-file-validation --kms-key-id <kms-key-arn>"
    }
    fn base_severity(&self) -> Severity {
        Severity::Medium
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type != "aws_cloudtrail_trail" {
            return CheckEvaluation::NotApplicable;
        }

        let config = &resource.configuration;
        let log_file_validation_enabled = config
            .get("log_file_validation_enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let kms_key_id = config
            .get("kms_key_id")
            .and_then(Value::as_str)
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);

        if log_file_validation_enabled && kms_key_id {
            CheckEvaluation::Passed
        } else {
            CheckEvaluation::Failed {
                severity: self.base_severity(),
                evidence: json!({
                    "log_file_validation_enabled": log_file_validation_enabled,
                    "kms_key_encryption": kms_key_id,
                }),
                message: format!(
                    "CloudTrail trail '{}' lacks log file validation or KMS customer-managed encryption",
                    resource
                        .name
                        .as_deref()
                        .unwrap_or(&resource.provider_native_id)
                ),
            }
        }
    }
}

/// Check: CloudTrail trails integrate with CloudWatch Logs
pub struct AwsCloudTrailCloudWatchLogsCheck;

impl Check for AwsCloudTrailCloudWatchLogsCheck {
    fn id(&self) -> &str {
        "aws-cloudtrail-cloudwatch-logs"
    }
    fn provider(&self) -> CloudProvider {
        CloudProvider::Aws
    }
    fn service(&self) -> &str {
        "cloudtrail"
    }
    fn category(&self) -> &str {
        "logging"
    }
    fn version(&self) -> &str {
        "1.0.0"
    }
    fn title(&self) -> &str {
        "Ensure CloudTrail trails integrate with CloudWatch Logs"
    }
    fn description(&self) -> &str {
        "Integration with CloudWatch Logs allows real-time alerting on unauthorized API calls and privilege escalation."
    }
    fn remediation(&self) -> &str {
        "aws cloudtrail update-trail --name <name> --cloud-watch-logs-log-group-arn <arn> --cloud-watch-logs-role-arn <role-arn>"
    }
    fn base_severity(&self) -> Severity {
        Severity::Medium
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type != "aws_cloudtrail_trail" {
            return CheckEvaluation::NotApplicable;
        }

        let config = &resource.configuration;
        let cloudwatch_logs_enabled = config
            .get("cloud_watch_logs_log_group_arn")
            .and_then(Value::as_str)
            .map(|arn| !arn.trim().is_empty())
            .unwrap_or(false);

        if cloudwatch_logs_enabled {
            CheckEvaluation::Passed
        } else {
            CheckEvaluation::Failed {
                severity: self.base_severity(),
                evidence: json!({
                    "cloud_watch_logs_enabled": false,
                }),
                message: format!(
                    "CloudTrail trail '{}' is not integrated with CloudWatch Logs",
                    resource
                        .name
                        .as_deref()
                        .unwrap_or(&resource.provider_native_id)
                ),
            }
        }
    }
}
