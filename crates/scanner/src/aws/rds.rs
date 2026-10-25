use cloudsec_domain::{CloudProvider, Resource, Severity};
use serde_json::{Value, json};

use crate::check::{Check, CheckEvaluation};

/// Check: RDS instances are not publicly accessible
pub struct AwsRdsPublicAccessDisabledCheck;

impl Check for AwsRdsPublicAccessDisabledCheck {
    fn id(&self) -> &str {
        "aws-rds-public-access-disabled"
    }
    fn provider(&self) -> CloudProvider {
        CloudProvider::Aws
    }
    fn service(&self) -> &str {
        "rds"
    }
    fn category(&self) -> &str {
        "database"
    }
    fn version(&self) -> &str {
        "1.0.0"
    }
    fn title(&self) -> &str {
        "Ensure RDS database instances are not publicly accessible"
    }
    fn description(&self) -> &str {
        "RDS database instances should not have public IP addresses or direct internet accessibility."
    }
    fn remediation(&self) -> &str {
        "aws rds modify-db-instance --db-instance-identifier <id> --no-publicly-accessible"
    }
    fn base_severity(&self) -> Severity {
        Severity::Critical
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type != "aws_rds_instance" {
            return CheckEvaluation::NotApplicable;
        }

        let config = &resource.configuration;
        let publicly_accessible = config
            .get("publicly_accessible")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        if !publicly_accessible {
            CheckEvaluation::Passed
        } else {
            CheckEvaluation::Failed {
                severity: self.base_severity(),
                evidence: json!({
                    "publicly_accessible": true,
                }),
                message: format!(
                    "RDS DB Instance '{}' is publicly accessible from the internet",
                    resource
                        .name
                        .as_deref()
                        .unwrap_or(&resource.provider_native_id)
                ),
            }
        }
    }
}

/// Check: RDS storage encryption is enabled with KMS
pub struct AwsRdsStorageEncryptedCheck;

impl Check for AwsRdsStorageEncryptedCheck {
    fn id(&self) -> &str {
        "aws-rds-storage-encrypted"
    }
    fn provider(&self) -> CloudProvider {
        CloudProvider::Aws
    }
    fn service(&self) -> &str {
        "rds"
    }
    fn category(&self) -> &str {
        "database"
    }
    fn version(&self) -> &str {
        "1.0.0"
    }
    fn title(&self) -> &str {
        "Ensure RDS storage is encrypted at rest"
    }
    fn description(&self) -> &str {
        "RDS database storage must be encrypted at rest using AWS KMS."
    }
    fn remediation(&self) -> &str {
        "Create an encrypted snapshot and restore it to a new encrypted RDS DB instance."
    }
    fn base_severity(&self) -> Severity {
        Severity::High
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type != "aws_rds_instance" {
            return CheckEvaluation::NotApplicable;
        }

        let config = &resource.configuration;
        let storage_encrypted = config
            .get("storage_encrypted")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        if storage_encrypted {
            CheckEvaluation::Passed
        } else {
            CheckEvaluation::Failed {
                severity: self.base_severity(),
                evidence: json!({
                    "storage_encrypted": false,
                }),
                message: format!(
                    "RDS DB Instance '{}' does not have storage encryption enabled at rest",
                    resource
                        .name
                        .as_deref()
                        .unwrap_or(&resource.provider_native_id)
                ),
            }
        }
    }
}

/// Check: RDS automated backup retention (>= 7 days) and deletion protection
pub struct AwsRdsBackupAndDeletionProtectionCheck;

impl Check for AwsRdsBackupAndDeletionProtectionCheck {
    fn id(&self) -> &str {
        "aws-rds-backup-and-deletion-protection"
    }
    fn provider(&self) -> CloudProvider {
        CloudProvider::Aws
    }
    fn service(&self) -> &str {
        "rds"
    }
    fn category(&self) -> &str {
        "database"
    }
    fn version(&self) -> &str {
        "1.0.0"
    }
    fn title(&self) -> &str {
        "Ensure RDS automated backup retention and deletion protection are enabled"
    }
    fn description(&self) -> &str {
        "Automated backup retention should be at least 7 days and deletion protection enabled to prevent accidental loss."
    }
    fn remediation(&self) -> &str {
        "aws rds modify-db-instance --db-instance-identifier <id> --backup-retention-period 7 --deletion-protection"
    }
    fn base_severity(&self) -> Severity {
        Severity::Medium
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type != "aws_rds_instance" {
            return CheckEvaluation::NotApplicable;
        }

        let config = &resource.configuration;
        let backup_retention_days = config
            .get("backup_retention_period")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let deletion_protection = config
            .get("deletion_protection")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        if backup_retention_days >= 7 && deletion_protection {
            CheckEvaluation::Passed
        } else {
            CheckEvaluation::Failed {
                severity: self.base_severity(),
                evidence: json!({
                    "backup_retention_period": backup_retention_days,
                    "deletion_protection": deletion_protection,
                }),
                message: format!(
                    "RDS DB Instance '{}' does not meet resilience standards (backup days: {backup_retention_days}, deletion protection: {deletion_protection})",
                    resource
                        .name
                        .as_deref()
                        .unwrap_or(&resource.provider_native_id)
                ),
            }
        }
    }
}

/// Check: RDS enhanced logging is exported to CloudWatch Logs
pub struct AwsRdsEnhancedLoggingCheck;

impl Check for AwsRdsEnhancedLoggingCheck {
    fn id(&self) -> &str {
        "aws-rds-enhanced-logging"
    }
    fn provider(&self) -> CloudProvider {
        CloudProvider::Aws
    }
    fn service(&self) -> &str {
        "rds"
    }
    fn category(&self) -> &str {
        "database"
    }
    fn version(&self) -> &str {
        "1.0.0"
    }
    fn title(&self) -> &str {
        "Ensure RDS database logs are exported to CloudWatch Logs"
    }
    fn description(&self) -> &str {
        "Database audit, error, and slow query logs should be exported to CloudWatch Logs for continuous monitoring."
    }
    fn remediation(&self) -> &str {
        "aws rds modify-db-instance --db-instance-identifier <id> --cloudwatch-logs-export-configuration '{\"EnableLogTypes\":[\"audit\",\"error\"]}'"
    }
    fn base_severity(&self) -> Severity {
        Severity::Low
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type != "aws_rds_instance" {
            return CheckEvaluation::NotApplicable;
        }

        let config = &resource.configuration;
        let enabled_log_exports = config
            .get("enabled_cloudwatch_logs_exports")
            .and_then(Value::as_array)
            .map(|a| !a.is_empty())
            .unwrap_or(false);

        if enabled_log_exports {
            CheckEvaluation::Passed
        } else {
            CheckEvaluation::Failed {
                severity: self.base_severity(),
                evidence: json!({
                    "enabled_cloudwatch_logs_exports": [],
                }),
                message: format!(
                    "RDS DB Instance '{}' has no database log exports enabled to CloudWatch",
                    resource
                        .name
                        .as_deref()
                        .unwrap_or(&resource.provider_native_id)
                ),
            }
        }
    }
}
