use cloudsec_domain::{CloudProvider, Resource, Severity};
use serde_json::{Value, json};

use crate::check::{Check, CheckEvaluation};

/// Check: Cloud SQL Instances Do Not Have Public IP or Overly Permissive Authorized Networks
pub struct GcpSqlNoPublicIpAndAuthorizedNetworksCheck;

impl Check for GcpSqlNoPublicIpAndAuthorizedNetworksCheck {
    fn id(&self) -> &str {
        "gcp-sql-no-public-ip-and-authorized-networks"
    }

    fn provider(&self) -> CloudProvider {
        CloudProvider::Gcp
    }

    fn service(&self) -> &str {
        "sql"
    }

    fn category(&self) -> &str {
        "database_security"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn title(&self) -> &str {
        "Ensure Cloud SQL Instances Do Not Have Public IPs or Unrestricted Authorized Networks"
    }

    fn description(&self) -> &str {
        "Verify that Cloud SQL database instances use private IP addressing only and do not allow 0.0.0.0/0 in authorized networks."
    }

    fn remediation(&self) -> &str {
        "Disable public IPv4 address on the Cloud SQL instance, attach private IP via Private Service Access, and remove any 0.0.0.0/0 authorized networks."
    }

    fn base_severity(&self) -> Severity {
        Severity::High
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type != "gcp_sql_instance"
            && resource.resource_type != "sqladmin.googleapis.com/Instance"
        {
            return CheckEvaluation::NotApplicable;
        }

        let config = &resource.configuration;
        let ip_config = config
            .get("ip_configuration")
            .or_else(|| config.get("ipConfiguration"))
            .or_else(|| {
                config.get("settings").and_then(|s| {
                    s.get("ip_configuration")
                        .or_else(|| s.get("ipConfiguration"))
                })
            });

        let ipv4_enabled = ip_config
            .and_then(|ip| ip.get("ipv4_enabled").or_else(|| ip.get("ipv4Enabled")))
            .and_then(Value::as_bool)
            .unwrap_or(false);

        let mut open_authorized_networks = Vec::new();

        if let Some(auth_nets) = ip_config
            .and_then(|ip| {
                ip.get("authorized_networks")
                    .or_else(|| ip.get("authorizedNetworks"))
            })
            .and_then(Value::as_array)
        {
            for net in auth_nets {
                let value = net.get("value").and_then(Value::as_str).unwrap_or("");
                if value == "0.0.0.0/0" || value == "::/0" || value == "*" {
                    let name = net.get("name").and_then(Value::as_str).unwrap_or("unnamed");
                    open_authorized_networks.push(format!("{name} ({value})"));
                }
            }
        }

        if !ipv4_enabled && open_authorized_networks.is_empty() {
            CheckEvaluation::Passed
        } else {
            let severity = if !open_authorized_networks.is_empty() {
                Severity::Critical
            } else {
                Severity::High
            };

            CheckEvaluation::Failed {
                severity,
                evidence: json!({
                    "ipv4_enabled": ipv4_enabled,
                    "open_authorized_networks": open_authorized_networks,
                }),
                message: format!(
                    "Cloud SQL instance '{}' has public IPv4 enabled or allows 0.0.0.0/0 in authorized networks",
                    resource
                        .name
                        .as_deref()
                        .unwrap_or(&resource.provider_native_id)
                ),
            }
        }
    }
}

/// Check: Cloud SQL Encryption, Backups, Deletion Protection, and Database Flags
pub struct GcpSqlBackupCmekAndFlagsCheck;

impl Check for GcpSqlBackupCmekAndFlagsCheck {
    fn id(&self) -> &str {
        "gcp-sql-backup-cmek-and-flags"
    }

    fn provider(&self) -> CloudProvider {
        CloudProvider::Gcp
    }

    fn service(&self) -> &str {
        "sql"
    }

    fn category(&self) -> &str {
        "data_protection"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn title(&self) -> &str {
        "Ensure Cloud SQL Has CMEK Encryption, Automated Backups, Deletion Protection, and Secure Flags"
    }

    fn description(&self) -> &str {
        "Verify that Cloud SQL instances have Customer-Managed Encryption Keys (CMEK), automated backups, point-in-time recovery, and deletion protection enabled."
    }

    fn remediation(&self) -> &str {
        "Enable automated backups with point-in-time recovery, configure disk encryption with Cloud KMS (CMEK), and enable deletion protection."
    }

    fn base_severity(&self) -> Severity {
        Severity::High
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type != "gcp_sql_instance"
            && resource.resource_type != "sqladmin.googleapis.com/Instance"
        {
            return CheckEvaluation::NotApplicable;
        }

        let config = &resource.configuration;
        let settings = config.get("settings").unwrap_or(config);

        let backup_config = settings
            .get("backup_configuration")
            .or_else(|| settings.get("backupConfiguration"));

        let backups_enabled = backup_config
            .and_then(|b| b.get("enabled").and_then(Value::as_bool))
            .or_else(|| config.get("backups_enabled").and_then(Value::as_bool))
            .unwrap_or(false);

        let pitr_enabled = backup_config
            .and_then(|b| {
                b.get("point_in_time_recovery_enabled")
                    .or_else(|| b.get("pointInTimeRecoveryEnabled"))
                    .and_then(Value::as_bool)
            })
            .or_else(|| config.get("pitr_enabled").and_then(Value::as_bool))
            .unwrap_or(false);

        let deletion_protection = config
            .get("deletion_protection_enabled")
            .or_else(|| config.get("deletionProtectionEnabled"))
            .or_else(|| config.get("deletion_protection"))
            .and_then(Value::as_bool)
            .unwrap_or(false);

        let has_cmek = config
            .get("disk_encryption_configuration")
            .or_else(|| config.get("diskEncryptionConfiguration"))
            .and_then(|d| d.get("kms_key_name").or_else(|| d.get("kmsKeyName")))
            .and_then(Value::as_str)
            .map(|k| !k.trim().is_empty())
            .unwrap_or(false)
            || config
                .get("cmek_enabled")
                .and_then(Value::as_bool)
                .unwrap_or(false);

        if backups_enabled && pitr_enabled && deletion_protection && has_cmek {
            CheckEvaluation::Passed
        } else {
            CheckEvaluation::Failed {
                severity: self.base_severity(),
                evidence: json!({
                    "automated_backups_enabled": backups_enabled,
                    "point_in_time_recovery_enabled": pitr_enabled,
                    "deletion_protection_enabled": deletion_protection,
                    "cmek_encryption_enabled": has_cmek,
                }),
                message: format!(
                    "Cloud SQL instance '{}' lacks automated backups, PITR, deletion protection, or CMEK encryption",
                    resource
                        .name
                        .as_deref()
                        .unwrap_or(&resource.provider_native_id)
                ),
            }
        }
    }
}
