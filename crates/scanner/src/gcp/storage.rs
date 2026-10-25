use cloudsec_domain::{CloudProvider, Resource, Severity};
use serde_json::{Value, json};

use crate::check::{Check, CheckEvaluation};

/// Check: Cloud Storage Buckets Do Not Have Public IAM Bindings
pub struct GcpStorageNoPublicIamBindingsCheck;

impl Check for GcpStorageNoPublicIamBindingsCheck {
    fn id(&self) -> &str {
        "gcp-storage-no-public-iam-bindings"
    }

    fn provider(&self) -> CloudProvider {
        CloudProvider::Gcp
    }

    fn service(&self) -> &str {
        "storage"
    }

    fn category(&self) -> &str {
        "storage_security"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn title(&self) -> &str {
        "Ensure Cloud Storage Buckets Do Not Have Public IAM Bindings (allUsers/allAuthenticatedUsers)"
    }

    fn description(&self) -> &str {
        "Verify that Cloud Storage bucket IAM policies do not grant permissions to 'allUsers' or 'allAuthenticatedUsers'."
    }

    fn remediation(&self) -> &str {
        "Remove IAM bindings granting roles to 'allUsers' or 'allAuthenticatedUsers' on the Cloud Storage bucket."
    }

    fn base_severity(&self) -> Severity {
        Severity::Critical
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type != "gcp_storage_bucket"
            && resource.resource_type != "storage.googleapis.com/Bucket"
        {
            return CheckEvaluation::NotApplicable;
        }

        let config = &resource.configuration;

        let iam_bindings = config
            .get("iam_policy")
            .or_else(|| config.get("iam_bindings"))
            .or_else(|| config.get("bindings"))
            .and_then(Value::as_array);

        let mut public_bindings = Vec::new();

        if let Some(bindings) = iam_bindings {
            for binding in bindings {
                let role = binding.get("role").and_then(Value::as_str).unwrap_or("");
                let members = binding.get("members").and_then(Value::as_array);

                if let Some(mem_arr) = members {
                    for member in mem_arr.iter().filter_map(Value::as_str) {
                        if member.eq_ignore_ascii_case("allUsers")
                            || member.eq_ignore_ascii_case("allAuthenticatedUsers")
                        {
                            public_bindings.push(json!({
                                "role": role,
                                "member": member,
                            }));
                        }
                    }
                }
            }
        }

        // Also check boolean flag if simplified payload
        let has_public_access = config
            .get("has_public_iam_bindings")
            .or_else(|| config.get("public_access"))
            .and_then(Value::as_bool)
            .unwrap_or(false);

        if public_bindings.is_empty() && !has_public_access {
            CheckEvaluation::Passed
        } else {
            CheckEvaluation::Failed {
                severity: self.base_severity(),
                evidence: json!({
                    "public_bindings": public_bindings,
                    "has_public_access_flag": has_public_access,
                }),
                message: format!(
                    "Cloud Storage bucket '{}' has public IAM bindings granting access to allUsers or allAuthenticatedUsers",
                    resource
                        .name
                        .as_deref()
                        .unwrap_or(&resource.provider_native_id)
                ),
            }
        }
    }
}

/// Check: Cloud Storage Uniform Bucket-Level Access and Public Access Prevention Enabled
pub struct GcpStorageUniformAccessAndPapCheck;

impl Check for GcpStorageUniformAccessAndPapCheck {
    fn id(&self) -> &str {
        "gcp-storage-uniform-access-and-pap"
    }

    fn provider(&self) -> CloudProvider {
        CloudProvider::Gcp
    }

    fn service(&self) -> &str {
        "storage"
    }

    fn category(&self) -> &str {
        "access_control"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn title(&self) -> &str {
        "Ensure Uniform Bucket-Level Access and Public Access Prevention are Enforced"
    }

    fn description(&self) -> &str {
        "Verify that Cloud Storage buckets have Uniform Bucket-Level Access enabled and Public Access Prevention set to 'enforced'."
    }

    fn remediation(&self) -> &str {
        "gcloud storage buckets update gs://BUCKET_NAME --uniform-bucket-level-access --public-access-prevention=enforced"
    }

    fn base_severity(&self) -> Severity {
        Severity::High
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type != "gcp_storage_bucket"
            && resource.resource_type != "storage.googleapis.com/Bucket"
        {
            return CheckEvaluation::NotApplicable;
        }

        let config = &resource.configuration;

        let ubla_enabled = config
            .get("uniform_bucket_level_access")
            .or_else(|| config.get("uniformBucketLevelAccess"))
            .and_then(|u| u.get("enabled").and_then(Value::as_bool))
            .or_else(|| config.get("ubla_enabled").and_then(Value::as_bool))
            .unwrap_or(false);

        let pap = config
            .get("public_access_prevention")
            .or_else(|| config.get("publicAccessPrevention"))
            .and_then(Value::as_str)
            .unwrap_or("inherited");

        let pap_enforced = pap.eq_ignore_ascii_case("enforced");

        if ubla_enabled && pap_enforced {
            CheckEvaluation::Passed
        } else {
            CheckEvaluation::Failed {
                severity: self.base_severity(),
                evidence: json!({
                    "uniform_bucket_level_access_enabled": ubla_enabled,
                    "public_access_prevention": pap,
                }),
                message: format!(
                    "Cloud Storage bucket '{}' does not enforce Uniform Bucket-Level Access or Public Access Prevention",
                    resource
                        .name
                        .as_deref()
                        .unwrap_or(&resource.provider_native_id)
                ),
            }
        }
    }
}

/// Check: Cloud Storage Encryption, Logging, Versioning, and Retention
pub struct GcpStorageEncryptionLoggingRetentionCheck;

impl Check for GcpStorageEncryptionLoggingRetentionCheck {
    fn id(&self) -> &str {
        "gcp-storage-encryption-logging-retention"
    }

    fn provider(&self) -> CloudProvider {
        CloudProvider::Gcp
    }

    fn service(&self) -> &str {
        "storage"
    }

    fn category(&self) -> &str {
        "data_protection"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn title(&self) -> &str {
        "Ensure Cloud Storage Uses Customer-Managed Encryption Keys (CMEK), Logging, Versioning, and Retention"
    }

    fn description(&self) -> &str {
        "Verify that Cloud Storage buckets use Customer-Managed Encryption Keys (CMEK), diagnostic access logging, object versioning, and retention policies."
    }

    fn remediation(&self) -> &str {
        "Configure default KMS key (CMEK), enable usage/access logging to a dedicated bucket, enable object versioning, and define a retention policy."
    }

    fn base_severity(&self) -> Severity {
        Severity::Medium
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type != "gcp_storage_bucket"
            && resource.resource_type != "storage.googleapis.com/Bucket"
        {
            return CheckEvaluation::NotApplicable;
        }

        let config = &resource.configuration;

        let has_cmek = config
            .get("encryption")
            .and_then(|e| {
                e.get("default_kms_key_name")
                    .or_else(|| e.get("defaultKmsKeyName"))
            })
            .and_then(Value::as_str)
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false)
            || config
                .get("cmek_enabled")
                .and_then(Value::as_bool)
                .unwrap_or(false);

        let logging_enabled = config
            .get("logging")
            .and_then(|l| l.get("log_bucket").or_else(|| l.get("logBucket")))
            .and_then(Value::as_str)
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false)
            || config
                .get("logging_enabled")
                .and_then(Value::as_bool)
                .unwrap_or(false);

        let versioning_enabled = config
            .get("versioning")
            .and_then(|v| v.get("enabled").and_then(Value::as_bool))
            .or_else(|| config.get("versioning_enabled").and_then(Value::as_bool))
            .unwrap_or(false);

        let retention_enabled = config
            .get("retention_policy")
            .or_else(|| config.get("retentionPolicy"))
            .and_then(|r| {
                r.get("retention_period")
                    .or_else(|| r.get("retentionPeriod"))
            })
            .and_then(Value::as_u64)
            .map(|p| p > 0)
            .unwrap_or(false)
            || config
                .get("retention_enabled")
                .and_then(Value::as_bool)
                .unwrap_or(false);

        if has_cmek && logging_enabled && versioning_enabled && retention_enabled {
            CheckEvaluation::Passed
        } else {
            CheckEvaluation::Failed {
                severity: self.base_severity(),
                evidence: json!({
                    "cmek_enabled": has_cmek,
                    "logging_enabled": logging_enabled,
                    "versioning_enabled": versioning_enabled,
                    "retention_enabled": retention_enabled,
                }),
                message: format!(
                    "Cloud Storage bucket '{}' lacks required CMEK encryption, access logging, versioning, or retention controls",
                    resource
                        .name
                        .as_deref()
                        .unwrap_or(&resource.provider_native_id)
                ),
            }
        }
    }
}
