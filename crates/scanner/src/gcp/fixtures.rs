use cloudsec_domain::{DiscoveredResource, Id, Resource};
use serde_json::json;

pub struct GcpTestFixtures;

impl GcpTestFixtures {
    // -------------------------------------------------------------
    // Cloud Storage Fixtures
    // -------------------------------------------------------------

    pub fn compliant_storage_bucket(org_id: Id, account_id: Id, name: &str) -> Resource {
        let disc = DiscoveredResource {
            provider_native_id: format!("b/{name}"),
            resource_type: "gcp_storage_bucket".to_string(),
            name: Some(name.to_string()),
            region: Some("us-central1".to_string()),
            tags: json!({"env": "production"}),
            configuration: json!({
                "uniform_bucket_level_access": {"enabled": true},
                "public_access_prevention": "enforced",
                "encryption": {
                    "default_kms_key_name": "projects/my-proj/locations/us-central1/keyRings/ring/cryptoKeys/key-01"
                },
                "logging": {
                    "log_bucket": "my-logging-bucket"
                },
                "versioning": {"enabled": true},
                "retention_policy": {"retention_period": 7776000},
                "iam_policy": [
                    {
                        "role": "roles/storage.objectViewer",
                        "members": ["group:analytics@example.com"]
                    }
                ]
            }),
        };
        disc.into_resource(org_id, account_id)
    }

    pub fn public_storage_bucket(org_id: Id, account_id: Id, name: &str) -> Resource {
        let disc = DiscoveredResource {
            provider_native_id: format!("b/{name}"),
            resource_type: "gcp_storage_bucket".to_string(),
            name: Some(name.to_string()),
            region: Some("us-central1".to_string()),
            tags: json!({"env": "dev"}),
            configuration: json!({
                "uniform_bucket_level_access": {"enabled": false},
                "public_access_prevention": "inherited",
                "encryption": {},
                "logging": {},
                "versioning": {"enabled": false},
                "iam_policy": [
                    {
                        "role": "roles/storage.objectViewer",
                        "members": ["allUsers"]
                    }
                ]
            }),
        };
        disc.into_resource(org_id, account_id)
    }

    // -------------------------------------------------------------
    // Compute Engine & VPC Fixtures
    // -------------------------------------------------------------

    pub fn compliant_firewall_rule(org_id: Id, account_id: Id, name: &str) -> Resource {
        let disc = DiscoveredResource {
            provider_native_id: format!("projects/my-proj/global/firewalls/{name}"),
            resource_type: "gcp_compute_firewall".to_string(),
            name: Some(name.to_string()),
            region: None,
            tags: json!({}),
            configuration: json!({
                "network": "projects/my-proj/global/networks/custom-vpc",
                "direction": "INGRESS",
                "disabled": false,
                "source_ranges": ["10.0.0.0/8"],
                "target_tags": ["web-tier"],
                "log_config": {"enable": true},
                "allowed": [
                    {"IPProtocol": "tcp", "ports": ["443"]}
                ]
            }),
        };
        disc.into_resource(org_id, account_id)
    }

    pub fn open_admin_firewall_rule(org_id: Id, account_id: Id, name: &str) -> Resource {
        let disc = DiscoveredResource {
            provider_native_id: format!("projects/my-proj/global/firewalls/{name}"),
            resource_type: "gcp_compute_firewall".to_string(),
            name: Some(name.to_string()),
            region: None,
            tags: json!({}),
            configuration: json!({
                "network": "projects/my-proj/global/networks/default",
                "direction": "INGRESS",
                "disabled": false,
                "source_ranges": ["0.0.0.0/0"],
                "target_tags": [],
                "target_service_accounts": [],
                "log_config": {"enable": false},
                "allowed": [
                    {"IPProtocol": "tcp", "ports": ["22", "3389", "3306"]}
                ]
            }),
        };
        disc.into_resource(org_id, account_id)
    }

    pub fn compliant_compute_instance(org_id: Id, account_id: Id, name: &str) -> Resource {
        let disc = DiscoveredResource {
            provider_native_id: format!("projects/my-proj/zones/us-central1-a/instances/{name}"),
            resource_type: "gcp_compute_instance".to_string(),
            name: Some(name.to_string()),
            region: Some("us-central1".to_string()),
            tags: json!({}),
            configuration: json!({
                "network_interfaces": [
                    {
                        "network": "projects/my-proj/global/networks/custom-vpc",
                        "network_ip": "10.0.1.5",
                        "access_configs": []
                    }
                ]
            }),
        };
        disc.into_resource(org_id, account_id)
    }

    pub fn external_ip_compute_instance(org_id: Id, account_id: Id, name: &str) -> Resource {
        let disc = DiscoveredResource {
            provider_native_id: format!("projects/my-proj/zones/us-central1-a/instances/{name}"),
            resource_type: "gcp_compute_instance".to_string(),
            name: Some(name.to_string()),
            region: Some("us-central1".to_string()),
            tags: json!({}),
            configuration: json!({
                "network_interfaces": [
                    {
                        "network": "projects/my-proj/global/networks/custom-vpc",
                        "network_ip": "10.0.1.5",
                        "access_configs": [
                            {
                                "name": "external-nat",
                                "type": "ONE_TO_ONE_NAT",
                                "nat_ip": "35.200.10.20"
                            }
                        ]
                    }
                ]
            }),
        };
        disc.into_resource(org_id, account_id)
    }

    // -------------------------------------------------------------
    // Cloud SQL Fixtures
    // -------------------------------------------------------------

    pub fn compliant_sql_instance(org_id: Id, account_id: Id, name: &str) -> Resource {
        let disc = DiscoveredResource {
            provider_native_id: format!("projects/my-proj/instances/{name}"),
            resource_type: "gcp_sql_instance".to_string(),
            name: Some(name.to_string()),
            region: Some("us-central1".to_string()),
            tags: json!({"tier": "prod"}),
            configuration: json!({
                "settings": {
                    "ip_configuration": {
                        "ipv4_enabled": false,
                        "authorized_networks": []
                    },
                    "backup_configuration": {
                        "enabled": true,
                        "point_in_time_recovery_enabled": true
                    }
                },
                "deletion_protection_enabled": true,
                "disk_encryption_configuration": {
                    "kms_key_name": "projects/my-proj/locations/us-central1/keyRings/ring/cryptoKeys/sql-key"
                }
            }),
        };
        disc.into_resource(org_id, account_id)
    }

    pub fn public_sql_instance(org_id: Id, account_id: Id, name: &str) -> Resource {
        let disc = DiscoveredResource {
            provider_native_id: format!("projects/my-proj/instances/{name}"),
            resource_type: "gcp_sql_instance".to_string(),
            name: Some(name.to_string()),
            region: Some("us-central1".to_string()),
            tags: json!({"tier": "dev"}),
            configuration: json!({
                "settings": {
                    "ip_configuration": {
                        "ipv4_enabled": true,
                        "authorized_networks": [
                            {"name": "AllowWorld", "value": "0.0.0.0/0"}
                        ]
                    },
                    "backup_configuration": {
                        "enabled": false,
                        "point_in_time_recovery_enabled": false
                    }
                },
                "deletion_protection_enabled": false,
                "disk_encryption_configuration": {}
            }),
        };
        disc.into_resource(org_id, account_id)
    }

    // -------------------------------------------------------------
    // IAM & Logging Fixtures
    // -------------------------------------------------------------

    pub fn compliant_iam_policy(org_id: Id, account_id: Id) -> Resource {
        let disc = DiscoveredResource {
            provider_native_id: "projects/my-proj/iamPolicy".to_string(),
            resource_type: "gcp_iam_policy".to_string(),
            name: Some("Project IAM Policy".to_string()),
            region: None,
            tags: json!({}),
            configuration: json!({
                "bindings": [
                    {
                        "role": "roles/viewer.private",
                        "members": ["user:dev@example.com"]
                    },
                    {
                        "role": "roles/resourcemanager.organizationViewer",
                        "members": ["group:auditors@example.com"]
                    }
                ]
            }),
        };
        disc.into_resource(org_id, account_id)
    }

    pub fn non_compliant_iam_policy(org_id: Id, account_id: Id) -> Resource {
        let disc = DiscoveredResource {
            provider_native_id: "projects/my-proj/iamPolicy".to_string(),
            resource_type: "gcp_iam_policy".to_string(),
            name: Some("Project IAM Policy Legacy".to_string()),
            region: None,
            tags: json!({}),
            configuration: json!({
                "bindings": [
                    {
                        "role": "roles/owner",
                        "members": ["user:dev@example.com", "allUsers"]
                    },
                    {
                        "role": "roles/editor",
                        "members": ["user:contractor@example.com"]
                    },
                    {
                        "role": "roles/iam.serviceAccountUser",
                        "members": ["user:analyst@example.com"]
                    }
                ]
            }),
        };
        disc.into_resource(org_id, account_id)
    }

    pub fn compliant_audit_config(org_id: Id, account_id: Id) -> Resource {
        let disc = DiscoveredResource {
            provider_native_id: "projects/my-proj/auditConfig".to_string(),
            resource_type: "gcp_audit_config".to_string(),
            name: Some("Project Audit Config".to_string()),
            region: None,
            tags: json!({}),
            configuration: json!({
                "audit_configs": [
                    {
                        "service": "allServices",
                        "audit_log_configs": [
                            {"log_type": "DATA_READ"},
                            {"log_type": "DATA_WRITE"},
                            {"log_type": "ADMIN_READ"}
                        ]
                    }
                ],
                "log_sinks": [
                    {"name": "security-central-bq-sink", "destination": "bigquery.googleapis.com/projects/my-proj/datasets/audit_logs"}
                ]
            }),
        };
        disc.into_resource(org_id, account_id)
    }

    pub fn non_compliant_audit_config(org_id: Id, account_id: Id) -> Resource {
        let disc = DiscoveredResource {
            provider_native_id: "projects/my-proj/auditConfig".to_string(),
            resource_type: "gcp_audit_config".to_string(),
            name: Some("Project Audit Config Empty".to_string()),
            region: None,
            tags: json!({}),
            configuration: json!({
                "audit_configs": [],
                "log_sinks": []
            }),
        };
        disc.into_resource(org_id, account_id)
    }

    // -------------------------------------------------------------
    // General Edge-case Fixtures
    // -------------------------------------------------------------

    pub fn malformed_resource(org_id: Id, account_id: Id, resource_type: &str) -> Resource {
        let disc = DiscoveredResource {
            provider_native_id: "corrupted-gcp-id".to_string(),
            resource_type: resource_type.to_string(),
            name: None,
            region: None,
            tags: json!(null),
            configuration: json!({}),
        };
        disc.into_resource(org_id, account_id)
    }

    pub fn wrong_provider_resource(org_id: Id, account_id: Id) -> Resource {
        let disc = DiscoveredResource {
            provider_native_id: "aws-s3-bucket-not-gcp".to_string(),
            resource_type: "aws_s3_bucket".to_string(),
            name: Some("not-gcp-bucket".to_string()),
            region: Some("us-east-1".to_string()),
            tags: json!({}),
            configuration: json!({}),
        };
        disc.into_resource(org_id, account_id)
    }
}
