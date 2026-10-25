use cloudsec_domain::{CloudProvider, Resource, Severity};
use serde_json::{Value, json};

use crate::check::{Check, CheckEvaluation};

const ADMIN_AND_DB_PORTS: &[u16] = &[22, 3389, 3306, 5432, 1433, 27017, 6379];

/// Check: No security group allows ingress from 0.0.0.0/0 to administrative or database ports
pub struct AwsEc2SgNoOpenAdminPortsCheck;

impl Check for AwsEc2SgNoOpenAdminPortsCheck {
    fn id(&self) -> &str {
        "aws-ec2-sg-no-open-admin-ports"
    }
    fn provider(&self) -> CloudProvider {
        CloudProvider::Aws
    }
    fn service(&self) -> &str {
        "ec2"
    }
    fn category(&self) -> &str {
        "network"
    }
    fn version(&self) -> &str {
        "1.0.0"
    }
    fn title(&self) -> &str {
        "Ensure security groups do not allow internet ingress to admin or database ports"
    }
    fn description(&self) -> &str {
        "Security groups should not permit ingress from 0.0.0.0/0 or ::/0 to administrative ports (22, 3389) or database ports (3306, 5432, 1433, 27017, 6379)."
    }
    fn remediation(&self) -> &str {
        "aws ec2 revoke-security-group-ingress --group-id <sg-id> --protocol tcp --port <port> --cidr 0.0.0.0/0"
    }
    fn base_severity(&self) -> Severity {
        Severity::High
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type != "aws_security_group" {
            return CheckEvaluation::NotApplicable;
        }

        let config = &resource.configuration;
        let mut exposed_ports = Vec::new();

        if let Some(rules) = config.get("ingress_rules").and_then(Value::as_array) {
            for rule in rules {
                let is_public = rule
                    .get("cidr")
                    .and_then(Value::as_str)
                    .map(|cidr| cidr == "0.0.0.0/0" || cidr == "::/0")
                    .unwrap_or(false);

                if is_public {
                    let from_port =
                        rule.get("from_port").and_then(Value::as_u64).unwrap_or(0) as u16;
                    let to_port = rule.get("to_port").and_then(Value::as_u64).unwrap_or(0) as u16;

                    for &port in ADMIN_AND_DB_PORTS {
                        if (from_port..=to_port).contains(&port) {
                            exposed_ports.push(port);
                        }
                    }
                }
            }
        }

        exposed_ports.sort_unstable();
        exposed_ports.dedup();

        if exposed_ports.is_empty() {
            CheckEvaluation::Passed
        } else {
            CheckEvaluation::Failed {
                severity: self.base_severity(),
                evidence: json!({
                    "exposed_admin_or_db_ports": exposed_ports,
                    "ingress_cidr": "0.0.0.0/0",
                }),
                message: format!(
                    "Security group '{}' ({}) allows public ingress on sensitive ports: {:?}",
                    resource.name.as_deref().unwrap_or(""),
                    resource.provider_native_id,
                    exposed_ports
                ),
            }
        }
    }
}

/// Check: No security group allows unrestricted all-traffic ingress
pub struct AwsEc2SgUnrestrictedTrafficCheck;

impl Check for AwsEc2SgUnrestrictedTrafficCheck {
    fn id(&self) -> &str {
        "aws-ec2-sg-unrestricted-traffic"
    }
    fn provider(&self) -> CloudProvider {
        CloudProvider::Aws
    }
    fn service(&self) -> &str {
        "ec2"
    }
    fn category(&self) -> &str {
        "network"
    }
    fn version(&self) -> &str {
        "1.0.0"
    }
    fn title(&self) -> &str {
        "Ensure security groups do not allow all-traffic ingress from the internet"
    }
    fn description(&self) -> &str {
        "Security groups should not permit all protocols (-1) from 0.0.0.0/0 or ::/0."
    }
    fn remediation(&self) -> &str {
        "aws ec2 revoke-security-group-ingress --group-id <sg-id> --protocol -1 --cidr 0.0.0.0/0"
    }
    fn base_severity(&self) -> Severity {
        Severity::Critical
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type != "aws_security_group" {
            return CheckEvaluation::NotApplicable;
        }

        let config = &resource.configuration;
        let mut allows_all_traffic = false;

        if let Some(rules) = config.get("ingress_rules").and_then(Value::as_array) {
            for rule in rules {
                let is_public = rule
                    .get("cidr")
                    .and_then(Value::as_str)
                    .map(|cidr| cidr == "0.0.0.0/0" || cidr == "::/0")
                    .unwrap_or(false);

                let protocol = rule.get("protocol").and_then(Value::as_str).unwrap_or("");
                if is_public && (protocol == "-1" || protocol == "all") {
                    allows_all_traffic = true;
                    break;
                }
            }
        }

        if !allows_all_traffic {
            CheckEvaluation::Passed
        } else {
            CheckEvaluation::Failed {
                severity: self.base_severity(),
                evidence: json!({
                    "allows_all_protocols_publicly": true,
                }),
                message: format!(
                    "Security group '{}' ({}) allows all traffic from 0.0.0.0/0",
                    resource.name.as_deref().unwrap_or(""),
                    resource.provider_native_id
                ),
            }
        }
    }
}

/// Check: Identify unused security groups
pub struct AwsEc2SgUnusedCheck;

impl Check for AwsEc2SgUnusedCheck {
    fn id(&self) -> &str {
        "aws-ec2-sg-unused"
    }
    fn provider(&self) -> CloudProvider {
        CloudProvider::Aws
    }
    fn service(&self) -> &str {
        "ec2"
    }
    fn category(&self) -> &str {
        "network"
    }
    fn version(&self) -> &str {
        "1.0.0"
    }
    fn title(&self) -> &str {
        "Identify unused security groups for review"
    }
    fn description(&self) -> &str {
        "Security groups with 0 attached network interfaces or instances should be audited and cleaned up if obsolete."
    }
    fn remediation(&self) -> &str {
        "Review dependencies and run aws ec2 delete-security-group --group-id <sg-id> if no longer required."
    }
    fn base_severity(&self) -> Severity {
        Severity::Low
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type != "aws_security_group" {
            return CheckEvaluation::NotApplicable;
        }

        let config = &resource.configuration;
        let attached_eni_count = config
            .get("attached_eni_count")
            .and_then(Value::as_u64)
            .unwrap_or(1);

        if attached_eni_count > 0 {
            CheckEvaluation::Passed
        } else {
            CheckEvaluation::Failed {
                severity: self.base_severity(),
                evidence: json!({
                    "attached_eni_count": 0,
                }),
                message: format!(
                    "Security group '{}' ({}) is not associated with any active network interfaces",
                    resource.name.as_deref().unwrap_or(""),
                    resource.provider_native_id
                ),
            }
        }
    }
}

/// Check: IMDSv2 is enforced on EC2 instances
pub struct AwsEc2Imdsv2EnforcedCheck;

impl Check for AwsEc2Imdsv2EnforcedCheck {
    fn id(&self) -> &str {
        "aws-ec2-imdsv2-enforced"
    }
    fn provider(&self) -> CloudProvider {
        CloudProvider::Aws
    }
    fn service(&self) -> &str {
        "ec2"
    }
    fn category(&self) -> &str {
        "compute"
    }
    fn version(&self) -> &str {
        "1.0.0"
    }
    fn title(&self) -> &str {
        "Ensure IMDSv2 is enforced on all EC2 instances"
    }
    fn description(&self) -> &str {
        "Instance Metadata Service Version 2 (IMDSv2) uses session-oriented requests, mitigating Server-Side Request Forgery (SSRF) risks."
    }
    fn remediation(&self) -> &str {
        "aws ec2 modify-instance-metadata-options --instance-id <id> --http-tokens required --http-endpoint enabled"
    }
    fn base_severity(&self) -> Severity {
        Severity::High
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type != "aws_ec2_instance" {
            return CheckEvaluation::NotApplicable;
        }

        let config = &resource.configuration;
        let http_tokens = config
            .get("http_tokens")
            .and_then(Value::as_str)
            .unwrap_or("optional");

        if http_tokens == "required" {
            CheckEvaluation::Passed
        } else {
            CheckEvaluation::Failed {
                severity: self.base_severity(),
                evidence: json!({
                    "http_tokens": http_tokens,
                }),
                message: format!(
                    "EC2 Instance '{}' has IMDSv2 token requirement set to '{http_tokens}' (expected 'required')",
                    resource
                        .name
                        .as_deref()
                        .unwrap_or(&resource.provider_native_id)
                ),
            }
        }
    }
}

/// Check: EBS Volume encryption is enabled
pub struct AwsEc2EbsEncryptionEnabledCheck;

impl Check for AwsEc2EbsEncryptionEnabledCheck {
    fn id(&self) -> &str {
        "aws-ec2-ebs-encryption-enabled"
    }
    fn provider(&self) -> CloudProvider {
        CloudProvider::Aws
    }
    fn service(&self) -> &str {
        "ec2"
    }
    fn category(&self) -> &str {
        "storage"
    }
    fn version(&self) -> &str {
        "1.0.0"
    }
    fn title(&self) -> &str {
        "Ensure EBS volume encryption is enabled"
    }
    fn description(&self) -> &str {
        "EBS volumes should be encrypted at rest using KMS to protect confidential and regulated data."
    }
    fn remediation(&self) -> &str {
        "aws ec2 enable-ebs-encryption-by-default in target region."
    }
    fn base_severity(&self) -> Severity {
        Severity::High
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type != "aws_ebs_volume" {
            return CheckEvaluation::NotApplicable;
        }

        let config = &resource.configuration;
        let encrypted = config
            .get("encrypted")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        if encrypted {
            CheckEvaluation::Passed
        } else {
            CheckEvaluation::Failed {
                severity: self.base_severity(),
                evidence: json!({
                    "encrypted": false,
                }),
                message: format!(
                    "EBS Volume '{}' is unencrypted at rest",
                    resource
                        .name
                        .as_deref()
                        .unwrap_or(&resource.provider_native_id)
                ),
            }
        }
    }
}

/// Check: VPC Flow Logs enabled
pub struct AwsVpcFlowLogsEnabledCheck;

impl Check for AwsVpcFlowLogsEnabledCheck {
    fn id(&self) -> &str {
        "aws-vpc-flow-logs-enabled"
    }
    fn provider(&self) -> CloudProvider {
        CloudProvider::Aws
    }
    fn service(&self) -> &str {
        "vpc"
    }
    fn category(&self) -> &str {
        "network"
    }
    fn version(&self) -> &str {
        "1.0.0"
    }
    fn title(&self) -> &str {
        "Ensure VPC Flow Logs are enabled for all VPCs"
    }
    fn description(&self) -> &str {
        "VPC Flow Logs capture IP traffic information for network monitoring, threat investigation, and forensics."
    }
    fn remediation(&self) -> &str {
        "aws ec2 create-flow-logs --resource-type VPC --resource-ids <vpc-id> --traffic-type ALL --log-destination-type cloud-watch-logs"
    }
    fn base_severity(&self) -> Severity {
        Severity::Medium
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type != "aws_vpc" {
            return CheckEvaluation::NotApplicable;
        }

        let config = &resource.configuration;
        let flow_logs_enabled = config
            .get("flow_logs_enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        if flow_logs_enabled {
            CheckEvaluation::Passed
        } else {
            CheckEvaluation::Failed {
                severity: self.base_severity(),
                evidence: json!({
                    "flow_logs_enabled": false,
                }),
                message: format!(
                    "VPC '{}' does not have active flow logging enabled",
                    resource
                        .name
                        .as_deref()
                        .unwrap_or(&resource.provider_native_id)
                ),
            }
        }
    }
}

/// Check: Default security group restricts all traffic
pub struct AwsEc2DefaultSgRestrictsAllCheck;

impl Check for AwsEc2DefaultSgRestrictsAllCheck {
    fn id(&self) -> &str {
        "aws-ec2-default-sg-restricts-all"
    }
    fn provider(&self) -> CloudProvider {
        CloudProvider::Aws
    }
    fn service(&self) -> &str {
        "ec2"
    }
    fn category(&self) -> &str {
        "network"
    }
    fn version(&self) -> &str {
        "1.0.0"
    }
    fn title(&self) -> &str {
        "Ensure default security group of every VPC restricts all traffic"
    }
    fn description(&self) -> &str {
        "The default security group in each VPC should deny all inbound and outbound traffic to prevent accidental exposure."
    }
    fn remediation(&self) -> &str {
        "Remove all inbound and outbound rules from default security groups."
    }
    fn base_severity(&self) -> Severity {
        Severity::Medium
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type != "aws_security_group" {
            return CheckEvaluation::NotApplicable;
        }

        let is_default = resource.name.as_deref() == Some("default")
            || resource
                .configuration
                .get("group_name")
                .and_then(Value::as_str)
                == Some("default");

        if !is_default {
            return CheckEvaluation::NotApplicable;
        }

        let config = &resource.configuration;
        let ingress_rules_count = config
            .get("ingress_rules")
            .and_then(Value::as_array)
            .map(|a| a.len())
            .unwrap_or(0);
        let egress_rules_count = config
            .get("egress_rules")
            .and_then(Value::as_array)
            .map(|a| a.len())
            .unwrap_or(0);

        if ingress_rules_count == 0 && egress_rules_count == 0 {
            CheckEvaluation::Passed
        } else {
            CheckEvaluation::Failed {
                severity: self.base_severity(),
                evidence: json!({
                    "default_security_group": true,
                    "ingress_rules_count": ingress_rules_count,
                    "egress_rules_count": egress_rules_count,
                }),
                message: format!(
                    "Default security group '{}' has active rules (ingress: {ingress_rules_count}, egress: {egress_rules_count})",
                    resource.provider_native_id
                ),
            }
        }
    }
}

/// Check: Unattached Elastic IPs identified for cost and security optimization
pub struct AwsEc2UnattachedElasticIpCheck;

impl Check for AwsEc2UnattachedElasticIpCheck {
    fn id(&self) -> &str {
        "aws-ec2-unattached-elastic-ip"
    }
    fn provider(&self) -> CloudProvider {
        CloudProvider::Aws
    }
    fn service(&self) -> &str {
        "ec2"
    }
    fn category(&self) -> &str {
        "network"
    }
    fn version(&self) -> &str {
        "1.0.0"
    }
    fn title(&self) -> &str {
        "Identify unattached Elastic IP addresses"
    }
    fn description(&self) -> &str {
        "Unattached Elastic IPs incur idle charges and can pose security risks if stale DNS records point to them."
    }
    fn remediation(&self) -> &str {
        "aws ec2 release-address --allocation-id <allocation-id>"
    }
    fn base_severity(&self) -> Severity {
        Severity::Informational
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type != "aws_elastic_ip" {
            return CheckEvaluation::NotApplicable;
        }

        let config = &resource.configuration;
        let associated = config
            .get("associated")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        if associated {
            CheckEvaluation::Passed
        } else {
            CheckEvaluation::Failed {
                severity: self.base_severity(),
                evidence: json!({
                    "associated": false,
                    "public_ip": config.get("public_ip"),
                }),
                message: format!(
                    "Elastic IP '{}' is allocated but not associated with any active resource",
                    resource.provider_native_id
                ),
            }
        }
    }
}
