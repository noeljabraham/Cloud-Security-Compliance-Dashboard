use cloudsec_domain::{CloudProvider, Resource, Severity};
use serde_json::{Value, json};

use crate::check::{Check, CheckEvaluation};

const ADMIN_AND_DB_PORTS: &[u16] = &[
    22,    // SSH
    3389,  // RDP
    3306,  // MySQL
    5432,  // PostgreSQL
    1433,  // MSSQL
    1521,  // Oracle
    27017, // MongoDB
    6379,  // Redis
    9200,  // Elasticsearch
];

fn is_open_source(source: &str) -> bool {
    let s = source.trim();
    s == "0.0.0.0/0" || s == "::/0" || s == "*" || s.eq_ignore_ascii_case("all")
}

fn port_matches(rule_port: &str, target: u16) -> bool {
    let p = rule_port.trim();
    if p == "*" || p == "all" || p == "0-65535" {
        return true;
    }
    if let Ok(num) = p.parse::<u16>() {
        return num == target;
    }
    if let Some((start_s, end_s)) = p.split_once('-') {
        if let (Ok(start), Ok(end)) = (start_s.trim().parse::<u16>(), end_s.trim().parse::<u16>()) {
            return target >= start && target <= end;
        }
    }
    false
}

/// Check: GCP VPC Firewall Rules Do Not Allow Inbound Internet on Admin or Database Ports
pub struct GcpComputeFirewallNoOpenAdminOrDbPortsCheck;

impl Check for GcpComputeFirewallNoOpenAdminOrDbPortsCheck {
    fn id(&self) -> &str {
        "gcp-compute-firewall-no-open-admin-or-db-ports"
    }

    fn provider(&self) -> CloudProvider {
        CloudProvider::Gcp
    }

    fn service(&self) -> &str {
        "compute"
    }

    fn category(&self) -> &str {
        "network_security"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn title(&self) -> &str {
        "Ensure VPC Firewall Rules Do Not Allow Inbound Internet on Admin or Database Ports"
    }

    fn description(&self) -> &str {
        "Verify that GCP VPC firewall rules do not permit ingress traffic from 0.0.0.0/0 on SSH, RDP, or database ports."
    }

    fn remediation(&self) -> &str {
        "Update or delete firewall rules allowing ingress traffic from 0.0.0.0/0 on ports 22, 3389, 3306, 5432, 1433, 27017, or all ports."
    }

    fn base_severity(&self) -> Severity {
        Severity::High
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type != "gcp_compute_firewall"
            && resource.resource_type != "compute.googleapis.com/Firewall"
        {
            return CheckEvaluation::NotApplicable;
        }

        let config = &resource.configuration;

        let direction = config
            .get("direction")
            .and_then(Value::as_str)
            .unwrap_or("INGRESS");

        let disabled = config
            .get("disabled")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        // Disabled rules or egress rules don't expose ports
        if disabled || !direction.eq_ignore_ascii_case("INGRESS") {
            return CheckEvaluation::Passed;
        }

        let source_ranges = config
            .get("source_ranges")
            .or_else(|| config.get("sourceRanges"))
            .and_then(Value::as_array);

        let is_public_source = source_ranges
            .map(|arr| arr.iter().filter_map(Value::as_str).any(is_open_source))
            .unwrap_or(false);

        if !is_public_source {
            return CheckEvaluation::Passed;
        }

        let allowed = config.get("allowed").and_then(Value::as_array);
        let mut exposed_ports = Vec::new();

        if let Some(allow_list) = allowed {
            for entry in allow_list {
                let ip_proto = entry
                    .get("IPProtocol")
                    .or_else(|| entry.get("ip_protocol"))
                    .and_then(Value::as_str)
                    .unwrap_or("");

                let ports = entry.get("ports").and_then(Value::as_array);

                if ip_proto.eq_ignore_ascii_case("all") {
                    exposed_ports.push("all".to_string());
                    break;
                }

                if let Some(port_arr) = ports {
                    for &target_port in ADMIN_AND_DB_PORTS {
                        for p_val in port_arr.iter().filter_map(Value::as_str) {
                            if port_matches(p_val, target_port) {
                                exposed_ports.push(format!("{target_port} ({ip_proto})"));
                                break;
                            }
                        }
                    }
                }
            }
        }

        if exposed_ports.is_empty() {
            CheckEvaluation::Passed
        } else {
            let has_admin_port = exposed_ports
                .iter()
                .any(|p| p.contains("22") || p.contains("3389") || p == "all");
            let severity = if has_admin_port {
                Severity::Critical
            } else {
                Severity::High
            };

            CheckEvaluation::Failed {
                severity,
                evidence: json!({
                    "direction": direction,
                    "is_public_source": is_public_source,
                    "exposed_ports": exposed_ports,
                }),
                message: format!(
                    "VPC firewall rule '{}' exposes administrative or database ports to 0.0.0.0/0",
                    resource
                        .name
                        .as_deref()
                        .unwrap_or(&resource.provider_native_id)
                ),
            }
        }
    }
}

/// Check: GCP VPC Firewall Target Scope, Rule Logging, and Default Network Usage
pub struct GcpComputeFirewallTargetLoggingAndDefaultNetworkCheck;

impl Check for GcpComputeFirewallTargetLoggingAndDefaultNetworkCheck {
    fn id(&self) -> &str {
        "gcp-compute-firewall-target-logging-and-default-network"
    }

    fn provider(&self) -> CloudProvider {
        CloudProvider::Gcp
    }

    fn service(&self) -> &str {
        "compute"
    }

    fn category(&self) -> &str {
        "network_hygiene"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn title(&self) -> &str {
        "Ensure VPC Firewall Rules Have Explicit Target Scope, Logging Enabled, and Do Not Use Default Network"
    }

    fn description(&self) -> &str {
        "Verify that VPC firewall rules define explicit target tags or service accounts, have firewall rule logging enabled, and avoid the legacy 'default' VPC network."
    }

    fn remediation(&self) -> &str {
        "Assign explicit target tags or service accounts, enable firewall rule logging, and migrate workloads to a custom VPC network."
    }

    fn base_severity(&self) -> Severity {
        Severity::Medium
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type != "gcp_compute_firewall"
            && resource.resource_type != "compute.googleapis.com/Firewall"
        {
            return CheckEvaluation::NotApplicable;
        }

        let config = &resource.configuration;

        let network = config.get("network").and_then(Value::as_str).unwrap_or("");

        let is_default_network = network.ends_with("/default") || network == "default";

        let target_tags = config
            .get("target_tags")
            .or_else(|| config.get("targetTags"))
            .and_then(Value::as_array);

        let target_service_accounts = config
            .get("target_service_accounts")
            .or_else(|| config.get("targetServiceAccounts"))
            .and_then(Value::as_array);

        let has_explicit_target = target_tags.map(|a| !a.is_empty()).unwrap_or(false)
            || target_service_accounts
                .map(|a| !a.is_empty())
                .unwrap_or(false);

        let logging_enabled = config
            .get("log_config")
            .or_else(|| config.get("logConfig"))
            .and_then(|l| l.get("enable").and_then(Value::as_bool))
            .or_else(|| config.get("logging_enabled").and_then(Value::as_bool))
            .unwrap_or(false);

        if !is_default_network && has_explicit_target && logging_enabled {
            CheckEvaluation::Passed
        } else {
            CheckEvaluation::Failed {
                severity: self.base_severity(),
                evidence: json!({
                    "is_default_network": is_default_network,
                    "has_explicit_target_scope": has_explicit_target,
                    "logging_enabled": logging_enabled,
                }),
                message: format!(
                    "Firewall rule '{}' uses default network, lacks target tags/service accounts, or has logging disabled",
                    resource
                        .name
                        .as_deref()
                        .unwrap_or(&resource.provider_native_id)
                ),
            }
        }
    }
}

/// Check: Compute Instances Do Not Have Direct External IPs and No Unattached External IPs
pub struct GcpComputeNoUnattachedOrDirectExternalIpsCheck;

impl Check for GcpComputeNoUnattachedOrDirectExternalIpsCheck {
    fn id(&self) -> &str {
        "gcp-compute-no-unattached-or-direct-external-ips"
    }

    fn provider(&self) -> CloudProvider {
        CloudProvider::Gcp
    }

    fn service(&self) -> &str {
        "compute"
    }

    fn category(&self) -> &str {
        "network_security"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn title(&self) -> &str {
        "Ensure Compute Instances Do Not Have Direct External IPs and Unattached Static IPs are Removed"
    }

    fn description(&self) -> &str {
        "Verify that Compute Engine VM instances do not possess direct external IP addresses (use Cloud NAT instead) and that unattached static external IPs are reclaimed."
    }

    fn remediation(&self) -> &str {
        "Remove external access configs (accessConfigs) from VM network interfaces, configure Cloud NAT for outbound access, and delete unattached static external IP addresses."
    }

    fn base_severity(&self) -> Severity {
        Severity::Medium
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type == "gcp_compute_instance"
            || resource.resource_type == "compute.googleapis.com/Instance"
        {
            let config = &resource.configuration;
            let network_interfaces = config
                .get("network_interfaces")
                .or_else(|| config.get("networkInterfaces"))
                .and_then(Value::as_array);

            let mut direct_external_ips = Vec::new();

            if let Some(nics) = network_interfaces {
                for nic in nics {
                    let access_configs = nic
                        .get("access_configs")
                        .or_else(|| nic.get("accessConfigs"))
                        .and_then(Value::as_array);

                    if let Some(configs) = access_configs {
                        for ac in configs {
                            if let Some(nat_ip) = ac
                                .get("nat_ip")
                                .or_else(|| ac.get("natIP"))
                                .and_then(Value::as_str)
                            {
                                direct_external_ips.push(nat_ip.to_string());
                            } else if ac
                                .get("type")
                                .and_then(Value::as_str)
                                .map(|t| t.contains("ONE_TO_ONE_NAT"))
                                .unwrap_or(false)
                            {
                                direct_external_ips.push("ONE_TO_ONE_NAT".to_string());
                            }
                        }
                    }
                }
            }

            if direct_external_ips.is_empty() {
                CheckEvaluation::Passed
            } else {
                CheckEvaluation::Failed {
                    severity: self.base_severity(),
                    evidence: json!({
                        "direct_external_ips": direct_external_ips,
                    }),
                    message: format!(
                        "Compute instance '{}' has direct external IP address attached instead of using Cloud NAT or Load Balancer",
                        resource
                            .name
                            .as_deref()
                            .unwrap_or(&resource.provider_native_id)
                    ),
                }
            }
        } else if resource.resource_type == "gcp_compute_address"
            || resource.resource_type == "compute.googleapis.com/Address"
        {
            let config = &resource.configuration;
            let status = config
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("IN_USE");

            let users = config.get("users").and_then(Value::as_array);
            let is_unattached = status.eq_ignore_ascii_case("RESERVED")
                || users.map(|u| u.is_empty()).unwrap_or(false)
                || config
                    .get("is_unattached")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);

            if !is_unattached {
                CheckEvaluation::Passed
            } else {
                CheckEvaluation::Failed {
                    severity: Severity::Low,
                    evidence: json!({
                        "status": status,
                        "is_unattached": is_unattached,
                    }),
                    message: format!(
                        "Static external IP address '{}' is unattached and should be released",
                        resource
                            .name
                            .as_deref()
                            .unwrap_or(&resource.provider_native_id)
                    ),
                }
            }
        } else {
            CheckEvaluation::NotApplicable
        }
    }
}
