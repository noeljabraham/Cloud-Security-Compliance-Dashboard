use cloudsec_domain::{CloudProvider, Resource, Severity};
use serde_json::{Value, json};

use crate::check::{Check, CheckEvaluation};

const ADMIN_AND_DB_PORTS: &[u16] = &[
    22,    // SSH
    3389,  // RDP
    3306,  // MySQL
    5432,  // PostgreSQL
    1433,  // Microsoft SQL Server
    1521,  // Oracle DB
    27017, // MongoDB
    6379,  // Redis
    9200,  // Elasticsearch
];

fn is_internet_source(source: &str) -> bool {
    let s = source.trim();
    s == "*"
        || s.eq_ignore_ascii_case("Internet")
        || s.eq_ignore_ascii_case("any")
        || s == "0.0.0.0/0"
        || s == "::/0"
}

fn port_matches(rule_port: &str, target_port: u16) -> bool {
    let p = rule_port.trim();
    if p == "*" || p == "0-65535" {
        return true;
    }
    if let Ok(num) = p.parse::<u16>() {
        return num == target_port;
    }
    if let Some((start_s, end_s)) = p.split_once('-') {
        if let (Ok(start), Ok(end)) = (start_s.trim().parse::<u16>(), end_s.trim().parse::<u16>()) {
            return target_port >= start && target_port <= end;
        }
    }
    false
}

/// Check: Azure NSGs Do Not Allow Inbound Internet Traffic on Admin or Database Ports
pub struct AzureNsgNoOpenAdminOrDbPortsCheck;

impl Check for AzureNsgNoOpenAdminOrDbPortsCheck {
    fn id(&self) -> &str {
        "azure-nsg-no-open-admin-or-db-ports"
    }

    fn provider(&self) -> CloudProvider {
        CloudProvider::Azure
    }

    fn service(&self) -> &str {
        "network"
    }

    fn category(&self) -> &str {
        "network_security"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn title(&self) -> &str {
        "Ensure Network Security Groups Restrict Inbound Internet Access on Admin and Database Ports"
    }

    fn description(&self) -> &str {
        "Verify that Azure Network Security Group (NSG) security rules do not allow inbound traffic from the Internet on management (SSH/RDP) or database ports."
    }

    fn remediation(&self) -> &str {
        "Modify or delete NSG inbound security rules allowing access from 'Internet' or '*' to ports 22, 3389, 1433, 3306, 5432, or all ports."
    }

    fn base_severity(&self) -> Severity {
        Severity::High
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type != "azure_network_security_group"
            && resource.resource_type != "Microsoft.Network/networkSecurityGroups"
        {
            return CheckEvaluation::NotApplicable;
        }

        let config = &resource.configuration;

        let security_rules = config
            .get("security_rules")
            .or_else(|| config.get("securityRules"))
            .and_then(Value::as_array);

        let mut violations = Vec::new();

        if let Some(rules) = security_rules {
            for rule in rules {
                let access = rule.get("access").and_then(Value::as_str).unwrap_or("");
                let direction = rule.get("direction").and_then(Value::as_str).unwrap_or("");

                if !access.eq_ignore_ascii_case("Allow")
                    || !direction.eq_ignore_ascii_case("Inbound")
                {
                    continue;
                }

                let source = rule
                    .get("source_address_prefix")
                    .or_else(|| rule.get("sourceAddressPrefix"))
                    .and_then(Value::as_str)
                    .unwrap_or("");

                let source_prefixes = rule
                    .get("source_address_prefixes")
                    .or_else(|| rule.get("sourceAddressPrefixes"))
                    .and_then(Value::as_array);

                let is_open_source = is_internet_source(source)
                    || source_prefixes
                        .map(|arr| arr.iter().filter_map(Value::as_str).any(is_internet_source))
                        .unwrap_or(false);

                if !is_open_source {
                    continue;
                }

                let dest_port = rule
                    .get("destination_port_range")
                    .or_else(|| rule.get("destinationPortRange"))
                    .and_then(Value::as_str)
                    .unwrap_or("");

                let dest_ports = rule
                    .get("destination_port_ranges")
                    .or_else(|| rule.get("destinationPortRanges"))
                    .and_then(Value::as_array);

                for &target_port in ADMIN_AND_DB_PORTS {
                    let mut matched = false;
                    if !dest_port.is_empty() && port_matches(dest_port, target_port) {
                        matched = true;
                    }
                    if let Some(d_arr) = dest_ports {
                        if d_arr
                            .iter()
                            .filter_map(Value::as_str)
                            .any(|dp| port_matches(dp, target_port))
                        {
                            matched = true;
                        }
                    }

                    if matched {
                        let rule_name = rule
                            .get("name")
                            .and_then(Value::as_str)
                            .unwrap_or("unnamed");
                        violations.push(json!({
                            "rule_name": rule_name,
                            "port": target_port,
                            "source": source,
                            "destination_port": dest_port,
                        }));
                        break;
                    }
                }
            }
        }

        if violations.is_empty() {
            CheckEvaluation::Passed
        } else {
            let has_admin_port = violations.iter().any(|v| {
                v.get("port")
                    .and_then(Value::as_u64)
                    .map(|p| p == 22 || p == 3389)
                    .unwrap_or(false)
            });
            let severity = if has_admin_port {
                Severity::Critical
            } else {
                Severity::High
            };

            CheckEvaluation::Failed {
                severity,
                evidence: json!({ "violations": violations }),
                message: format!(
                    "NSG '{}' exposes administrative or database ports directly to the internet",
                    resource
                        .name
                        .as_deref()
                        .unwrap_or(&resource.provider_native_id)
                ),
            }
        }
    }
}

/// Check: Azure NSGs Do Not Contain Overly Broad Ranges or Stale Inactive Rules
pub struct AzureNsgNoBroadRangesOrStaleRulesCheck;

impl Check for AzureNsgNoBroadRangesOrStaleRulesCheck {
    fn id(&self) -> &str {
        "azure-nsg-no-broad-ranges-or-stale-rules"
    }

    fn provider(&self) -> CloudProvider {
        CloudProvider::Azure
    }

    fn service(&self) -> &str {
        "network"
    }

    fn category(&self) -> &str {
        "network_hygiene"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn title(&self) -> &str {
        "Ensure Network Security Groups Do Not Contain Overly Broad Ranges or Stale Rules"
    }

    fn description(&self) -> &str {
        "Verify that Azure NSGs do not contain catch-all allow rules across all ports ('*') and identify stale, unattached rules."
    }

    fn remediation(&self) -> &str {
        "Restrict broad port range rules to required service ports and remove stale NSG rules that are no longer associated with active network interfaces."
    }

    fn base_severity(&self) -> Severity {
        Severity::Medium
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type != "azure_network_security_group"
            && resource.resource_type != "Microsoft.Network/networkSecurityGroups"
        {
            return CheckEvaluation::NotApplicable;
        }

        let config = &resource.configuration;

        // Check if NSG is unattached / stale
        let subnets_count = config
            .get("subnets")
            .and_then(Value::as_array)
            .map(|a| a.len())
            .unwrap_or(0);
        let nics_count = config
            .get("network_interfaces")
            .or_else(|| config.get("networkInterfaces"))
            .and_then(Value::as_array)
            .map(|a| a.len())
            .unwrap_or(0);

        let is_stale_nsg = config
            .get("is_stale")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            || (subnets_count == 0 && nics_count == 0);

        let security_rules = config
            .get("security_rules")
            .or_else(|| config.get("securityRules"))
            .and_then(Value::as_array);

        let mut broad_rules = Vec::new();

        if let Some(rules) = security_rules {
            for rule in rules {
                let access = rule.get("access").and_then(Value::as_str).unwrap_or("");
                if !access.eq_ignore_ascii_case("Allow") {
                    continue;
                }

                let source = rule
                    .get("source_address_prefix")
                    .or_else(|| rule.get("sourceAddressPrefix"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let dest_port = rule
                    .get("destination_port_range")
                    .or_else(|| rule.get("destinationPortRange"))
                    .and_then(Value::as_str)
                    .unwrap_or("");

                let rule_is_stale = rule
                    .get("is_stale")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);

                if (is_internet_source(source) && (dest_port == "*" || dest_port == "0-65535"))
                    || rule_is_stale
                {
                    let rule_name = rule
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or("unnamed");
                    broad_rules.push(json!({
                        "rule_name": rule_name,
                        "source": source,
                        "destination_port": dest_port,
                        "is_stale": rule_is_stale,
                    }));
                }
            }
        }

        if !is_stale_nsg && broad_rules.is_empty() {
            CheckEvaluation::Passed
        } else {
            CheckEvaluation::Failed {
                severity: self.base_severity(),
                evidence: json!({
                    "is_unattached_nsg": is_stale_nsg,
                    "subnets_count": subnets_count,
                    "nics_count": nics_count,
                    "broad_or_stale_rules": broad_rules,
                }),
                message: format!(
                    "NSG '{}' contains overly broad allow-all rules or is unattached/stale",
                    resource
                        .name
                        .as_deref()
                        .unwrap_or(&resource.provider_native_id)
                ),
            }
        }
    }
}
