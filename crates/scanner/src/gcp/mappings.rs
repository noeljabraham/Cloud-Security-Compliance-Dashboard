use crate::aws::mappings::FrameworkMapping;

pub struct GcpCheckFrameworkMappings;

impl GcpCheckFrameworkMappings {
    pub fn get_mappings(check_id: &str) -> Vec<FrameworkMapping> {
        match check_id {
            // Storage
            "gcp-storage-no-public-iam-bindings" => vec![
                FrameworkMapping {
                    framework: "CIS Google Cloud Platform Foundation Benchmark",
                    version: "3.0.0",
                    control_id: "5.1",
                    title: "Ensure that Cloud Storage bucket is not anonymously or publicly accessible",
                },
                FrameworkMapping {
                    framework: "AICPA SOC 2 (TSC)",
                    version: "2017/2022",
                    control_id: "CC6.1",
                    title: "Logical access controls protect against public data exposure",
                },
                FrameworkMapping {
                    framework: "PCI DSS",
                    version: "4.0.1",
                    control_id: "1.3.1",
                    title: "Inbound traffic from untrusted networks is restricted",
                },
                FrameworkMapping {
                    framework: "HIPAA Security Rule",
                    version: "45 CFR Part 164",
                    control_id: "164.312(a)(1)",
                    title: "Access control for electronic protected health information",
                },
            ],
            "gcp-storage-uniform-access-and-pap" => vec![
                FrameworkMapping {
                    framework: "CIS Google Cloud Platform Foundation Benchmark",
                    version: "3.0.0",
                    control_id: "5.2",
                    title: "Ensure that Cloud Storage buckets have uniform bucket-level access and public access prevention enabled",
                },
                FrameworkMapping {
                    framework: "AICPA SOC 2 (TSC)",
                    version: "2017/2022",
                    control_id: "CC6.2",
                    title: "Access privileges are authorized and granted using uniform permissions",
                },
                FrameworkMapping {
                    framework: "PCI DSS",
                    version: "4.0.1",
                    control_id: "7.2.1",
                    title: "Access is defined based on job function and least privilege",
                },
                FrameworkMapping {
                    framework: "HIPAA Security Rule",
                    version: "45 CFR Part 164",
                    control_id: "164.308(a)(4)",
                    title: "Information access management isolating administrative roles",
                },
            ],
            "gcp-storage-encryption-logging-retention" => vec![
                FrameworkMapping {
                    framework: "CIS Google Cloud Platform Foundation Benchmark",
                    version: "3.0.0",
                    control_id: "5.3",
                    title: "Ensure that Cloud Storage buckets are encrypted with Customer-Managed Encryption Keys (CMEK) and logged",
                },
                FrameworkMapping {
                    framework: "AICPA SOC 2 (TSC)",
                    version: "2017/2022",
                    control_id: "CC6.1",
                    title: "Data encryption at rest using customer-controlled keys",
                },
                FrameworkMapping {
                    framework: "PCI DSS",
                    version: "4.0.1",
                    control_id: "3.5.1",
                    title: "Cryptographic keys are protected and isolated through secure perimeters",
                },
                FrameworkMapping {
                    framework: "HIPAA Security Rule",
                    version: "45 CFR Part 164",
                    control_id: "164.312(a)(2)(iv)",
                    title: "Encryption and decryption of electronic protected health information",
                },
            ],

            // Compute Engine & VPC
            "gcp-compute-firewall-no-open-admin-or-db-ports" => vec![
                FrameworkMapping {
                    framework: "CIS Google Cloud Platform Foundation Benchmark",
                    version: "3.0.0",
                    control_id: "3.6",
                    title: "Ensure that SSH is restricted from the internet (0.0.0.0/0)",
                },
                FrameworkMapping {
                    framework: "CIS Google Cloud Platform Foundation Benchmark",
                    version: "3.0.0",
                    control_id: "3.7",
                    title: "Ensure that RDP is restricted from the internet (0.0.0.0/0)",
                },
                FrameworkMapping {
                    framework: "AICPA SOC 2 (TSC)",
                    version: "2017/2022",
                    control_id: "CC6.6",
                    title: "Network boundaries and security perimeters restrict untrusted traffic",
                },
                FrameworkMapping {
                    framework: "PCI DSS",
                    version: "4.0.1",
                    control_id: "1.3.1",
                    title: "Inbound traffic from untrusted networks is filtered and administrative protocols restricted",
                },
                FrameworkMapping {
                    framework: "HIPAA Security Rule",
                    version: "45 CFR Part 164",
                    control_id: "164.312(a)(1)",
                    title: "Access controls blocking unauthorized internet network communication",
                },
            ],
            "gcp-compute-firewall-target-logging-and-default-network" => vec![
                FrameworkMapping {
                    framework: "CIS Google Cloud Platform Foundation Benchmark",
                    version: "3.0.0",
                    control_id: "3.1",
                    title: "Ensure that the legacy default network does not exist in a project",
                },
                FrameworkMapping {
                    framework: "CIS Google Cloud Platform Foundation Benchmark",
                    version: "3.0.0",
                    control_id: "3.9",
                    title: "Ensure that VPC Flow Logs and Firewall Rules Logging is enabled",
                },
                FrameworkMapping {
                    framework: "AICPA SOC 2 (TSC)",
                    version: "2017/2022",
                    control_id: "CC7.2",
                    title: "System monitoring and network traffic logging",
                },
                FrameworkMapping {
                    framework: "PCI DSS",
                    version: "4.0.1",
                    control_id: "1.2.7",
                    title: "Network firewall rule sets are monitored and scoped to explicit targets",
                },
                FrameworkMapping {
                    framework: "HIPAA Security Rule",
                    version: "45 CFR Part 164",
                    control_id: "164.312(b)",
                    title: "Audit controls recording examination of activity in information systems",
                },
            ],
            "gcp-compute-no-unattached-or-direct-external-ips" => vec![
                FrameworkMapping {
                    framework: "CIS Google Cloud Platform Foundation Benchmark",
                    version: "3.0.0",
                    control_id: "4.3",
                    title: "Ensure that Compute instances do not have public IP addresses",
                },
                FrameworkMapping {
                    framework: "AICPA SOC 2 (TSC)",
                    version: "2017/2022",
                    control_id: "CC6.6",
                    title: "Perimeter defense and isolation of internal infrastructure",
                },
                FrameworkMapping {
                    framework: "PCI DSS",
                    version: "4.0.1",
                    control_id: "1.3.2",
                    title: "Direct public access to internal system components is prohibited",
                },
                FrameworkMapping {
                    framework: "HIPAA Security Rule",
                    version: "45 CFR Part 164",
                    control_id: "164.312(a)(1)",
                    title: "Access control shielding internal health data repositories",
                },
            ],

            // Cloud SQL
            "gcp-sql-no-public-ip-and-authorized-networks" => vec![
                FrameworkMapping {
                    framework: "CIS Google Cloud Platform Foundation Benchmark",
                    version: "3.0.0",
                    control_id: "6.5",
                    title: "Ensure that Cloud SQL instances are not configured to use public IP addresses or unrestricted networks",
                },
                FrameworkMapping {
                    framework: "AICPA SOC 2 (TSC)",
                    version: "2017/2022",
                    control_id: "CC6.6",
                    title: "Database perimeters are isolated from untrusted networks",
                },
                FrameworkMapping {
                    framework: "PCI DSS",
                    version: "4.0.1",
                    control_id: "1.3.1",
                    title: "Databases are not directly accessible from untrusted networks",
                },
                FrameworkMapping {
                    framework: "HIPAA Security Rule",
                    version: "45 CFR Part 164",
                    control_id: "164.312(a)(1)",
                    title: "Database access controls restricting internet-based access",
                },
            ],
            "gcp-sql-backup-cmek-and-flags" => vec![
                FrameworkMapping {
                    framework: "CIS Google Cloud Platform Foundation Benchmark",
                    version: "3.0.0",
                    control_id: "6.7",
                    title: "Ensure that Cloud SQL database instances have automated backups and point-in-time recovery enabled",
                },
                FrameworkMapping {
                    framework: "CIS Google Cloud Platform Foundation Benchmark",
                    version: "3.0.0",
                    control_id: "6.8",
                    title: "Ensure that Cloud SQL database instances are encrypted with Customer-Managed Encryption Key (CMEK)",
                },
                FrameworkMapping {
                    framework: "AICPA SOC 2 (TSC)",
                    version: "2017/2022",
                    control_id: "A1.2",
                    title: "Data backup, replication, and recovery procedures ensure availability",
                },
                FrameworkMapping {
                    framework: "PCI DSS",
                    version: "4.0.1",
                    control_id: "3.5.1",
                    title: "Database encryption keys are customer-controlled and protected",
                },
                FrameworkMapping {
                    framework: "HIPAA Security Rule",
                    version: "45 CFR Part 164",
                    control_id: "164.308(a)(7)(ii)(A)",
                    title: "Data backup plan to create and maintain retrievable exact copies of EPHI",
                },
            ],

            // IAM & Audit Logging
            "gcp-iam-no-primitive-roles-and-wildcard-custom-roles" => vec![
                FrameworkMapping {
                    framework: "CIS Google Cloud Platform Foundation Benchmark",
                    version: "3.0.0",
                    control_id: "1.4",
                    title: "Ensure that primitive roles are not used at project level for IAM users",
                },
                FrameworkMapping {
                    framework: "AICPA SOC 2 (TSC)",
                    version: "2017/2022",
                    control_id: "CC6.3",
                    title: "Access privileges are authorized and granted using least privilege principle",
                },
                FrameworkMapping {
                    framework: "PCI DSS",
                    version: "4.0.1",
                    control_id: "7.2.2",
                    title: "Access is assigned based on least privilege and explicit authorization",
                },
                FrameworkMapping {
                    framework: "HIPAA Security Rule",
                    version: "45 CFR Part 164",
                    control_id: "164.308(a)(3)(ii)(A)",
                    title: "Authorization and supervision of workforce members",
                },
            ],
            "gcp-iam-no-public-principals-and-stale-keys" => vec![
                FrameworkMapping {
                    framework: "CIS Google Cloud Platform Foundation Benchmark",
                    version: "3.0.0",
                    control_id: "1.7",
                    title: "Ensure that Service Account Keys are rotated every 90 days or less and impersonation is restricted",
                },
                FrameworkMapping {
                    framework: "AICPA SOC 2 (TSC)",
                    version: "2017/2022",
                    control_id: "CC6.1",
                    title: "Authentication credentials and keys are periodically rotated",
                },
                FrameworkMapping {
                    framework: "PCI DSS",
                    version: "4.0.1",
                    control_id: "8.3.6",
                    title: "Service account passwords and cryptographic tokens are securely managed and rotated",
                },
                FrameworkMapping {
                    framework: "HIPAA Security Rule",
                    version: "45 CFR Part 164",
                    control_id: "164.312(d)",
                    title: "Person or entity authentication verifying claiming identity",
                },
            ],
            "gcp-logging-data-access-audit-and-sinks" => vec![
                FrameworkMapping {
                    framework: "CIS Google Cloud Platform Foundation Benchmark",
                    version: "3.0.0",
                    control_id: "2.1",
                    title: "Ensure that Cloud Audit Logging is configured properly across all services and log sinks are active",
                },
                FrameworkMapping {
                    framework: "AICPA SOC 2 (TSC)",
                    version: "2017/2022",
                    control_id: "CC7.2",
                    title: "System monitoring and audit logging for security events",
                },
                FrameworkMapping {
                    framework: "PCI DSS",
                    version: "4.0.1",
                    control_id: "10.2.1",
                    title: "Audit logs are enabled and capture all actions taken by administrative users",
                },
                FrameworkMapping {
                    framework: "HIPAA Security Rule",
                    version: "45 CFR Part 164",
                    control_id: "164.312(b)",
                    title: "Audit controls to record and examine activity in information systems",
                },
            ],

            _ => Vec::new(),
        }
    }
}
