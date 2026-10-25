use crate::aws::mappings::FrameworkMapping;

pub struct AzureCheckFrameworkMappings;

impl AzureCheckFrameworkMappings {
    pub fn get_mappings(check_id: &str) -> Vec<FrameworkMapping> {
        match check_id {
            // Storage Accounts
            "azure-storage-public-access" => vec![
                FrameworkMapping {
                    framework: "CIS Microsoft Azure Foundations Benchmark",
                    version: "3.0.0",
                    control_id: "3.7",
                    title: "Ensure that 'Public access level' is set to Disabled for storage accounts",
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
            "azure-storage-secure-transfer-and-tls" => vec![
                FrameworkMapping {
                    framework: "CIS Microsoft Azure Foundations Benchmark",
                    version: "3.0.0",
                    control_id: "3.1",
                    title: "Ensure that 'Secure transfer required' is set to 'Enabled'",
                },
                FrameworkMapping {
                    framework: "CIS Microsoft Azure Foundations Benchmark",
                    version: "3.0.0",
                    control_id: "3.15",
                    title: "Ensure 'Minimum TLS version' is set to 'Version 1.2'",
                },
                FrameworkMapping {
                    framework: "AICPA SOC 2 (TSC)",
                    version: "2017/2022",
                    control_id: "CC6.7",
                    title: "Data in transit is protected using cryptographic protocols",
                },
                FrameworkMapping {
                    framework: "PCI DSS",
                    version: "4.0.1",
                    control_id: "4.1.2",
                    title: "Strong cryptography and security protocols safeguard data in transit",
                },
                FrameworkMapping {
                    framework: "HIPAA Security Rule",
                    version: "45 CFR Part 164",
                    control_id: "164.312(e)(1)",
                    title: "Transmission security to guard against unauthorized access",
                },
            ],
            "azure-storage-cmk-encryption" => vec![
                FrameworkMapping {
                    framework: "CIS Microsoft Azure Foundations Benchmark",
                    version: "3.0.0",
                    control_id: "3.10",
                    title: "Ensure Storage for Critical Data are Encrypted with Customer Managed Key",
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
                    title: "Keys used for encryption of cardholder data are protected against disclosure",
                },
                FrameworkMapping {
                    framework: "HIPAA Security Rule",
                    version: "45 CFR Part 164",
                    control_id: "164.312(a)(2)(iv)",
                    title: "Encryption and decryption of electronic protected health information",
                },
            ],
            "azure-storage-logging-and-retention" => vec![
                FrameworkMapping {
                    framework: "CIS Microsoft Azure Foundations Benchmark",
                    version: "3.0.0",
                    control_id: "5.1.1",
                    title: "Ensure Storage Logging is Enabled for Read, Write, and Delete Requests",
                },
                FrameworkMapping {
                    framework: "AICPA SOC 2 (TSC)",
                    version: "2017/2022",
                    control_id: "CC7.2",
                    title: "System monitoring and audit logging",
                },
                FrameworkMapping {
                    framework: "PCI DSS",
                    version: "4.0.1",
                    control_id: "10.2.1",
                    title: "Audit logs are enabled and active for all access to cardholder data",
                },
                FrameworkMapping {
                    framework: "HIPAA Security Rule",
                    version: "45 CFR Part 164",
                    control_id: "164.312(b)",
                    title: "Mechanisms to record and examine activity in information systems",
                },
            ],

            // RBAC and Microsoft Entra ID
            "azure-rbac-no-direct-user-owner-assignments" => vec![
                FrameworkMapping {
                    framework: "CIS Microsoft Azure Foundations Benchmark",
                    version: "3.0.0",
                    control_id: "1.23",
                    title: "Ensure that No Direct User Assignments Exist for Subscription-Level Owner or Contributor",
                },
                FrameworkMapping {
                    framework: "AICPA SOC 2 (TSC)",
                    version: "2017/2022",
                    control_id: "CC6.2",
                    title: "User access is granted based on role and authorized through procedures",
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
            "azure-rbac-no-wildcard-custom-roles" => vec![
                FrameworkMapping {
                    framework: "CIS Microsoft Azure Foundations Benchmark",
                    version: "3.0.0",
                    control_id: "1.24",
                    title: "Ensure that Custom Subscription Owner Roles Do Not Exist with Wildcard Actions",
                },
                FrameworkMapping {
                    framework: "AICPA SOC 2 (TSC)",
                    version: "2017/2022",
                    control_id: "CC6.3",
                    title: "Access privileges are authorized and granted using least privilege",
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
            "azure-entra-privileged-role-governance" => vec![
                FrameworkMapping {
                    framework: "CIS Microsoft Azure Foundations Benchmark",
                    version: "3.0.0",
                    control_id: "1.1.1",
                    title: "Ensure Multi-Factor Authentication is Enabled for All Privileged Users in Microsoft Entra ID",
                },
                FrameworkMapping {
                    framework: "CIS Microsoft Azure Foundations Benchmark",
                    version: "3.0.0",
                    control_id: "1.1.3",
                    title: "Ensure Guest Users Have Restricted Directory Access",
                },
                FrameworkMapping {
                    framework: "AICPA SOC 2 (TSC)",
                    version: "2017/2022",
                    control_id: "CC6.1",
                    title: "Authentication mechanisms require multi-factor authentication for administrative access",
                },
                FrameworkMapping {
                    framework: "PCI DSS",
                    version: "4.0.1",
                    control_id: "8.4.2",
                    title: "Multi-factor authentication is implemented for all administrative access",
                },
                FrameworkMapping {
                    framework: "HIPAA Security Rule",
                    version: "45 CFR Part 164",
                    control_id: "164.312(d)",
                    title: "Person or entity authentication verifying claiming identity",
                },
            ],
            "azure-entra-identity-coverage" => vec![
                FrameworkMapping {
                    framework: "CIS Microsoft Azure Foundations Benchmark",
                    version: "3.0.0",
                    control_id: "1.1",
                    title: "Microsoft Entra ID Security and Governance Assessment Coverage",
                },
                FrameworkMapping {
                    framework: "AICPA SOC 2 (TSC)",
                    version: "2017/2022",
                    control_id: "CC6.1",
                    title: "Completeness of access control evaluation and audit evidence",
                },
                FrameworkMapping {
                    framework: "PCI DSS",
                    version: "4.0.1",
                    control_id: "12.1.1",
                    title: "Overall security policy and assessment coverage across cloud assets",
                },
                FrameworkMapping {
                    framework: "HIPAA Security Rule",
                    version: "45 CFR Part 164",
                    control_id: "164.308(a)(1)(ii)(A)",
                    title: "Risk analysis assessing vulnerabilities and gaps in technical controls",
                },
            ],

            // Network Security Groups
            "azure-nsg-no-open-admin-or-db-ports" => vec![
                FrameworkMapping {
                    framework: "CIS Microsoft Azure Foundations Benchmark",
                    version: "3.0.0",
                    control_id: "6.1",
                    title: "Ensure that RDP access is restricted from the internet",
                },
                FrameworkMapping {
                    framework: "CIS Microsoft Azure Foundations Benchmark",
                    version: "3.0.0",
                    control_id: "6.2",
                    title: "Ensure that SSH access is restricted from the internet",
                },
                FrameworkMapping {
                    framework: "CIS Microsoft Azure Foundations Benchmark",
                    version: "3.0.0",
                    control_id: "6.4",
                    title: "Ensure that Database access is restricted from the internet",
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
            "azure-nsg-no-broad-ranges-or-stale-rules" => vec![
                FrameworkMapping {
                    framework: "CIS Microsoft Azure Foundations Benchmark",
                    version: "3.0.0",
                    control_id: "6.5",
                    title: "Ensure Network Security Groups do not contain catch-all unrestricted allow rules or stale configurations",
                },
                FrameworkMapping {
                    framework: "AICPA SOC 2 (TSC)",
                    version: "2017/2022",
                    control_id: "CC6.6",
                    title: "Network security configuration is periodically reviewed for obsolete rules",
                },
                FrameworkMapping {
                    framework: "PCI DSS",
                    version: "4.0.1",
                    control_id: "1.2.7",
                    title: "Firewall rule sets are reviewed periodically to purge stale rules",
                },
                FrameworkMapping {
                    framework: "HIPAA Security Rule",
                    version: "45 CFR Part 164",
                    control_id: "164.308(a)(1)(ii)(B)",
                    title: "Risk management implementing security measures to reduce risks and cleanup stale exposure",
                },
            ],

            // Key Vault
            "azure-keyvault-network-and-rbac" => vec![
                FrameworkMapping {
                    framework: "CIS Microsoft Azure Foundations Benchmark",
                    version: "3.0.0",
                    control_id: "8.5",
                    title: "Ensure that the Key Vault Network Rule Set Restricts Access to Allowed Networks and Private Endpoints",
                },
                FrameworkMapping {
                    framework: "CIS Microsoft Azure Foundations Benchmark",
                    version: "3.0.0",
                    control_id: "8.6",
                    title: "Ensure that Key Vault Uses Azure RBAC for Access Control",
                },
                FrameworkMapping {
                    framework: "AICPA SOC 2 (TSC)",
                    version: "2017/2022",
                    control_id: "CC6.1",
                    title: "Logical access controls protect cryptographic vaults and keys",
                },
                FrameworkMapping {
                    framework: "PCI DSS",
                    version: "4.0.1",
                    control_id: "3.5.1",
                    title: "Cryptographic keys are protected and isolated through secure role-based perimeters",
                },
                FrameworkMapping {
                    framework: "HIPAA Security Rule",
                    version: "45 CFR Part 164",
                    control_id: "164.312(a)(1)",
                    title: "Access controls preventing unauthorized disclosure of cryptographic keys",
                },
            ],
            "azure-keyvault-protection-and-expiration" => vec![
                FrameworkMapping {
                    framework: "CIS Microsoft Azure Foundations Benchmark",
                    version: "3.0.0",
                    control_id: "8.1",
                    title: "Ensure that Key Vault has Soft Delete and Purge Protection Enabled",
                },
                FrameworkMapping {
                    framework: "CIS Microsoft Azure Foundations Benchmark",
                    version: "3.0.0",
                    control_id: "8.2",
                    title: "Ensure that Key Vault Keys and Secrets have Expiration Dates Set",
                },
                FrameworkMapping {
                    framework: "AICPA SOC 2 (TSC)",
                    version: "2017/2022",
                    control_id: "CC6.7",
                    title: "Key lifecycle management enforces expiration and cryptographic preservation",
                },
                FrameworkMapping {
                    framework: "PCI DSS",
                    version: "4.0.1",
                    control_id: "3.6.1",
                    title: "Key lifecycle management includes defined cryptoperiods, expiration, and prevention of premature deletion",
                },
                FrameworkMapping {
                    framework: "HIPAA Security Rule",
                    version: "45 CFR Part 164",
                    control_id: "164.312(a)(2)(iv)",
                    title: "Mechanisms to encrypt and decrypt EPHI with controlled key lifecycle",
                },
            ],

            _ => Vec::new(),
        }
    }
}
