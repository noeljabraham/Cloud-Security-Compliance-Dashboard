use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FrameworkMapping {
    pub framework: &'static str,
    pub version: &'static str,
    pub control_id: &'static str,
    pub title: &'static str,
}

pub struct CheckFrameworkMappings;

impl CheckFrameworkMappings {
    pub fn get_mappings(check_id: &str) -> Vec<FrameworkMapping> {
        match check_id {
            // S3 Checks
            "aws-s3-block-public-access" => vec![
                FrameworkMapping {
                    framework: "CIS Amazon Web Services Foundations Benchmark",
                    version: "7.1.0",
                    control_id: "2.1.1",
                    title: "Ensure S3 Bucket Public Access Block is enabled at the bucket level",
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
            "aws-s3-bucket-policy-public-access" => vec![
                FrameworkMapping {
                    framework: "CIS Amazon Web Services Foundations Benchmark",
                    version: "7.1.0",
                    control_id: "2.1.2",
                    title: "Ensure S3 bucket policies do not grant public access",
                },
                FrameworkMapping {
                    framework: "AICPA SOC 2 (TSC)",
                    version: "2017/2022",
                    control_id: "CC6.1",
                    title: "Boundary protection and access restriction",
                },
                FrameworkMapping {
                    framework: "PCI DSS",
                    version: "4.0.1",
                    control_id: "1.3.1",
                    title: "Restrict direct public access to internal cardholder data stores",
                },
            ],
            "aws-s3-default-encryption" => vec![
                FrameworkMapping {
                    framework: "CIS Amazon Web Services Foundations Benchmark",
                    version: "7.1.0",
                    control_id: "2.1.3",
                    title: "Ensure S3 default encryption is enabled with KMS or AES256",
                },
                FrameworkMapping {
                    framework: "AICPA SOC 2 (TSC)",
                    version: "2017/2022",
                    control_id: "CC6.6",
                    title: "Encryption of data at rest",
                },
                FrameworkMapping {
                    framework: "PCI DSS",
                    version: "4.0.1",
                    control_id: "3.4",
                    title: "Protect stored cardholder data with strong cryptography",
                },
                FrameworkMapping {
                    framework: "HIPAA Security Rule",
                    version: "45 CFR Part 164",
                    control_id: "164.312(a)(2)(iv)",
                    title: "Encryption and decryption of ePHI at rest",
                },
            ],
            "aws-s3-access-logging" => vec![
                FrameworkMapping {
                    framework: "CIS Amazon Web Services Foundations Benchmark",
                    version: "7.1.0",
                    control_id: "2.1.4",
                    title: "Ensure S3 bucket access logging is enabled",
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
                    control_id: "10.2",
                    title: "Audit logs capture all administrative and data access actions",
                },
            ],
            "aws-s3-bucket-versioning" => vec![
                FrameworkMapping {
                    framework: "CIS Amazon Web Services Foundations Benchmark",
                    version: "7.1.0",
                    control_id: "2.1.5",
                    title: "Ensure S3 bucket versioning is enabled for durability",
                },
                FrameworkMapping {
                    framework: "AICPA SOC 2 (TSC)",
                    version: "2017/2022",
                    control_id: "A1.2",
                    title: "Data backup, replication, and disaster recovery procedures",
                },
            ],

            // IAM Checks
            "aws-iam-root-mfa-and-keys" => vec![
                FrameworkMapping {
                    framework: "CIS Amazon Web Services Foundations Benchmark",
                    version: "7.1.0",
                    control_id: "1.1.1",
                    title: "Ensure root user MFA is enabled and root access keys are eliminated",
                },
                FrameworkMapping {
                    framework: "AICPA SOC 2 (TSC)",
                    version: "2017/2022",
                    control_id: "CC6.1",
                    title: "Privileged account protection and credential isolation",
                },
                FrameworkMapping {
                    framework: "PCI DSS",
                    version: "4.0.1",
                    control_id: "8.3",
                    title: "Multi-factor authentication for all administrative accounts",
                },
            ],
            "aws-iam-user-mfa-enabled" => vec![
                FrameworkMapping {
                    framework: "CIS Amazon Web Services Foundations Benchmark",
                    version: "7.1.0",
                    control_id: "1.1.2",
                    title: "Ensure MFA is enabled for all IAM users with a console password",
                },
                FrameworkMapping {
                    framework: "AICPA SOC 2 (TSC)",
                    version: "2017/2022",
                    control_id: "CC6.1",
                    title: "MFA enforcement for human interactive access",
                },
            ],
            "aws-iam-password-policy" => vec![
                FrameworkMapping {
                    framework: "CIS Amazon Web Services Foundations Benchmark",
                    version: "7.1.0",
                    control_id: "1.1.3",
                    title: "Ensure IAM password policy meets complexity and length requirements",
                },
                FrameworkMapping {
                    framework: "PCI DSS",
                    version: "4.0.1",
                    control_id: "8.3.6",
                    title: "Enforce strong password complexity and length",
                },
            ],
            "aws-iam-old-access-keys" => vec![
                FrameworkMapping {
                    framework: "CIS Amazon Web Services Foundations Benchmark",
                    version: "7.1.0",
                    control_id: "1.1.4",
                    title: "Ensure access keys are rotated every 90 days or less",
                },
                FrameworkMapping {
                    framework: "PCI DSS",
                    version: "4.0.1",
                    control_id: "8.3.9",
                    title: "Periodic credential rotation and expiration",
                },
            ],
            "aws-iam-inactive-users" => vec![
                FrameworkMapping {
                    framework: "CIS Amazon Web Services Foundations Benchmark",
                    version: "7.1.0",
                    control_id: "1.1.5",
                    title: "Ensure credentials unused for 90 days or more are disabled",
                },
                FrameworkMapping {
                    framework: "AICPA SOC 2 (TSC)",
                    version: "2017/2022",
                    control_id: "CC6.2",
                    title: "Revocation of dormant or unused user credentials",
                },
            ],
            "aws-iam-no-wildcard-admin-policies" => vec![
                FrameworkMapping {
                    framework: "CIS Amazon Web Services Foundations Benchmark",
                    version: "7.1.0",
                    control_id: "1.1.6",
                    title: "Ensure IAM policies do not grant full wildcard administrative access",
                },
                FrameworkMapping {
                    framework: "AICPA SOC 2 (TSC)",
                    version: "2017/2022",
                    control_id: "CC6.1",
                    title: "Principle of least privilege and separation of duties",
                },
                FrameworkMapping {
                    framework: "PCI DSS",
                    version: "4.0.1",
                    control_id: "7.1",
                    title: "Limit access to system components to only those individuals whose jobs require it",
                },
            ],
            "aws-iam-role-trust-policy" => vec![
                FrameworkMapping {
                    framework: "CIS Amazon Web Services Foundations Benchmark",
                    version: "7.1.0",
                    control_id: "1.1.7",
                    title: "Ensure IAM role trust policies restrict cross-account access and specify conditions",
                },
                FrameworkMapping {
                    framework: "AICPA SOC 2 (TSC)",
                    version: "2017/2022",
                    control_id: "CC6.1",
                    title: "Federation and external trust boundary controls",
                },
            ],

            // EC2 & VPC Checks
            "aws-ec2-sg-no-open-admin-ports" => vec![
                FrameworkMapping {
                    framework: "CIS Amazon Web Services Foundations Benchmark",
                    version: "7.1.0",
                    control_id: "5.1.1",
                    title: "Ensure no security groups allow ingress from 0.0.0.0/0 to administrative ports",
                },
                FrameworkMapping {
                    framework: "PCI DSS",
                    version: "4.0.1",
                    control_id: "1.3.1",
                    title: "Inbound traffic restricted to authorized protocols; block open administrative ports",
                },
                FrameworkMapping {
                    framework: "HIPAA Security Rule",
                    version: "45 CFR Part 164",
                    control_id: "164.312(e)(1)",
                    title: "Transmission security and external boundary protection",
                },
            ],
            "aws-ec2-sg-unrestricted-traffic" => vec![
                FrameworkMapping {
                    framework: "CIS Amazon Web Services Foundations Benchmark",
                    version: "7.1.0",
                    control_id: "5.1.2",
                    title: "Ensure security groups do not allow all-traffic ingress from the internet",
                },
                FrameworkMapping {
                    framework: "AICPA SOC 2 (TSC)",
                    version: "2017/2022",
                    control_id: "CC6.6",
                    title: "Network boundary filtering and segmentation",
                },
            ],
            "aws-ec2-sg-unused" => vec![
                FrameworkMapping {
                    framework: "CIS Amazon Web Services Foundations Benchmark",
                    version: "7.1.0",
                    control_id: "5.1.3",
                    title: "Identify and review unused security groups",
                },
                FrameworkMapping {
                    framework: "PCI DSS",
                    version: "4.0.1",
                    control_id: "1.2.2",
                    title: "Review configuration rules periodically to remove obsolete entries",
                },
            ],
            "aws-ec2-imdsv2-enforced" => vec![
                FrameworkMapping {
                    framework: "CIS Amazon Web Services Foundations Benchmark",
                    version: "7.1.0",
                    control_id: "5.1.4",
                    title: "Ensure IMDSv2 is enforced on all EC2 instances",
                },
                FrameworkMapping {
                    framework: "AICPA SOC 2 (TSC)",
                    version: "2017/2022",
                    control_id: "CC6.1",
                    title: "Defense in depth against SSRF credential theft",
                },
            ],
            "aws-ec2-ebs-encryption-enabled" => vec![
                FrameworkMapping {
                    framework: "CIS Amazon Web Services Foundations Benchmark",
                    version: "7.1.0",
                    control_id: "5.1.5",
                    title: "Ensure EBS volume encryption is enabled by default in all regions",
                },
                FrameworkMapping {
                    framework: "PCI DSS",
                    version: "4.0.1",
                    control_id: "3.4",
                    title: "Render primary storage cryptographic protection mandatory",
                },
            ],
            "aws-vpc-flow-logs-enabled" => vec![
                FrameworkMapping {
                    framework: "CIS Amazon Web Services Foundations Benchmark",
                    version: "7.1.0",
                    control_id: "5.1.6",
                    title: "Ensure VPC flow logging is enabled in all VPCs",
                },
                FrameworkMapping {
                    framework: "AICPA SOC 2 (TSC)",
                    version: "2017/2022",
                    control_id: "CC7.2",
                    title: "Network traffic monitoring and anomaly detection",
                },
                FrameworkMapping {
                    framework: "PCI DSS",
                    version: "4.0.1",
                    control_id: "10.2.1",
                    title: "Audit logs record all network access",
                },
            ],
            "aws-ec2-default-sg-restricts-all" => vec![
                FrameworkMapping {
                    framework: "CIS Amazon Web Services Foundations Benchmark",
                    version: "7.1.0",
                    control_id: "5.1.7",
                    title: "Ensure default security group of every VPC restricts all traffic",
                },
                FrameworkMapping {
                    framework: "AICPA SOC 2 (TSC)",
                    version: "2017/2022",
                    control_id: "CC6.6",
                    title: "Secure baseline default configuration",
                },
            ],
            "aws-ec2-unattached-elastic-ip" => vec![
                FrameworkMapping {
                    framework: "CIS Amazon Web Services Foundations Benchmark",
                    version: "7.1.0",
                    control_id: "5.1.8",
                    title: "Identify unattached Elastic IP addresses for cost and exposure optimization",
                },
                FrameworkMapping {
                    framework: "AICPA SOC 2 (TSC)",
                    version: "2017/2022",
                    control_id: "A1.2",
                    title: "Asset management and resource efficiency",
                },
            ],

            // RDS Checks
            "aws-rds-public-access-disabled" => vec![
                FrameworkMapping {
                    framework: "CIS Amazon Web Services Foundations Benchmark",
                    version: "7.1.0",
                    control_id: "4.1.1",
                    title: "Ensure RDS database instances are not publicly accessible",
                },
                FrameworkMapping {
                    framework: "PCI DSS",
                    version: "4.0.1",
                    control_id: "1.3.1",
                    title: "Prohibit direct public internet access to database systems",
                },
                FrameworkMapping {
                    framework: "HIPAA Security Rule",
                    version: "45 CFR Part 164",
                    control_id: "164.312(a)(1)",
                    title: "Restrict direct access to clinical and ePHI database repositories",
                },
            ],
            "aws-rds-storage-encrypted" => vec![
                FrameworkMapping {
                    framework: "CIS Amazon Web Services Foundations Benchmark",
                    version: "7.1.0",
                    control_id: "4.1.2",
                    title: "Ensure RDS storage is encrypted at rest using KMS",
                },
                FrameworkMapping {
                    framework: "PCI DSS",
                    version: "4.0.1",
                    control_id: "3.4",
                    title: "Database storage encryption using approved keys",
                },
            ],
            "aws-rds-backup-and-deletion-protection" => vec![
                FrameworkMapping {
                    framework: "CIS Amazon Web Services Foundations Benchmark",
                    version: "7.1.0",
                    control_id: "4.1.3",
                    title: "Ensure RDS automated backups and deletion protection are enabled",
                },
                FrameworkMapping {
                    framework: "AICPA SOC 2 (TSC)",
                    version: "2017/2022",
                    control_id: "A1.2",
                    title: "Data recovery and resilience against accidental deletion",
                },
            ],
            "aws-rds-enhanced-logging" => vec![
                FrameworkMapping {
                    framework: "CIS Amazon Web Services Foundations Benchmark",
                    version: "7.1.0",
                    control_id: "4.1.4",
                    title: "Ensure RDS database logging is exported to CloudWatch Logs",
                },
                FrameworkMapping {
                    framework: "PCI DSS",
                    version: "4.0.1",
                    control_id: "10.2",
                    title: "Database audit logs captured and monitored",
                },
            ],

            // CloudTrail Checks
            "aws-cloudtrail-multi-region-trail" => vec![
                FrameworkMapping {
                    framework: "CIS Amazon Web Services Foundations Benchmark",
                    version: "7.1.0",
                    control_id: "3.1.1",
                    title: "Ensure a multi-region CloudTrail is enabled and active in all regions",
                },
                FrameworkMapping {
                    framework: "AICPA SOC 2 (TSC)",
                    version: "2017/2022",
                    control_id: "CC7.2",
                    title: "Continuous audit logging of all API activities",
                },
                FrameworkMapping {
                    framework: "PCI DSS",
                    version: "4.0.1",
                    control_id: "10.1",
                    title: "Implement audit trails to link all access to system components",
                },
            ],
            "aws-cloudtrail-log-validation-and-encryption" => vec![
                FrameworkMapping {
                    framework: "CIS Amazon Web Services Foundations Benchmark",
                    version: "7.1.0",
                    control_id: "3.1.2",
                    title: "Ensure CloudTrail log file validation and KMS encryption are enabled",
                },
                FrameworkMapping {
                    framework: "PCI DSS",
                    version: "4.0.1",
                    control_id: "10.5",
                    title: "Secure audit trail records from tampering or alteration",
                },
            ],
            "aws-cloudtrail-cloudwatch-logs" => vec![
                FrameworkMapping {
                    framework: "CIS Amazon Web Services Foundations Benchmark",
                    version: "7.1.0",
                    control_id: "3.1.3",
                    title: "Ensure CloudTrail trails are integrated with CloudWatch Logs",
                },
                FrameworkMapping {
                    framework: "AICPA SOC 2 (TSC)",
                    version: "2017/2022",
                    control_id: "CC7.2",
                    title: "Real-time alerting on security events",
                },
            ],

            // Lambda Checks
            "aws-lambda-execution-role-least-privilege" => vec![
                FrameworkMapping {
                    framework: "CIS Amazon Web Services Foundations Benchmark",
                    version: "7.1.0",
                    control_id: "6.1.1",
                    title: "Ensure Lambda function execution roles adhere to least privilege",
                },
                FrameworkMapping {
                    framework: "AICPA SOC 2 (TSC)",
                    version: "2017/2022",
                    control_id: "CC6.1",
                    title: "Serverless execution identity confinement",
                },
            ],
            "aws-lambda-no-public-urls" => vec![
                FrameworkMapping {
                    framework: "CIS Amazon Web Services Foundations Benchmark",
                    version: "7.1.0",
                    control_id: "6.1.2",
                    title: "Ensure Lambda function URLs require IAM authentication",
                },
                FrameworkMapping {
                    framework: "PCI DSS",
                    version: "4.0.1",
                    control_id: "1.3.1",
                    title: "Restrict unauthorized public invocation of cloud serverless endpoints",
                },
            ],
            "aws-lambda-vpc-attachment-policy" => vec![
                FrameworkMapping {
                    framework: "CIS Amazon Web Services Foundations Benchmark",
                    version: "7.1.0",
                    control_id: "6.1.3",
                    title: "Ensure Lambda functions accessing private resources are attached to a VPC",
                },
                FrameworkMapping {
                    framework: "AICPA SOC 2 (TSC)",
                    version: "2017/2022",
                    control_id: "CC6.6",
                    title: "Network boundary and segmentation for serverless functions",
                },
            ],
            "aws-lambda-runtime-and-encryption" => vec![
                FrameworkMapping {
                    framework: "CIS Amazon Web Services Foundations Benchmark",
                    version: "7.1.0",
                    control_id: "6.1.4",
                    title: "Ensure Lambda runtimes are supported and environment variables are encrypted",
                },
                FrameworkMapping {
                    framework: "PCI DSS",
                    version: "4.0.1",
                    control_id: "6.2",
                    title: "Maintain software on supported versions with security patches",
                },
            ],

            _ => Vec::new(),
        }
    }
}
