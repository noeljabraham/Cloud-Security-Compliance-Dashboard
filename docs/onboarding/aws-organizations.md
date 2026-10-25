# AWS Organizations Onboarding Guide

This document describes how to securely onboard multiple AWS accounts across an AWS Organization into the Cloud Security Compliance Dashboard.

## Architecture & Security Model

Production onboarding **strictly forbids** long-lived IAM access keys (`access_key_id` / `secret_access_key`). Instead, access is granted via:
1. Cross-account IAM roles assumed through AWS Security Token Service (`sts:AssumeRole`).
2. Unique, cryptographically secure **External IDs** generated per organization/connection to mitigate the [confused deputy problem](https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html).
3. Least-privilege read-only policies scoped exclusively to compliance and configuration metadata.

## Multi-Account Deployment with CloudFormation StackSets

To onboard all member accounts in your AWS Organization:

1. **Deploy from the Management Account or Delegated Administrator:**
   Navigate to the CloudFormation console in your AWS Organizations management account or delegated administrator account.

2. **Create a StackSet:**
   - Choose `templates/aws/cloudformation-onboarding.yaml` as the template.
   - Enter the `ExternalId` provided by the CloudSec dashboard during connection setup.
   - Set `CloudSecPrincipalArn` to the CloudSec platform IAM principal.

3. **Configure StackSet Options:**
   - Deployment targets: **Deploy to organization** (or select specific Organizational Units / OUs).
   - Automatic deployment: **Enabled** (automatically deploys the role when new accounts join the organization).
   - Region: Select your primary region (e.g., `us-east-1` for IAM resources).

4. **Register Connection in CloudSec Dashboard:**
   - Provider: `AWS`
   - Role Name: `CloudSecSecurityAuditRole`
   - External ID: Enter the configured External ID.
   - Accounts: Specify member account IDs (or allow the scanner to discover active accounts in the target OUs).

## Security Verification

Before accepting scans, CloudSec runs an automated pre-flight check:
- Validates that `sts:AssumeRole` succeeds with the provided External ID.
- Confirms the caller identity matches the specified account.
- Checks that required read actions (`s3:GetBucketPublicAccessBlock`, `iam:GetAccountSummary`, `ec2:DescribeSecurityGroups`, `cloudtrail:DescribeTrails`) succeed.
- Logs the onboarding event in the immutable audit log with credentials redacted.

