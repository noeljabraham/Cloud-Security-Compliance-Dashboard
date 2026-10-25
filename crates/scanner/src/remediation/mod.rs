use cloudsec_domain::{CloudProvider, RemediationEffort, RemediationTemplate};

pub fn sanitize_input(input: &str) -> String {
    input
        .chars()
        .filter(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '.' | ':' | '@'))
        .collect()
}

pub struct RemediationTemplateEngine;

impl RemediationTemplateEngine {
    pub fn all_templates() -> Vec<RemediationTemplate> {
        vec![
            // AWS S3 Public Access
            RemediationTemplate {
                template_id: "rem-aws-s3-public-access-v1".to_string(),
                check_id: "aws-s3-block-public-access".to_string(),
                provider: CloudProvider::Aws,
                resource_type: "aws_s3_bucket".to_string(),
                title: "Enable Amazon S3 Block Public Access".to_string(),
                description: "Enforce S3 Block Public Access settings at bucket and account level to prevent public data exposure.".to_string(),
                effort: RemediationEffort::Low,
                terraform_template: r#"# RECOMMENDATION ONLY - Review and test before applying
resource "aws_s3_bucket_public_access_block" "{{RESOURCE_NAME}}_block" {
  bucket = "{{RESOURCE_NAME}}"

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}"#.to_string(),
                cli_template: "aws s3api put-public-access-block --bucket {{RESOURCE_NAME}} --public-access-block-configuration \"BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true\" --region {{REGION}}".to_string(),
                preventive_policy_example: r#"# AWS Service Control Policy (SCP) to prevent disabling S3 Public Access Block
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyDisablingS3PublicAccessBlock",
      "Effect": "Deny",
      "Action": [
        "s3:DeleteAccountPublicAccessBlock",
        "s3:PutAccountPublicAccessBlock"
      ],
      "Resource": "*"
    }
  ]
}"#.to_string(),
                version: "1.0.0".to_string(),
                requires_approval: true,
            },
            // AWS IAM Root Access Keys
            RemediationTemplate {
                template_id: "rem-aws-iam-root-access-keys-v1".to_string(),
                check_id: "aws-iam-root-no-access-keys".to_string(),
                provider: CloudProvider::Aws,
                resource_type: "aws_iam_root".to_string(),
                title: "Delete AWS Root Account Access Keys".to_string(),
                description: "Root account access keys should be eliminated in favor of IAM roles and temporary credentials.".to_string(),
                effort: RemediationEffort::Low,
                terraform_template: r#"# Root access keys cannot be managed via Terraform.
# Please log in to the AWS Management Console as root and delete all active access keys under My Security Credentials."#.to_string(),
                cli_template: "aws iam delete-access-key --access-key-id {{KEY_ID}} --user-name root".to_string(),
                preventive_policy_example: r#"# AWS SCP: Deny actions using Root credentials
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RestrictRootUser",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringLike": { "aws:PrincipalArn": "arn:aws:iam::*:root" }
      }
    }
  ]
}"#.to_string(),
                version: "1.0.0".to_string(),
                requires_approval: true,
            },
            // AWS S3 Default Encryption
            RemediationTemplate {
                template_id: "rem-aws-s3-default-encryption-v1".to_string(),
                check_id: "aws-s3-default-encryption".to_string(),
                provider: CloudProvider::Aws,
                resource_type: "aws_s3_bucket".to_string(),
                title: "Enable S3 Server-Side Encryption (KMS/AES256)".to_string(),
                description: "Enforce automatic server-side encryption for all objects stored in the bucket.".to_string(),
                effort: RemediationEffort::Low,
                terraform_template: r#"# RECOMMENDATION ONLY - Review and test before applying
resource "aws_s3_bucket_server_side_encryption_configuration" "{{RESOURCE_NAME}}_encryption" {
  bucket = "{{RESOURCE_NAME}}"

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}"#.to_string(),
                cli_template: "aws s3api put-bucket-encryption --bucket {{RESOURCE_NAME}} --server-side-encryption-configuration '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"}}]}' --region {{REGION}}".to_string(),
                preventive_policy_example: r#"# AWS Config Rule: s3-bucket-server-side-encryption-enabled"#.to_string(),
                version: "1.0.0".to_string(),
                requires_approval: true,
            },
            // Azure Storage Public Access
            RemediationTemplate {
                template_id: "rem-azure-storage-public-access-v1".to_string(),
                check_id: "azure-storage-public-access".to_string(),
                provider: CloudProvider::Azure,
                resource_type: "azure_storage_account".to_string(),
                title: "Disable Azure Storage Account Anonymous Access".to_string(),
                description: "Disallow public blob and container access on the storage account.".to_string(),
                effort: RemediationEffort::Low,
                terraform_template: r#"# RECOMMENDATION ONLY - Review and test before applying
resource "azurerm_storage_account" "{{RESOURCE_NAME}}" {
  name                     = "{{RESOURCE_NAME}}"
  resource_group_name      = "{{RESOURCE_GROUP}}"
  allow_nested_items_to_be_public = false
  public_network_access_enabled   = false
}"#.to_string(),
                cli_template: "az storage account update --name {{RESOURCE_NAME}} --resource-group {{RESOURCE_GROUP}} --allow-blob-public-access false --subscription {{SUBSCRIPTION_ID}}".to_string(),
                preventive_policy_example: r#"# Azure Policy Definition
{
  "mode": "Indexed",
  "policyRule": {
    "if": {
      "allOf": [
        { "field": "type", "equals": "Microsoft.Storage/storageAccounts" },
        { "field": "Microsoft.Storage/storageAccounts/allowBlobPublicAccess", "notEquals": "false" }
      ]
    },
    "then": { "effect": "deny" }
  }
}"#.to_string(),
                version: "1.0.0".to_string(),
                requires_approval: true,
            },
            // Azure Storage HTTPS Traffic Only
            RemediationTemplate {
                template_id: "rem-azure-storage-https-only-v1".to_string(),
                check_id: "azure-storage-https-only".to_string(),
                provider: CloudProvider::Azure,
                resource_type: "azure_storage_account".to_string(),
                title: "Enforce HTTPS Only on Azure Storage".to_string(),
                description: "Reject unencrypted HTTP connections to the storage account.".to_string(),
                effort: RemediationEffort::Low,
                terraform_template: r#"# RECOMMENDATION ONLY - Review and test before applying
resource "azurerm_storage_account" "{{RESOURCE_NAME}}" {
  name                     = "{{RESOURCE_NAME}}"
  enable_https_traffic_only = true
  min_tls_version          = "TLS1_2"
}"#.to_string(),
                cli_template: "az storage account update --name {{RESOURCE_NAME}} --resource-group {{RESOURCE_GROUP}} --https-only true --min-tls-version TLS1_2 --subscription {{SUBSCRIPTION_ID}}".to_string(),
                preventive_policy_example: r#"# Azure Policy: Secure transfer to storage accounts should be enabled"#.to_string(),
                version: "1.0.0".to_string(),
                requires_approval: true,
            },
            // GCP Storage Public IAM Bindings
            RemediationTemplate {
                template_id: "rem-gcp-storage-no-public-iam-v1".to_string(),
                check_id: "gcp-storage-no-public-iam-bindings".to_string(),
                provider: CloudProvider::Gcp,
                resource_type: "gcp_storage_bucket".to_string(),
                title: "Remove Public IAM Bindings from GCP Cloud Storage Bucket".to_string(),
                description: "Revoke allUsers and allAuthenticatedUsers roles from the bucket IAM policy.".to_string(),
                effort: RemediationEffort::Low,
                terraform_template: r#"# RECOMMENDATION ONLY - Review and test before applying
resource "google_storage_bucket_iam_binding" "{{RESOURCE_NAME}}_binding" {
  bucket = "{{RESOURCE_NAME}}"
  role   = "roles/storage.objectViewer"
  members = [
    # Explicitly specify authorized service accounts or groups only. Do NOT include allUsers or allAuthenticatedUsers.
    "group:security-auditors@example.com",
  ]
}"#.to_string(),
                cli_template: "gcloud storage buckets remove-iam-policy-binding gs://{{RESOURCE_NAME}} --member=allUsers --role=roles/storage.objectViewer --project={{PROJECT_ID}}".to_string(),
                preventive_policy_example: r#"# GCP Organization Policy Constraint
constraints/storage.publicAccessPrevention: enforce"#.to_string(),
                version: "1.0.0".to_string(),
                requires_approval: true,
            },
            // GCP Cloud SQL Public IP
            RemediationTemplate {
                template_id: "rem-gcp-sql-no-public-ip-v1".to_string(),
                check_id: "gcp-sql-no-public-ip".to_string(),
                provider: CloudProvider::Gcp,
                resource_type: "gcp_sql_database_instance".to_string(),
                title: "Disable Public IP on GCP Cloud SQL Instance".to_string(),
                description: "Restrict database connectivity exclusively to Private IP via Virtual Private Cloud (VPC) peering.".to_string(),
                effort: RemediationEffort::High,
                terraform_template: r#"# RECOMMENDATION ONLY - Review and test before applying
resource "google_sql_database_instance" "{{RESOURCE_NAME}}" {
  name             = "{{RESOURCE_NAME}}"
  database_version = "POSTGRES_15"
  settings {
    ip_configuration {
      ipv4_enabled    = false
      private_network = "projects/{{PROJECT_ID}}/global/networks/default"
    }
  }
}"#.to_string(),
                cli_template: "gcloud sql instances patch {{RESOURCE_NAME}} --no-assign-ip --network=projects/{{PROJECT_ID}}/global/networks/default --project={{PROJECT_ID}}".to_string(),
                preventive_policy_example: r#"# GCP Organization Policy Constraint
constraints/sql.restrictPublicIp: enforce"#.to_string(),
                version: "1.0.0".to_string(),
                requires_approval: true,
            },
        ]
    }

    pub fn get_template_for_check(check_id: &str) -> Option<RemediationTemplate> {
        Self::all_templates()
            .into_iter()
            .find(|t| t.check_id == check_id)
    }

    pub fn render_terraform(
        template: &RemediationTemplate,
        resource_name: &str,
        account_id: &str,
        region: &str,
    ) -> String {
        let clean_res = sanitize_input(resource_name);
        let clean_acc = sanitize_input(account_id);
        let clean_reg = sanitize_input(region);

        template
            .terraform_template
            .replace("{{RESOURCE_NAME}}", &clean_res)
            .replace("{{ACCOUNT_ID}}", &clean_acc)
            .replace("{{PROJECT_ID}}", &clean_acc)
            .replace("{{SUBSCRIPTION_ID}}", &clean_acc)
            .replace("{{RESOURCE_GROUP}}", &format!("rg-{clean_res}"))
            .replace("{{REGION}}", &clean_reg)
    }

    pub fn render_cli(
        template: &RemediationTemplate,
        resource_name: &str,
        account_id: &str,
        region: &str,
    ) -> String {
        let clean_res = sanitize_input(resource_name);
        let clean_acc = sanitize_input(account_id);
        let clean_reg = sanitize_input(region);

        template
            .cli_template
            .replace("{{RESOURCE_NAME}}", &clean_res)
            .replace("{{ACCOUNT_ID}}", &clean_acc)
            .replace("{{PROJECT_ID}}", &clean_acc)
            .replace("{{SUBSCRIPTION_ID}}", &clean_acc)
            .replace("{{RESOURCE_GROUP}}", &format!("rg-{clean_res}"))
            .replace("{{REGION}}", &clean_reg)
            .replace("{{KEY_ID}}", "AKIAEXAMPLEKEYID")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_sanitizer_removes_dangerous_metacharacters() {
        let dirty = "prod-bucket; rm -rf / && $(whoami)`calc`\n";
        let clean = sanitize_input(dirty);
        assert_eq!(clean, "prod-bucketrm-rfwhoamicalc");
    }

    #[test]
    fn renders_aws_s3_block_public_access_templates_safely() {
        let tmpl = RemediationTemplateEngine::get_template_for_check("aws-s3-block-public-access")
            .expect("template must exist");
        let tf = RemediationTemplateEngine::render_terraform(
            &tmpl,
            "customer-data",
            "123456789012",
            "us-east-1",
        );
        assert!(tf.contains("bucket = \"customer-data\""));
        assert!(tf.contains("block_public_acls       = true"));

        let cli = RemediationTemplateEngine::render_cli(
            &tmpl,
            "customer-data",
            "123456789012",
            "us-east-1",
        );
        assert!(cli.contains("--bucket customer-data"));
        assert!(cli.contains("--region us-east-1"));
        assert!(!cli.contains("{{"));
    }

    #[test]
    fn renders_azure_storage_templates_safely() {
        let tmpl = RemediationTemplateEngine::get_template_for_check("azure-storage-public-access")
            .expect("template must exist");
        let cli = RemediationTemplateEngine::render_cli(
            &tmpl,
            "mystorageacct",
            "sub-1234-uuid",
            "eastus",
        );
        assert!(cli.contains("--name mystorageacct"));
        assert!(cli.contains("--subscription sub-1234-uuid"));
    }

    #[test]
    fn renders_gcp_cloud_sql_templates_safely() {
        let tmpl = RemediationTemplateEngine::get_template_for_check("gcp-sql-no-public-ip")
            .expect("template must exist");
        let cli = RemediationTemplateEngine::render_cli(
            &tmpl,
            "prod-postgres-db",
            "my-gcp-project",
            "us-central1",
        );
        assert!(cli.contains("gcloud sql instances patch prod-postgres-db"));
        assert!(cli.contains("--project=my-gcp-project"));
    }
}
