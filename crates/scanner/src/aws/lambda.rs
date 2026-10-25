use cloudsec_domain::{CloudProvider, Resource, Severity};
use serde_json::{Value, json};

use crate::check::{Check, CheckEvaluation};

const DEPRECATED_RUNTIMES: &[&str] = &[
    "nodejs12.x",
    "nodejs14.x",
    "nodejs16.x",
    "python2.7",
    "python3.6",
    "python3.7",
    "python3.8",
    "dotnetcore2.1",
    "dotnetcore3.1",
    "ruby2.5",
    "ruby2.7",
    "java8",
];

/// Check: Lambda execution role adheres to least privilege
pub struct AwsLambdaExecutionRoleLeastPrivilegeCheck;

impl Check for AwsLambdaExecutionRoleLeastPrivilegeCheck {
    fn id(&self) -> &str {
        "aws-lambda-execution-role-least-privilege"
    }
    fn provider(&self) -> CloudProvider {
        CloudProvider::Aws
    }
    fn service(&self) -> &str {
        "lambda"
    }
    fn category(&self) -> &str {
        "compute"
    }
    fn version(&self) -> &str {
        "1.0.0"
    }
    fn title(&self) -> &str {
        "Ensure Lambda execution roles adhere to least privilege"
    }
    fn description(&self) -> &str {
        "Lambda function execution roles should not grant wildcard admin permissions or excessive privileges across unrelated services."
    }
    fn remediation(&self) -> &str {
        "Scope down the IAM role attached to the Lambda function to only required actions."
    }
    fn base_severity(&self) -> Severity {
        Severity::High
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type != "aws_lambda_function" {
            return CheckEvaluation::NotApplicable;
        }

        let config = &resource.configuration;
        let role_has_wildcard_admin = config
            .get("role_has_wildcard_admin")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        if !role_has_wildcard_admin {
            CheckEvaluation::Passed
        } else {
            CheckEvaluation::Failed {
                severity: self.base_severity(),
                evidence: json!({
                    "role_has_wildcard_admin": true,
                    "role_arn": config.get("role_arn"),
                }),
                message: format!(
                    "Lambda function '{}' uses an execution role with wildcard administrative privileges",
                    resource
                        .name
                        .as_deref()
                        .unwrap_or(&resource.provider_native_id)
                ),
            }
        }
    }
}

/// Check: Lambda function URLs require IAM authentication and are not public
pub struct AwsLambdaNoPublicUrlsCheck;

impl Check for AwsLambdaNoPublicUrlsCheck {
    fn id(&self) -> &str {
        "aws-lambda-no-public-urls"
    }
    fn provider(&self) -> CloudProvider {
        CloudProvider::Aws
    }
    fn service(&self) -> &str {
        "lambda"
    }
    fn category(&self) -> &str {
        "compute"
    }
    fn version(&self) -> &str {
        "1.0.0"
    }
    fn title(&self) -> &str {
        "Ensure Lambda function URLs require IAM authentication"
    }
    fn description(&self) -> &str {
        "Lambda Function URLs should require AWS_IAM authentication rather than NONE, preventing unauthenticated public invocation."
    }
    fn remediation(&self) -> &str {
        "aws lambda update-function-url-config --function-name <name> --auth-type AWS_IAM"
    }
    fn base_severity(&self) -> Severity {
        Severity::High
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type != "aws_lambda_function" {
            return CheckEvaluation::NotApplicable;
        }

        let config = &resource.configuration;
        let has_url = config
            .get("has_function_url")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !has_url {
            return CheckEvaluation::Passed;
        }

        let auth_type = config
            .get("url_auth_type")
            .and_then(Value::as_str)
            .unwrap_or("NONE");

        if auth_type == "AWS_IAM" {
            CheckEvaluation::Passed
        } else {
            CheckEvaluation::Failed {
                severity: self.base_severity(),
                evidence: json!({
                    "has_function_url": true,
                    "url_auth_type": auth_type,
                }),
                message: format!(
                    "Lambda function '{}' has a public Function URL configured without IAM authentication (auth: {auth_type})",
                    resource
                        .name
                        .as_deref()
                        .unwrap_or(&resource.provider_native_id)
                ),
            }
        }
    }
}

/// Check: Lambda VPC attachment policy validation
pub struct AwsLambdaVpcAttachmentPolicyCheck;

impl Check for AwsLambdaVpcAttachmentPolicyCheck {
    fn id(&self) -> &str {
        "aws-lambda-vpc-attachment-policy"
    }
    fn provider(&self) -> CloudProvider {
        CloudProvider::Aws
    }
    fn service(&self) -> &str {
        "lambda"
    }
    fn category(&self) -> &str {
        "network"
    }
    fn version(&self) -> &str {
        "1.0.0"
    }
    fn title(&self) -> &str {
        "Ensure Lambda VPC attachment aligns with policy"
    }
    fn description(&self) -> &str {
        "Functions requiring access to private VPC resources should be attached to a VPC with dedicated security groups."
    }
    fn remediation(&self) -> &str {
        "aws lambda update-function-configuration --function-name <name> --vpc-config SubnetIds=<subnets>,SecurityGroupIds=<sgs>"
    }
    fn base_severity(&self) -> Severity {
        Severity::Low
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type != "aws_lambda_function" {
            return CheckEvaluation::NotApplicable;
        }

        let config = &resource.configuration;
        let requires_vpc = config
            .get("requires_vpc")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let in_vpc = config
            .get("in_vpc")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        // VPC attachment is evaluated only when required by workload policy
        if !requires_vpc || in_vpc {
            CheckEvaluation::Passed
        } else {
            CheckEvaluation::Failed {
                severity: self.base_severity(),
                evidence: json!({
                    "requires_vpc": true,
                    "in_vpc": false,
                }),
                message: format!(
                    "Lambda function '{}' requires VPC access according to policy but is not attached to a VPC",
                    resource
                        .name
                        .as_deref()
                        .unwrap_or(&resource.provider_native_id)
                ),
            }
        }
    }
}

/// Check: Lambda supported runtime policy and environment variable encryption
pub struct AwsLambdaRuntimeAndEncryptionCheck;

impl Check for AwsLambdaRuntimeAndEncryptionCheck {
    fn id(&self) -> &str {
        "aws-lambda-runtime-and-encryption"
    }
    fn provider(&self) -> CloudProvider {
        CloudProvider::Aws
    }
    fn service(&self) -> &str {
        "lambda"
    }
    fn category(&self) -> &str {
        "compute"
    }
    fn version(&self) -> &str {
        "1.0.0"
    }
    fn title(&self) -> &str {
        "Ensure Lambda runtimes are supported and environment variables are KMS encrypted"
    }
    fn description(&self) -> &str {
        "Lambda functions must use actively supported runtimes and encrypt environment variables containing secrets using KMS."
    }
    fn remediation(&self) -> &str {
        "Upgrade the Lambda function runtime to a supported version and configure KMS key ARN for environment encryption."
    }
    fn base_severity(&self) -> Severity {
        Severity::Medium
    }

    fn evaluate(&self, resource: &Resource) -> CheckEvaluation {
        if resource.resource_type != "aws_lambda_function" {
            return CheckEvaluation::NotApplicable;
        }

        let config = &resource.configuration;
        let runtime = config
            .get("runtime")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let is_deprecated = DEPRECATED_RUNTIMES.contains(&runtime);

        let has_env_vars = config
            .get("has_environment_variables")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let env_kms_encrypted = config
            .get("kms_key_arn")
            .and_then(Value::as_str)
            .map(|s| !s.is_empty())
            .unwrap_or(false);

        let env_ok = !has_env_vars || env_kms_encrypted;

        if !is_deprecated && env_ok {
            CheckEvaluation::Passed
        } else {
            CheckEvaluation::Failed {
                severity: self.base_severity(),
                evidence: json!({
                    "runtime": runtime,
                    "is_runtime_deprecated": is_deprecated,
                    "has_environment_variables": has_env_vars,
                    "kms_key_configured": env_kms_encrypted,
                }),
                message: format!(
                    "Lambda function '{}' fails runtime/encryption standards (runtime: {runtime}, deprecated: {is_deprecated}, KMS encrypted: {env_kms_encrypted})",
                    resource
                        .name
                        .as_deref()
                        .unwrap_or(&resource.provider_native_id)
                ),
            }
        }
    }
}
