output "vpc_id" {
  description = "CloudSec VPC ID"
  value       = aws_vpc.main.id
}

output "rds_endpoint" {
  description = "PostgreSQL RDS connection endpoint"
  value       = aws_db_instance.postgres.endpoint
}

output "kms_key_arn" {
  description = "KMS master encryption key ARN"
  value       = aws_kms_key.cloudsec.arn
}

output "db_credentials_secret_arn" {
  description = "Secrets Manager secret ARN for database credentials"
  value       = aws_secretsmanager_secret.db_credentials.arn
}

