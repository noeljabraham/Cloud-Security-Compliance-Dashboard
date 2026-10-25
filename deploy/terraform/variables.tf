variable "aws_region" {
  type        = string
  description = "AWS deployment region"
  default     = "us-east-1"
}

variable "environment" {
  type        = string
  description = "Deployment environment (dev, staging, prod)"
  default     = "prod"
}

variable "vpc_cidr" {
  type        = string
  description = "CIDR block for CloudSec VPC"
  default     = "10.0.0.0/16"
}

variable "db_instance_class" {
  type        = string
  description = "Instance type for RDS PostgreSQL"
  default     = "db.t4g.medium"
}

