terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "CloudSec"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

# --- VPC & Networking ---

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "cloudsec-${var.environment}-vpc"
  }
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 4, count.index)
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name = "cloudsec-${var.environment}-private-${count.index}"
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

# --- KMS Master Key for Secret Encryption ---

resource "aws_kms_key" "cloudsec" {
  description             = "KMS Key for CloudSec at-rest credential encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name = "cloudsec-${var.environment}-kms"
  }
}

# --- Database Storage (PostgreSQL RDS) ---

resource "aws_db_subnet_group" "rds" {
  name       = "cloudsec-${var.environment}-db-subnets"
  subnet_ids = aws_subnet.private[*].id
}

resource "aws_security_group" "rds" {
  name        = "cloudsec-${var.environment}-rds-sg"
  description = "Access to CloudSec RDS from application layer"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "random_password" "db_password" {
  length  = 32
  special = false
}

resource "aws_secretsmanager_secret" "db_credentials" {
  name                    = "cloudsec-${var.environment}-db-credentials"
  kms_key_id             = aws_kms_key.cloudsec.id
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "db_credentials" {
  secret_id     = aws_secretsmanager_secret.db_credentials.id
  secret_string = jsonencode({
    username = "cloudsec_admin"
    password = random_password.db_password.result
  })
}

resource "aws_db_instance" "postgres" {
  identifier             = "cloudsec-${var.environment}-postgres"
  engine                 = "postgres"
  engine_version         = "16.1"
  instance_class         = var.db_instance_class
  allocated_storage      = 50
  max_allocated_storage  = 500
  storage_type           = "gp3"
  storage_encrypted      = true
  kms_key_id             = aws_kms_key.cloudsec.arn
  db_subnet_group_name   = aws_db_subnet_group.rds.name
  vpc_security_group_ids = [aws_security_group.rds.id]

  username = "cloudsec_admin"
  password = random_password.db_password.result

  backup_retention_period   = 30
  backup_window             = "03:00-04:00"
  maintenance_window        = "Sun:04:30-Sun:05:30"
  auto_minor_version_upgrade = true
  copy_tags_to_snapshot     = true
  deletion_protection       = var.environment == "prod"
  skip_final_snapshot       = var.environment != "prod"

  tags = {
    Name = "cloudsec-${var.environment}-db"
  }
}

# --- Application Security Group ---

resource "aws_security_group" "app" {
  name        = "cloudsec-${var.environment}-app-sg"
  description = "CloudSec API and Worker Service Security Group"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

