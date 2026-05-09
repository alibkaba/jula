# ──────────────────────────────────────────────────────────────
# Jula Remediation Template: AWS Container Registry Governance
# ──────────────────────────────────────────────────────────────
# Jula Finding: aws.registry.lifecycle_policy == FAIL
# Frameworks: SOC 2 CC7.1, CC6.1
#
# Implements the "Prefix-Aware Retention Strategy":
# 1. Purges development builds (sha-*) after 30 days.
# 2. Purges untagged images after 14 days.
# 3. Implicitly protects semantic versions (v*) and 'prod' tags.
# ──────────────────────────────────────────────────────────────

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "ecr_repository_name" {
  type    = string
  default = "jula-evidence-collector"
}

provider "aws" {
  region = var.aws_region
}

resource "aws_ecr_repository" "remediated_ecr" {
  name                 = var.ecr_repository_name
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
  }
}

resource "aws_ecr_lifecycle_policy" "remediated_policy" {
  repository = aws_ecr_repository.remediated_ecr.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Expire untagged images older than 14 days"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = 14
        }
        action = {
          type = "expire"
        }
      },
      {
        rulePriority = 2
        description  = "Expire development builds (sha- prefix) older than 30 days"
        selection = {
          tagStatus     = "tagged"
          tagPrefixList = ["sha-"]
          countType     = "sinceImagePushed"
          countUnit     = "days"
          countNumber   = 30
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}
