# ──────────────────────────────────────────────────────────────
# Jula Evidence Collector – AWS Variables
# ──────────────────────────────────────────────────────────────

variable "aws_region" {
  description = "AWS region for ECR and OIDC resources."
  type        = string
  default     = "us-east-1"
}

variable "aws_repository_name" {
  description = "Name of the AWS ECR repository."
  type        = string
  default     = "jula-evidence-collector"
}

variable "github_repo_full_name" {
  description = "Full name of the GitHub repository (owner/repo) for OIDC trust."
  type        = string
  default     = "alibkaba/jula-evidence-collector"
}
