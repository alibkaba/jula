variable "aws_region" {
  description = "The AWS region where resources are deployed"
  type        = string
  default     = "us-east-1"
}

variable "evidence_bucket_name" {
  description = "Name of the S3 bucket to store evidence"
  type        = string
}

variable "collector_image_tag" {
  description = "The container image tag for the collector (typically a Git commit SHA)"
  type        = string
  default     = "latest"
}

variable "assessor_image_tag" {
  description = "The container image tag for the assessor"
  type        = string
  default     = "latest"
}

variable "vpc_id" {
  description = "The VPC ID to deploy the ECS tasks into (leave empty to use default VPC)"
  type        = string
  default     = ""
}

variable "subnets" {
  description = "The subnets to deploy the ECS tasks into (leave empty to use default VPC subnets)"
  type        = list(string)
  default     = []
}

# Secrets variables
variable "source_token" {
  description = "API token for the Git provider (e.g. GitHub PAT, GitLab token, Bitbucket app password)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "source_token_env_name" {
  description = "The environment variable name containers use to read the source token (e.g. GITHUB_TOKEN, GITLAB_TOKEN)"
  type        = string
  default     = "GITHUB_TOKEN"
}

variable "dispatch_token" {
  description = "Jula dispatch token for triggering downstream workflows"
  type        = string
  sensitive   = true
  default     = ""
}

# Repository configuration
variable "git_org" {
  description = "The Git organization or group that owns the Jula repository (e.g. my-org)"
  type        = string
}

variable "integration_url" {
  description = "URL to fetch the integrations tarball (e.g. https://api.github.com/repos/my-org/jula/tarball/main)"
  type        = string
}

variable "policy_url" {
  description = "URL to fetch the policies tarball (e.g. https://api.github.com/repos/my-org/jula/tarball/main)"
  type        = string
}

variable "governor_repo" {
  description = "The Git repository path for the governor (e.g. my-org/jula)"
  type        = string
}

variable "allowed_hosts" {
  description = "Comma-separated list of allowed HTTPS hosts for fetching integrations and policies"
  type        = string
  default     = "api.github.com,github.com"
}

variable "jula_provider" {
  description = "The native cloud provider this Collector runs on (gcp, aws, azure, etc.)"
  type        = string
  default     = "aws"
}

variable "source_repo" {
  description = "The Git repository name (e.g. jula) used in OIDC trust policy for CI/CD"
  type        = string
  default     = "jula"
}

# Auto-discovery data sources
data "aws_vpc" "default" {
  count   = var.vpc_id == "" ? 1 : 0
  default = true
}

data "aws_subnets" "default" {
  count = length(var.subnets) == 0 ? 1 : 0
  filter {
    name   = "vpc-id"
    values = [var.vpc_id == "" ? data.aws_vpc.default[0].id : var.vpc_id]
  }
}

locals {
  target_vpc_id  = var.vpc_id == "" ? data.aws_vpc.default[0].id : var.vpc_id
  target_subnets = length(var.subnets) == 0 ? data.aws_subnets.default[0].ids : var.subnets
}
