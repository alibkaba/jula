variable "project_id" {
  description = "The GCP Project ID where Jula is deployed"
  type        = string
}

variable "region" {
  description = "The GCP region for resources"
  type        = string
  default     = "us-central1"
}

variable "evidence_bucket_name" {
  description = "Name of the GCS bucket to store evidence"
  type        = string
}

variable "repository_name" {
  description = "Artifact Registry repository name"
  type        = string
  default     = "jula-collector"
}

variable "collector_image_tag" {
  description = "The container image tag (typically a Git commit SHA) deployed by GitHub Actions"
  type        = string
}

variable "assessor_image_tag" {
  description = "The container image tag for the assessor"
  type        = string
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

# Secrets configuration
variable "source_token_env_name" {
  description = "The environment variable name containers use to read the source token (e.g. GITHUB_TOKEN, GITLAB_TOKEN)"
  type        = string
  default     = "GITHUB_TOKEN"
}

variable "source_token_secret_id" {
  description = "The GCP Secret Manager secret ID that holds the source token"
  type        = string
  default     = "jula-source-token"
}

variable "allowed_hosts" {
  description = "Comma-separated list of allowed HTTPS hosts for fetching integrations and policies"
  type        = string
  default     = "api.github.com,github.com"
}

variable "jula_provider" {
  description = "The native cloud provider this Collector runs on (gcp, aws, azure, etc.)"
  type        = string
  default     = "gcp"
}

variable "source_token" {
  description = "API token for the Git provider (e.g. GitHub PAT, GitLab token, Bitbucket app password)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "dispatch_token" {
  description = "Jula dispatch token for triggering downstream workflows"
  type        = string
  sensitive   = true
  default     = ""
}

