# ──────────────────────────────────────────────────────────────
# Jula Evidence Evaluator – Terraform Variables
# ──────────────────────────────────────────────────────────────
# Copy terraform.tfvars.example → terraform.tfvars and fill in
# your values before running terraform apply.
# ──────────────────────────────────────────────────────────────

variable "project_id" {
  description = "GCP project ID where Jula will be deployed."
  type        = string
}

variable "region" {
  description = "GCP region for all regional resources."
  type        = string
  default     = "us-central1"
}

variable "docker_image" {
  description = "Full URI of the Jula Evaluator container image in Artifact Registry."
  type        = string
}

variable "evidence_bucket_name" {
  description = "Name of the GCS bucket containing evidence output from the Collector."
  type        = string
}

variable "service_account_id" {
  description = "Short ID for the Jula Evaluator runner service account."
  type        = string
  default     = "jula-eval-runner"
}

variable "signing_key_secret_id" {
  description = "Secret Manager secret ID for the ECDSA signing key."
  type        = string
  default     = "jula-signing-key"
}

variable "github_token_secret_id" {
  description = "Secret Manager secret ID for the GitHub PAT."
  type        = string
  default     = "jula-github-token"
}

variable "policy_repo_url" {
  description = "URL of the compliance policies repository (GitHub tarball endpoint)."
  type        = string
  default     = "https://api.github.com/repos/alibkaba/jula-compliance-as-code/tarball/main"
}

variable "scheduler_cron" {
  description = "Cron expression for the Cloud Scheduler trigger."
  type        = string
  default     = "30 3 * * *" # Every day at 3:30 AM UTC (30 min after Collector).
}

variable "scheduler_timezone" {
  description = "Timezone for the Cloud Scheduler trigger."
  type        = string
  default     = "Etc/UTC"
}

variable "repository_name" {
  description = "Name of the Artifact Registry repository."
  type        = string
  default     = "jula-evidence-evaluator"
}

variable "owner_email" {
  description = "The email address of the project owner/admin."
  type        = string
}

variable "github_org" {
  description = "The GitHub organization or username."
  type        = string
}
