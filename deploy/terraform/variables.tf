# ──────────────────────────────────────────────────────────────
# Jula Evidence Collector – Terraform Variables
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
  description = "Full URI of the Jula container image in Artifact Registry."
  type        = string
}

variable "evidence_bucket_name" {
  description = "Name of the GCS bucket for evidence output."
  type        = string
}

variable "service_account_id" {
  description = "Short ID for the Jula runner service account."
  type        = string
  default     = "jula-runner"
}

variable "signing_key_secret_id" {
  description = "Secret Manager secret ID for the HMAC signing key."
  type        = string
  default     = "jula-signing-key"
}

variable "scheduler_cron" {
  description = "Cron expression for the Cloud Scheduler trigger."
  type        = string
  default     = "0 3 * * *" # Every day at 3:00 AM UTC.
}

variable "scheduler_timezone" {
  description = "Timezone for the Cloud Scheduler trigger."
  type        = string
  default     = "Etc/UTC"
}
