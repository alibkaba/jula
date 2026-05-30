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
