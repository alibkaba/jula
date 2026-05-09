# ──────────────────────────────────────────────────────────────
# Jula Evidence Collector – Outputs
# ──────────────────────────────────────────────────────────────

output "cloud_run_url" {
  description = "URL of the deployed Jula Cloud Run service."
  value       = google_cloud_run_v2_service.jula.uri
}

output "evidence_bucket" {
  description = "Name of the GCS bucket receiving evidence artifacts."
  value       = google_storage_bucket.evidence.name
}

output "service_account_email" {
  description = "Email of the Jula runner service account."
  value       = google_service_account.jula_runner.email
}

output "scheduler_job_name" {
  description = "Name of the Cloud Scheduler job."
  value       = google_cloud_scheduler_job.jula_trigger.name
}

output "aws_github_actions_role_arn" {
  description = "ARN of the IAM role for GitHub Actions."
  value       = aws_iam_role.github_actions.arn
}
