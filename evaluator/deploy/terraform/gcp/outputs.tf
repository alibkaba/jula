# ──────────────────────────────────────────────────────────────
# Jula Evidence Evaluator – Outputs
# ──────────────────────────────────────────────────────────────

output "cloud_run_url" {
  description = "URL of the deployed Jula Evaluator Cloud Run service."
  value       = google_cloud_run_v2_service.jula_eval.uri
}

output "service_account_email" {
  description = "Email of the Jula Evaluator runner service account."
  value       = google_service_account.jula_eval_runner.email
}

output "scheduler_job_name" {
  description = "Name of the Cloud Scheduler job."
  value       = google_cloud_scheduler_job.jula_eval_trigger.name
}
