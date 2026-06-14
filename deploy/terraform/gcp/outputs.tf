output "evidence_bucket_name" {
  description = "The name of the evidence ledger GCS bucket"
  value       = google_storage_bucket.evidence.name
}

output "deployment_id" {
  description = "The unique deployment identifier for this environment"
  value       = random_string.deployment_id.result
}
