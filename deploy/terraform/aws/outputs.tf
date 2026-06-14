output "evidence_bucket_name" {
  description = "The name of the evidence ledger S3 bucket"
  value       = aws_s3_bucket.evidence.bucket
}

output "deployment_id" {
  description = "The unique deployment identifier for this environment"
  value       = random_string.deployment_id.result
}
