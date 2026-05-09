# ──────────────────────────────────────────────────────────────
# Jula Evidence Collector – AWS Outputs
# ──────────────────────────────────────────────────────────────

output "aws_ecr_repository_url" {
  description = "The URL of the ECR repository."
  value       = aws_ecr_repository.jula_registry.repository_url
}

output "aws_github_actions_role_arn" {
  description = "ARN of the IAM role for GitHub Actions to assume via OIDC."
  value       = aws_iam_role.github_actions.arn
}
