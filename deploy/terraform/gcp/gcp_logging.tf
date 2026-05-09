# audit_logging.tf – Environment-specific: jula-494603
# This file is .gitignored and should NOT be committed to the public repository.
# Generic template: remediation/audit_logging.tf

resource "google_project_iam_audit_config" "project_audit_logs" {
  project = var.project_id
  service = "allServices"
  audit_log_config { log_type = "ADMIN_READ" }
  audit_log_config { log_type = "DATA_READ" }
  audit_log_config { log_type = "DATA_WRITE" }
}
