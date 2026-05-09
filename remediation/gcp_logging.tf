# ──────────────────────────────────────────────────────────────
# Audit Logging – Enforce Global Data Access Logs
# ──────────────────────────────────────────────────────────────
# SOC 2 Criteria: CC2.1, CC7.2 (Monitoring and Logging)
#
# This template enables "ADMIN_READ", "DATA_READ", and "DATA_WRITE"
# logging for ALL GCP services within the project. This ensures
# a complete audit trail for compliance forensics.
# ──────────────────────────────────────────────────────────────

variable "project_id" {
  description = "The GCP Project ID where resources reside."
  type        = string
}

resource "google_project_iam_audit_config" "project_audit_logs" {
  project = var.project_id
  service = "allServices"

  audit_log_config {
    log_type = "ADMIN_READ"
  }
  audit_log_config {
    log_type = "DATA_READ"
  }
  audit_log_config {
    log_type = "DATA_WRITE"
  }
}
