# remediation/audit_logging.tf
#
# Remediates: gcp.audit_logging.enabled == FAIL
# SOC 2 Criteria: CC2.1 (Communication and Information), CC7.2 (Anomaly Detection)
#
# This blueprint enables Data Access audit logging globally for all GCP services,
# which satisfies the SOC 2 anomaly detection baseline.

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
