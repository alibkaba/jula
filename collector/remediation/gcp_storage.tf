# remediation/gcp_storage.tf
#
# Remediates: gcp.storage.encryption_enabled == FAIL
# SOC 2 Criteria: C1.1 (Confidentiality)
# Zero Trust: Immutable Evidence Ledger (WORM)
#
# This blueprint enforces:
#   1. Customer-Managed Encryption Keys (CMEK) for data at rest.
#   2. Retention policy for write-once-read-many (WORM) evidence storage.
#   3. Versioning to prevent silent overwrites.
#
# WARNING: Once is_locked = true, the retention period CANNOT be shortened
# or removed. Test on a scratch bucket first. See: Ticket T4 in the
# Zero Trust Architecture Implementation Plan.

variable "kms_key_self_link" {
  description = "The self-link of the Google KMS key to encrypt the bucket."
  type        = string
}

variable "evidence_retention_seconds" {
  description = "Evidence retention period in seconds. Default: 365 days (SOC 2 Type II audit window). Once bucket lock is enabled, this cannot be shortened."
  type        = number
  default     = 31536000 # 365 days
}

variable "lock_evidence_bucket" {
  description = "Enable irreversible GCS Bucket Lock. WARNING: Once enabled, the retention period cannot be shortened or removed. Defaults to false for safe testing."
  type        = bool
  default     = false
}

resource "google_storage_bucket" "secure_evidence_vault" {
  name          = "secure-company-data-vault"
  location      = "US"
  force_destroy = false

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  # Applies Customer-Managed Encryption Keys (CMEK)
  encryption {
    default_kms_key_name = var.kms_key_self_link
  }

  # Immutable Evidence Ledger: retention policy enforces WORM semantics.
  # Objects cannot be deleted or overwritten until the retention period expires.
  retention_policy {
    retention_period = var.evidence_retention_seconds
    is_locked        = var.lock_evidence_bucket
  }

  # Versioning prevents silent overwrites of evidence files.
  versioning {
    enabled = true
  }
}
