# remediation/storage_encryption.tf
#
# Remediates: gcp.storage.encryption_enabled == FAIL
# SOC 2 Criteria: C1.1 (Confidentiality)
#
# This blueprint attaches the KMS key from kms_rotation.tf to a cloud storage
# bucket, ensuring all confidential data is encrypted at rest using a
# customer-managed key.

variable "kms_key_self_link" {
  description = "The self-link of the Google KMS key to encrypt the bucket."
  type        = string
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
}
