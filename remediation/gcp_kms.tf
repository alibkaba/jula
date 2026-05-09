# remediation/kms_rotation.tf
#
# Remediates: gcp.kms.key_rotation == FAIL
# SOC 2 Criteria: CC6.1 (Logical Access - Cryptographic Controls)
#
# This blueprint creates a Customer-Managed Encryption Key (CMEK) and enforces
# an automatic 90-day rotation schedule to satisfy cryptographic logical access controls.

variable "keyring_id" {
  description = "The ID of the KMS Keyring."
  type        = string
}

resource "google_kms_crypto_key" "soc2_compliant_key" {
  name            = "production-storage-key"
  key_ring        = var.keyring_id
  purpose         = "ENCRYPT_DECRYPT"

  # Enforces a 90-day rotation (7776000 seconds)
  rotation_period = "7776000s"

  lifecycle {
    prevent_destroy = true
  }
}
