resource "google_storage_bucket" "evidence" {
  name          = var.evidence_bucket_name
  location      = var.region
  force_destroy = false # Set to true only in pure ephemeral testing

  lifecycle {
    prevent_destroy = true
  }

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  versioning {
    enabled = true
  }
}
