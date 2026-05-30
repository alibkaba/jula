resource "google_storage_bucket" "evidence" {
  name          = var.evidence_bucket_name
  location      = var.region
  force_destroy = true # Set to false in real production to prevent accidental deletion

  uniform_bucket_level_access = true

  versioning {
    enabled = true
  }
}
