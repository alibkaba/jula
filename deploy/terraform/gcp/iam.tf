resource "google_service_account" "jula_runner" {
  account_id   = "jula-runner"
  display_name = "Jula Evidence Collector Identity"
}

# Grant the service account permissions to write to its own bucket
resource "google_storage_bucket_iam_member" "storage_admin" {
  bucket = google_storage_bucket.evidence.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.jula_runner.email}"
}

# Grant the service account permission to access secrets
resource "google_project_iam_member" "secret_accessor" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.jula_runner.email}"
}

locals {
  collector_roles = [
    "roles/cloudasset.viewer",
    "roles/cloudkms.viewer",
    "roles/cloudsql.viewer",
    "roles/compute.viewer",
    "roles/iam.securityReviewer",
    "roles/iam.serviceAccountViewer",
    "roles/storage.objectViewer",
    "roles/run.viewer"
  ]
}

resource "google_project_iam_member" "collector_roles" {
  for_each = toset(local.collector_roles)
  project  = var.project_id
  role     = each.value
  member   = "serviceAccount:${google_service_account.jula_runner.email}"
}
