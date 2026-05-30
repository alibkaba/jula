resource "google_service_account" "jula_runner" {
  account_id   = "jula-runner"
  display_name = "Jula Evidence Collector Identity"
}

# Grant the service account permissions to write to its own bucket
resource "google_project_iam_member" "storage_admin" {
  project = var.project_id
  role    = "roles/storage.admin"
  member  = "serviceAccount:${google_service_account.jula_runner.email}"
}

# Grant the service account permission to access secrets
resource "google_project_iam_member" "secret_accessor" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.jula_runner.email}"
}
