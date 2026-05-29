# least_privilege_iam.tf – Environment-specific: jula-494603
# This file is .gitignored and should NOT be committed to the public repository.
# Generic template: remediation/least_privilege_iam.tf

data "google_service_account" "github_actions" {
  account_id = "github-actions-sa"
  project    = var.project_id
}

# ── Artifact Registry Repo Admin ──────────────────────────────
# Allows pushing images and overwriting tags (required for 'prod' tag).
resource "google_project_iam_member" "github_actions_ar_admin" {
  project = var.project_id
  role    = "roles/artifactregistry.repoAdmin"
  member  = "serviceAccount:${data.google_service_account.github_actions.email}"
}

resource "google_project_iam_member" "github_actions_run_developer" {
  project = var.project_id
  role    = "roles/run.developer"
  member  = "serviceAccount:${data.google_service_account.github_actions.email}"
}

resource "google_service_account_iam_member" "github_actions_sa_user" {
  service_account_id = google_service_account.jula_eval_runner.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${data.google_service_account.github_actions.email}"
}
