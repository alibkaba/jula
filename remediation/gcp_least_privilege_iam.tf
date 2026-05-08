# ──────────────────────────────────────────────────────────────
# Least Privilege IAM – Scoped CI/CD Service Account Roles
# ──────────────────────────────────────────────────────────────
# Prevents CI/CD pipelines from accumulating overly-broad
# permissions like roles/owner or roles/editor. This template
# binds only the minimum roles required for a typical
# build-push-deploy workflow targeting Cloud Run.
#
# Satisfies SOC 2 CC6.1 (Logical Access) and CC6.3
# (Role-Based Access Controls).
#
# Usage:
#   1. Copy this file into your Terraform workspace.
#   2. Provide values via terraform.tfvars.
#   3. Run: terraform init && terraform apply
# ──────────────────────────────────────────────────────────────

variable "project_id" {
  description = "GCP project ID to bind IAM roles in."
  type        = string
}

variable "cicd_service_account_email" {
  description = "Email of the CI/CD service account (e.g., github-actions-sa@project.iam.gserviceaccount.com)."
  type        = string
}

variable "deploy_target_service_account_name" {
  description = "Full resource name of the service account the CI/CD pipeline impersonates for deployment (e.g., projects/my-project/serviceAccounts/runner@my-project.iam.gserviceaccount.com)."
  type        = string
}

# ── Artifact Registry Writer ─────────────────────────────────
# Allows pushing container images to Artifact Registry.

resource "google_project_iam_member" "cicd_ar_writer" {
  project = var.project_id
  role    = "roles/artifactregistry.writer"
  member  = "serviceAccount:${var.cicd_service_account_email}"
}

# ── Cloud Run Developer ──────────────────────────────────────
# Allows deploying new revisions to Cloud Run services
# without granting full admin (which includes IAM mutation).

resource "google_project_iam_member" "cicd_run_developer" {
  project = var.project_id
  role    = "roles/run.developer"
  member  = "serviceAccount:${var.cicd_service_account_email}"
}

# ── Service Account User (Scoped) ────────────────────────────
# Allows the CI/CD SA to act-as the application's runner SA
# for Cloud Run deployments, scoped to a single target account.

resource "google_service_account_iam_member" "cicd_sa_user" {
  service_account_id = var.deploy_target_service_account_name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${var.cicd_service_account_email}"
}
