# ──────────────────────────────────────────────────────────────
# Jula Evidence Collector – Infrastructure
# ──────────────────────────────────────────────────────────────

terraform {
  required_version = ">= 1.5"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# ──────────────────────────────────────────────────────────────
# 1. Enable Required APIs
# ──────────────────────────────────────────────────────────────

locals {
  required_apis = [
    "run.googleapis.com",
    "artifactregistry.googleapis.com",
    "secretmanager.googleapis.com",
    "cloudscheduler.googleapis.com",
    "storage.googleapis.com",
    "iam.googleapis.com",
    "compute.googleapis.com",
    "sqladmin.googleapis.com",
    "cloudkms.googleapis.com",
  ]
}

resource "google_project_service" "apis" {
  for_each = toset(local.required_apis)

  project                    = var.project_id
  service                    = each.value
  disable_dependent_services = false
  disable_on_destroy         = false
}

# ──────────────────────────────────────────────────────────────
# 2. Service Account
# ──────────────────────────────────────────────────────────────

resource "google_service_account" "jula_runner" {
  account_id   = var.service_account_id
  display_name = "Jula Evidence Collector Runner"
  project      = var.project_id

  depends_on = [google_project_service.apis]
}

# ──────────────────────────────────────────────────────────────
# 3. IAM Bindings
# ──────────────────────────────────────────────────────────────

locals {
  project_roles = [
    "roles/compute.viewer",
    "roles/cloudsql.viewer",
    "roles/cloudkms.viewer",
    "roles/cloudasset.viewer",
  ]
}

resource "google_project_iam_member" "jula_runner" {
  for_each = toset(local.project_roles)

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.jula_runner.email}"
}

# ──────────────────────────────────────────────────────────────
# 4. Evidence Storage Bucket
# ──────────────────────────────────────────────────────────────

resource "google_storage_bucket" "evidence" {
  name     = var.evidence_bucket_name
  project  = var.project_id
  location = var.region

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  versioning {
    enabled = true
  }

  depends_on = [google_project_service.apis]
}

resource "google_storage_bucket_iam_member" "jula_runner_storage" {
  bucket = google_storage_bucket.evidence.name
  role   = "roles/storage.admin"
  member = "serviceAccount:${google_service_account.jula_runner.email}"
}

resource "google_storage_bucket_iam_member" "owner_viewer" {
  bucket = google_storage_bucket.evidence.name
  role   = "roles/storage.objectViewer"
  member = "user:${var.owner_email}"
}

# ──────────────────────────────────────────────────────────────
# 5. Secret Manager – Secrets
# ──────────────────────────────────────────────────────────────

resource "google_secret_manager_secret" "signing_key" {
  secret_id = var.signing_key_secret_id
  project   = var.project_id

  replication {
    auto {}
  }

  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret_iam_member" "jula_runner_secret" {
  secret_id = google_secret_manager_secret.signing_key.secret_id
  project   = var.project_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.jula_runner.email}"
}

data "google_secret_manager_secret" "aik_client_id" {
  secret_id = var.aik_client_id_secret_id
  project   = var.project_id
}

resource "google_secret_manager_secret_iam_member" "jula_runner_aik_client_id" {
  secret_id = data.google_secret_manager_secret.aik_client_id.secret_id
  project   = var.project_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.jula_runner.email}"
}

data "google_secret_manager_secret" "aik_secret_key" {
  secret_id = var.aik_secret_key_secret_id
  project   = var.project_id
}

resource "google_secret_manager_secret_iam_member" "jula_runner_aik_secret_key" {
  secret_id = data.google_secret_manager_secret.aik_secret_key.secret_id
  project   = var.project_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.jula_runner.email}"
}

data "google_secret_manager_secret" "github_token" {
  secret_id = var.github_token_secret_id
  project   = var.project_id
}

resource "google_secret_manager_secret_iam_member" "jula_runner_github_token" {
  secret_id = data.google_secret_manager_secret.github_token.secret_id
  project   = var.project_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.jula_runner.email}"
}

# ──────────────────────────────────────────────────────────────
# 6. Cloud Run Service
# ──────────────────────────────────────────────────────────────

resource "google_cloud_run_v2_service" "jula" {
  name     = "jula-evidence-collector"
  location = var.region
  project  = var.project_id

  template {
    service_account                  = google_service_account.jula_runner.email
    timeout                          = "300s"
    max_instance_request_concurrency = 80

    scaling {
      max_instance_count = 1
    }

    containers {
      image = var.docker_image

      ports {
        container_port = 8080
        name           = "http1"
      }

      resources {
        cpu_idle          = true
        startup_cpu_boost = true
        limits = {
          cpu    = "1"
          memory = "256Mi"
        }
      }

      env {
        name  = "JULA_ENVIRONMENT_ID"
        value = var.project_id
      }
      env {
        name  = "GCP_PROJECT_ID"
        value = var.project_id
      }
      env {
        name  = "JULA_PLATFORM_TYPE"
        value = "GCP"
      }
      env {
        name  = "JULA_OUTPUT_TARGET"
        value = "gcs"
      }
      env {
        name  = "JULA_OUTPUT_FORMAT"
        value = "json"
      }
      env {
        name  = "JULA_OUTPUT_PATH"
        value = "gs://${google_storage_bucket.evidence.name}"
      }
      env {
        name  = "JULA_FRAMEWORK"
        value = "soc2"
      }
      env {
        name  = "JULA_PROVIDER"
        value = "gcp,aikido,github"
      }
      env {
        name  = "GITHUB_ORG"
        value = var.github_org
      }
      env {
        name  = "GITHUB_REPO"
        value = "jula-evidence-collector"
      }
      env {
        name  = "JULA_INTEGRATION_URL"
        value = "https://api.github.com/repos/${var.github_org}/jula-compliance-as-code/tarball/main"
      }
      env {
        name = "GITHUB_TOKEN"
        value_source {
          secret_key_ref {
            secret  = data.google_secret_manager_secret.github_token.secret_id
            version = "latest"
          }
        }
      }
      env {
        name = "JULA_SIGNING_KEY"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.signing_key.secret_id
            version = "latest"
          }
        }
      }
      env {
        name = "AIK_CLIENT_ID"
        value_source {
          secret_key_ref {
            secret  = data.google_secret_manager_secret.aik_client_id.secret_id
            version = "latest"
          }
        }
      }
      env {
        name = "AIK_SECRET_KEY"
        value_source {
          secret_key_ref {
            secret  = data.google_secret_manager_secret.aik_secret_key.secret_id
            version = "latest"
          }
        }
      }
    }
  }

  depends_on = [google_project_service.apis]
}

# ──────────────────────────────────────────────────────────────
# 7. Cloud Scheduler (Weekly Trigger)
# ──────────────────────────────────────────────────────────────

resource "google_cloud_scheduler_job" "jula_trigger" {
  name      = "jula-daily-evidence-collection"
  project   = var.project_id
  region    = var.region
  schedule  = var.scheduler_cron
  time_zone = var.scheduler_timezone

  attempt_deadline = "180s"

  retry_config {
    retry_count          = 0
    max_retry_duration   = "0s"
    min_backoff_duration = "5s"
    max_backoff_duration = "3600s"
    max_doublings        = 5
  }

  http_target {
    http_method = "POST"
    uri         = "${google_cloud_run_v2_service.jula.uri}/run"

    oidc_token {
      service_account_email = google_service_account.jula_runner.email
      audience              = google_cloud_run_v2_service.jula.uri
    }
  }

  depends_on = [google_project_service.apis]
}

resource "google_cloud_run_v2_service_iam_member" "invoker" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.jula.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.jula_runner.email}"
}
