# ──────────────────────────────────────────────────────────────
# Jula Evidence Evaluator – Infrastructure
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

resource "google_service_account" "jula_eval_runner" {
  account_id   = var.service_account_id
  display_name = "Jula Evidence Evaluator Runner"
  project      = var.project_id

  depends_on = [google_project_service.apis]
}

# ──────────────────────────────────────────────────────────────
# 3. IAM Bindings
# ──────────────────────────────────────────────────────────────

# Grant the evaluator read access to the evidence bucket.
resource "google_storage_bucket_iam_member" "eval_runner_storage" {
  bucket = var.evidence_bucket_name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.jula_eval_runner.email}"
}

# ──────────────────────────────────────────────────────────────
# 4. Secret Manager – Bindings
# ──────────────────────────────────────────────────────────────

data "google_secret_manager_secret" "signing_key" {
  secret_id = var.signing_key_secret_id
  project   = var.project_id
}

resource "google_secret_manager_secret_iam_member" "eval_runner_signing_key" {
  secret_id = data.google_secret_manager_secret.signing_key.secret_id
  project   = var.project_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.jula_eval_runner.email}"
}

data "google_secret_manager_secret" "github_token" {
  secret_id = var.github_token_secret_id
  project   = var.project_id
}

resource "google_secret_manager_secret_iam_member" "eval_runner_github_token" {
  secret_id = data.google_secret_manager_secret.github_token.secret_id
  project   = var.project_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.jula_eval_runner.email}"
}

# ──────────────────────────────────────────────────────────────
# 5. Cloud Run Service
# ──────────────────────────────────────────────────────────────

resource "google_cloud_run_v2_service" "jula_eval" {
  name     = "jula-evidence-evaluator"
  location = var.region
  project  = var.project_id

  template {
    service_account                  = google_service_account.jula_eval_runner.email
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
        name  = "GCP_PROJECT_ID"
        value = var.project_id
      }
      env {
        name  = "JULA_PLATFORM_TYPE"
        value = "GCP"
      }
      env {
        name  = "JULA_OUTPUT_PATH"
        value = "gs://${var.evidence_bucket_name}"
      }
      env {
        name  = "JULA_FRAMEWORK"
        value = "soc2"
      }
      env {
        name  = "JULA_POLICY_URL"
        value = var.policy_repo_url
      }
      env {
        name  = "GITHUB_ORG"
        value = var.github_org
      }
      env {
        name  = "GITHUB_REPO"
        value = "jula-evidence-evaluator"
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
            secret  = data.google_secret_manager_secret.signing_key.secret_id
            version = "latest"
          }
        }
      }
    }
  }

  depends_on = [google_project_service.apis]
}

# ──────────────────────────────────────────────────────────────
# 6. Cloud Scheduler (Daily Trigger)
# ──────────────────────────────────────────────────────────────

resource "google_cloud_scheduler_job" "jula_eval_trigger" {
  name      = "jula-daily-evidence-evaluation"
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
    uri         = "${google_cloud_run_v2_service.jula_eval.uri}/run"

    oidc_token {
      service_account_email = google_service_account.jula_eval_runner.email
      audience              = google_cloud_run_v2_service.jula_eval.uri
    }
  }

  depends_on = [google_project_service.apis]
}

resource "google_cloud_run_v2_service_iam_member" "invoker" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.jula_eval.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.jula_eval_runner.email}"
}
