# Placeholder image for initial standup. Artifact Registry is empty until
# CI/CD pushes the first build. CI/CD overwrites via: gcloud run deploy --image ...
locals {
  placeholder = "us-docker.pkg.dev/cloudrun/container/hello:latest"
}

resource "google_cloud_run_v2_service" "jula_collector" {
  name     = "jula-collector"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_ALL"

  # Wait for IAM propagation before creating the revision.
  # Cloud Run validates secret access at revision creation time.
  depends_on = [google_project_iam_member.secret_accessor]

  template {
    service_account = google_service_account.jula_runner.email

    containers {
      image = local.placeholder

      env {
        name  = "JULA_OUTPUT_PATH"
        value = "gs://${google_storage_bucket.evidence.name}"
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
        name = var.source_token_env_name
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.source_token.secret_id
            version = "latest"
          }
        }
      }

      env {
        name  = "JULA_SOURCE_ORG"
        value = var.git_org
      }

      env {
        name  = "JULA_INTEGRATION_URL"
        value = var.integration_url
      }

      env {
        name  = "JULA_SOURCE_TOKEN_ENV"
        value = var.source_token_env_name
      }

      env {
        name  = "JULA_ALLOWED_HOSTS"
        value = var.allowed_hosts
      }
      
      env {
        name  = "GCP_PROJECT_ID"
        value = var.project_id
      }

      env {
        name  = "JULA_DEPLOYMENT_ID"
        value = random_string.deployment_id.result
      }

      env {
        name  = "JULA_PROVIDER"
        value = var.jula_provider
      }

      env {
        name  = "JULA_SOURCE_REPO"
        value = "jula"
      }
    }
  }
}

resource "google_cloud_run_v2_service" "jula_evaluator" {
  name     = "jula-evaluator"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_ALL"

  depends_on = [google_project_iam_member.secret_accessor]

  template {
    service_account = google_service_account.jula_runner.email

    containers {
      image = local.placeholder

      env {
        name  = "JULA_BUCKET_URL"
        value = "gs://${google_storage_bucket.evidence.name}"
      }

      env {
        name  = "JULA_POLICY_URL"
        value = var.policy_url
      }

      env {
        name  = "JULA_GOVERNOR_REPO"
        value = var.governor_repo
      }

      env {
        name  = "JULA_SOURCE_TOKEN_ENV"
        value = var.source_token_env_name
      }

      env {
        name = "JULA_PUBLIC_KEY"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.public_key.secret_id
            version = "latest"
          }
        }
      }

      env {
        name = var.source_token_env_name
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.source_token.secret_id
            version = "latest"
          }
        }
      }

      env {
        name = "JULA_DISPATCH_TOKEN"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.dispatch_token.secret_id
            version = "latest"
          }
        }
      }

      env {
        name  = "JULA_DEPLOYMENT_ID"
        value = random_string.deployment_id.result
      }
    }
  }
}

# Allow public unauthenticated invocation (for webhook triggers)
resource "google_cloud_run_service_iam_binding" "public_access" {
  location = google_cloud_run_v2_service.jula_collector.location
  project  = google_cloud_run_v2_service.jula_collector.project
  service  = google_cloud_run_v2_service.jula_collector.name
  role     = "roles/run.invoker"
  members  = ["allUsers"]
}

resource "google_cloud_run_service_iam_binding" "evaluator_public_access" {
  location = google_cloud_run_v2_service.jula_evaluator.location
  project  = google_cloud_run_v2_service.jula_evaluator.project
  service  = google_cloud_run_v2_service.jula_evaluator.name
  role     = "roles/run.invoker"
  members  = ["allUsers"]
}
