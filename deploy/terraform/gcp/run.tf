resource "google_cloud_run_v2_service" "jula_collector" {
  name     = "jula-collector"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_ALL"

  template {
    service_account = google_service_account.jula_runner.email

    containers {
      # Use the image that was deployed by GitHub Actions
      image = "us-central1-docker.pkg.dev/${var.project_id}/${var.repository_name}/jula:${var.collector_image_tag}"

      env {
        name  = "JULA_OUTPUT_TARGET"
        value = "gcs"
      }
      env {
        name  = "JULA_OUTPUT_PATH"
        value = "gs://${google_storage_bucket.evidence.name}"
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
        name = "AIK_CLIENT_ID"
        value_source {
          secret_key_ref {
            secret  = data.google_secret_manager_secret.aikido_client_id.secret_id
            version = "latest"
          }
        }
      }

      env {
        name = "AIK_SECRET_KEY"
        value_source {
          secret_key_ref {
            secret  = data.google_secret_manager_secret.aikido_secret_key.secret_id
            version = "latest"
          }
        }
      }

      env {
        name  = "JULA_INTEGRATION_URL"
        value = "https://api.github.com/repos/alibkaba/jula/tarball/main"
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
