resource "google_cloud_scheduler_job" "collector_trigger" {
  name             = "jula-daily-evidence-collection"
  description      = "Daily trigger for Jula Collector"
  schedule         = "0 3 * * *"
  time_zone        = "Etc/UTC"
  attempt_deadline = "320s"

  http_target {
    http_method = "POST"
    uri         = "${google_cloud_run_v2_service.jula_collector.uri}/run"

    oidc_token {
      service_account_email = google_service_account.jula_runner.email
    }
  }
}

resource "google_cloud_scheduler_job" "evaluator_trigger" {
  name             = "jula-daily-evidence-evaluation"
  description      = "Daily trigger for Jula Evaluator"
  schedule         = "30 3 * * *"
  time_zone        = "Etc/UTC"
  attempt_deadline = "320s"

  http_target {
    http_method = "POST"
    uri         = "${google_cloud_run_v2_service.jula_evaluator.uri}/run"

    oidc_token {
      service_account_email = google_service_account.jula_runner.email
    }
  }
}
