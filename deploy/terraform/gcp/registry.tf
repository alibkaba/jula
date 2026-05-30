resource "google_artifact_registry_repository" "collector" {
  location      = var.region
  repository_id = "jula-collector"
  description   = "Docker repository for Jula Collector"
  format        = "DOCKER"
}

resource "google_artifact_registry_repository" "evaluator" {
  location      = var.region
  repository_id = "jula-evaluator"
  description   = "Docker repository for Jula Evaluator"
  format        = "DOCKER"
}
