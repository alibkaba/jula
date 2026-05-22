# ──────────────────────────────────────────────────────────────
# Jula Evidence Evaluator – Artifact Registry
# ──────────────────────────────────────────────────────────────

resource "google_artifact_registry_repository" "jula_eval_registry" {
  location      = var.region
  repository_id = var.repository_name
  project       = var.project_id
  format        = "DOCKER"
  description   = "Jula Evidence Evaluator - Tiered Retention Registry"

  # 1. Protect the 15 most recent versions (Global Buffer)
  cleanup_policies {
    id     = "keep-recent-releases"
    action = "KEEP"
    most_recent_versions {
      keep_count = 15
    }
  }

  # 2. Protect the single most recent 'latest' tag
  cleanup_policies {
    id     = "keep-latest-tag"
    action = "KEEP"
    most_recent_versions {
      keep_count = 1
    }
  }

  # 3. Protect images in-flight (Buffer for recent builds)
  cleanup_policies {
    id     = "keep-buffer-versions"
    action = "KEEP"
    most_recent_versions {
      keep_count = 5
    }
  }

  # 4. Global Garbage Collection: Purge everything else older than 30 days
  cleanup_policies {
    id     = "delete-everything-else-older-than-30-days"
    action = "DELETE"
    condition {
      tag_state  = "ANY"
      older_than = "2592000s" # 30 Days (24h * 30 * 3600)
    }
  }
}
