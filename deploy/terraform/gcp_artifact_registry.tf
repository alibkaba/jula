# ──────────────────────────────────────────────────────────────
# Jula Evidence Collector – Artifact Registry
# ──────────────────────────────────────────────────────────────

resource "google_artifact_registry_repository" "jula_registry" {
  location      = var.region
  repository_id = var.repository_name
  project       = var.project_id
  format        = "DOCKER"
  description   = "Jula Evidence Collector - Tiered Retention Registry"

  # 1. Protect the 15 most recent versions (Global Buffer)
  cleanup_policies {
    id     = "keep-recent-releases"
    action = "KEEP"
    most_recent_versions {
      keep_count = 15
    }
  }

  # 2. Protect the single most recent 'latest' tag
  # Note: In the google provider, most_recent_versions applies to the whole repo.
  # We use this as a secondary safety for the latest build.
  cleanup_policies {
    id     = "keep-latest-tag"
    action = "KEEP"
    most_recent_versions {
      keep_count = 1
    }
  }

  # 3. Protect images in-flight (untagged safety buffer)
  cleanup_policies {
    id     = "keep-recent-untagged"
    action = "KEEP"
    condition {
      tag_state = "UNTAGGED"
    }
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
