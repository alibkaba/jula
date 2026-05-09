# ──────────────────────────────────────────────────────────────
# Jula Remediation Template: Artifact Registry Governance
# ──────────────────────────────────────────────────────────────
# Jula Finding: gcp.registry.lifecycle_policy == FAIL
# Frameworks: SOC 2 CC6.1, CC7.1
# ──────────────────────────────────────────────────────────────

variable "project_id" {
  type        = string
  description = "The GCP project ID."
}

variable "region" {
  type        = string
  description = "The GCP region."
  default     = "us-central1"
}

variable "repository_name" {
  type        = string
  description = "The name of the Artifact Registry repository."
}

resource "google_artifact_registry_repository" "remediated_registry" {
  location      = var.region
  repository_id = var.repository_name
  project       = var.project_id
  format        = "DOCKER"
  description   = "Secure Docker repository with Tiered Retention Policy"

  # 1. Protect the 15 most recent SemVer releases (tags starting with 'v')
  cleanup_policies {
    id     = "keep-recent-releases"
    action = "KEEP"
    condition {
      tag_prefixes = ["v"]
    }
    most_recent_versions {
      keep_count = 15
    }
  }

  # 2. Protect only the single most recent 'latest' tag
  cleanup_policies {
    id     = "keep-latest-tag"
    action = "KEEP"
    condition {
      tag_prefixes = ["latest"]
    }
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
      older_than = "2592000s" # 30 Days
    }
  }
}
