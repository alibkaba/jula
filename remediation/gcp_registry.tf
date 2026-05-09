# ──────────────────────────────────────────────────────────────
# Jula Remediation Template: GCP Artifact Registry Governance
# ──────────────────────────────────────────────────────────────
# Jula Finding: gcp.registry.lifecycle_policy == FAIL
# Frameworks: SOC 2 CC6.1, CC7.1
#
# Implements the "Tiered Union Strategy":
# 1. Protects environment tags (prod, staging) explicitly.
# 2. Protects semantic versions (v*) for audit/rollback.
# 3. Maintains a rolling 30-image buffer for all other SHAs.
# 4. Purges everything else via a global DELETE.
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
  description   = "Secure Docker repository with Tiered Union Strategy"

  # POLICY 1: Protect Environment Tags (KEEP)
  cleanup_policies {
    id     = "keep-environments"
    action = "KEEP"
    condition {
      tag_state    = "TAGGED"
      tag_prefixes = ["prod", "staging", "latest"]
    }
  }

  # POLICY 2: Protect Semantic Versions (KEEP)
  cleanup_policies {
    id     = "keep-semver"
    action = "KEEP"
    condition {
      tag_state    = "TAGGED"
      tag_prefixes = ["v"]
    }
  }

  # POLICY 3: Rolling FinOps Buffer (KEEP)
  cleanup_policies {
    id     = "keep-recent-buffer"
    action = "KEEP"
    most_recent_versions {
      keep_count = 30
    }
  }

  # POLICY 4: Global Garbage Collector (DELETE)
  cleanup_policies {
    id     = "delete-the-rest"
    action = "DELETE"
    condition {
      tag_state = "ANY"
    }
  }
}
