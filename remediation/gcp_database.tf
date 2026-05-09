# ──────────────────────────────────────────────────────────────
# Jula Remediation Template: GCP Cloud SQL Hardening
# ──────────────────────────────────────────────────────────────
# Jula Finding: gcp.database.secure_config == FAIL
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

variable "database_instance_name" {
  type        = string
  description = "The name of the Cloud SQL instance."
}

resource "google_sql_database_instance" "remediated_db" {
  name             = var.database_instance_name
  project          = var.project_id
  region           = var.region
  database_version = "POSTGRES_15"

  settings {
    tier = "db-f1-micro"

    # Enforce SSL/TLS for all connections
    ip_configuration {
      require_ssl = true
    }

    # Enable automated backups and point-in-time recovery
    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
    }

    # Restrict public access (use Private IP or Auth Proxy in prod)
    location_preference {
      zone = "${var.region}-a"
    }
  }

  deletion_protection = true
}
