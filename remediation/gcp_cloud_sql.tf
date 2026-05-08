# remediation/cloud_sql.tf
#
# Remediates: gcp.sql.secure_config == FAIL (Public IP or disabled backups)
# SOC 2 Criteria: CC6.1 (Logical Access), A1.2 (Recovery)
#
# This blueprint configures a PostgreSQL instance to strictly use Private IP
# and enforces automated daily backups.

variable "network_id" {
  description = "The self_link of the VPC network."
  type        = string
}

resource "google_sql_database_instance" "secure_postgres" {
  name             = "production-db"
  database_version = "POSTGRES_15"
  region           = "us-central1"

  settings {
    tier = "db-custom-2-7680"

    # Enforce Private IP Only (CC6.1)
    ip_configuration {
      ipv4_enabled    = false
      private_network = var.network_id
      require_ssl     = true
    }

    # Enforce Automated Backups (A1.2)
    backup_configuration {
      enabled                        = true
      start_time                     = "03:00"
      point_in_time_recovery_enabled = true
      transaction_log_retention_days = 7
    }
  }
}
