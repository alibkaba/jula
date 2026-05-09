# ──────────────────────────────────────────────────────────────
# CIS Log-Based Metrics & Alert Policies
# ──────────────────────────────────────────────────────────────
# Satisfies CIS GCP Foundations Benchmark 1.2/1.3:
#   - 2.1  Project Ownership Changes
#   - 2.4  VPC Firewall Rule Changes
#   - 2.5  Audit Configuration Changes
#   - 2.9  Cloud Storage IAM Permission Changes
#
# Usage:
#   1. Copy this file into your Terraform workspace.
#   2. Provide values via terraform.tfvars.
#   3. Run: terraform init && terraform apply
# ──────────────────────────────────────────────────────────────

variable "project_id" {
  description = "GCP project ID to create log metrics and alerts in."
  type        = string
}

variable "alert_notification_email" {
  description = "Email address to receive security alert notifications."
  type        = string
}

# ── Notification Channel ─────────────────────────────────────

resource "google_monitoring_notification_channel" "security_alerts" {
  display_name = "Security Alerts"
  type         = "email"
  project      = var.project_id

  labels = {
    email_address = var.alert_notification_email
  }
}

# ── 2.1 Project Ownership Changes ────────────────────────────

resource "google_logging_metric" "project_ownership_changes" {
  name    = "project-ownership-changes"
  project = var.project_id
  filter  = "(protoPayload.serviceName=\"cloudresourcemanager.googleapis.com\") AND (ProjectOwnership OR projectOwnerInvitee) OR (protoPayload.serviceData.policyDelta.bindingDeltas.action=\"REMOVE\" AND protoPayload.serviceData.policyDelta.bindingDeltas.role=\"roles/owner\") OR (protoPayload.serviceData.policyDelta.bindingDeltas.action=\"ADD\" AND protoPayload.serviceData.policyDelta.bindingDeltas.role=\"roles/owner\")"

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "project_ownership_changes" {
  display_name = "Project Ownership Changes"
  project      = var.project_id
  combiner     = "OR"

  conditions {
    display_name = "Project ownership change detected"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/project-ownership-changes\" AND resource.type=\"global\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_COUNT"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.security_alerts.name]

  alert_strategy {
    auto_close = "604800s"
  }
}

# ── 2.4 VPC Firewall Rule Changes ────────────────────────────

resource "google_logging_metric" "firewall_rule_changes" {
  name    = "firewall-rule-changes"
  project = var.project_id
  filter  = "resource.type=\"gce_firewall_rule\" AND protoPayload.methodName:\"compute.firewalls.insert\" OR protoPayload.methodName:\"compute.firewalls.patch\" OR protoPayload.methodName:\"compute.firewalls.delete\""

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "firewall_rule_changes" {
  display_name = "VPC Firewall Rule Changes"
  project      = var.project_id
  combiner     = "OR"

  conditions {
    display_name = "Firewall rule change detected"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/firewall-rule-changes\" AND resource.type=\"global\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_COUNT"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.security_alerts.name]

  alert_strategy {
    auto_close = "604800s"
  }
}

# ── 2.5 Audit Configuration Changes ─────────────────────────

resource "google_logging_metric" "audit_config_changes" {
  name    = "audit-config-changes"
  project = var.project_id
  filter  = "protoPayload.methodName=\"SetIamPolicy\" AND protoPayload.serviceData.policyDelta.auditConfigDeltas:*"

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "audit_config_changes" {
  display_name = "Audit Configuration Changes"
  project      = var.project_id
  combiner     = "OR"

  conditions {
    display_name = "Audit config change detected"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/audit-config-changes\" AND resource.type=\"global\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_COUNT"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.security_alerts.name]

  alert_strategy {
    auto_close = "604800s"
  }
}

# ── 2.9 Cloud Storage IAM Permission Changes ────────────────

resource "google_logging_metric" "storage_permission_changes" {
  name    = "storage-permission-changes"
  project = var.project_id
  filter  = "resource.type=\"gcs_bucket\" AND protoPayload.methodName=\"storage.setIamPermissions\""

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_monitoring_alert_policy" "storage_permission_changes" {
  display_name = "Storage Permission Changes"
  project      = var.project_id
  combiner     = "OR"

  conditions {
    display_name = "Storage permission change detected"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/storage-permission-changes\" AND resource.type=\"gcs_bucket\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_COUNT"
      }
    }
  }

  notification_channels = [google_monitoring_notification_channel.security_alerts.name]

  alert_strategy {
    auto_close = "604800s"
  }
}
