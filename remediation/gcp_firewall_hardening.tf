# ──────────────────────────────────────────────────────────────
# Firewall Hardening – Disable Default Permissive Rules
# ──────────────────────────────────────────────────────────────
# GCP projects created with a "default" VPC network include
# firewall rules that allow SSH (port 22) and RDP (port 3389)
# from 0.0.0.0/0. This template explicitly disables those rules
# to satisfy CIS GCP Foundations Benchmark 3.6 and 3.7.
#
# Usage:
#   1. Copy this file into your Terraform workspace.
#   2. Provide values via terraform.tfvars.
#   3. Run: terraform init && terraform apply
# ──────────────────────────────────────────────────────────────

variable "project_id" {
  description = "GCP project ID containing the default VPC network."
  type        = string
}

variable "vpc_network_name" {
  description = "Name of the VPC network with the default firewall rules."
  type        = string
  default     = "default"
}

# ── Disable Default SSH Rule ─────────────────────────────────

resource "google_compute_firewall" "restrict_ssh" {
  name     = "default-allow-ssh"
  network  = var.vpc_network_name
  project  = var.project_id
  disabled = true

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  # Restrict SSH to Identity-Aware Proxy (IAP)
  source_ranges = ["35.235.240.0/20"]
}

# ── Disable Default RDP Rule ─────────────────────────────────

resource "google_compute_firewall" "restrict_rdp" {
  name     = "default-allow-rdp"
  network  = var.vpc_network_name
  project  = var.project_id
  disabled = true

  allow {
    protocol = "tcp"
    ports    = ["3389"]
  }
  # Restrict RDP to Identity-Aware Proxy (IAP)
  source_ranges = ["35.235.240.0/20"]
}
