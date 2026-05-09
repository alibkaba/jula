# firewall_hardening.tf – Environment-specific: jula-494603
# This file is .gitignored and should NOT be committed to the public repository.
# Generic template: remediation/firewall_hardening.tf

resource "google_compute_firewall" "restrict_ssh" {
  name     = "default-allow-ssh"
  network  = "default"
  project  = var.project_id
  disabled = true

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  source_ranges = ["35.235.240.0/20"]
}

resource "google_compute_firewall" "restrict_rdp" {
  name     = "default-allow-rdp"
  network  = "default"
  project  = var.project_id
  disabled = true

  allow {
    protocol = "tcp"
    ports    = ["3389"]
  }
  source_ranges = ["35.235.240.0/20"]
}
