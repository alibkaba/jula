# Generate secure ECDSA key pair dynamically in Terraform
resource "tls_private_key" "signing_key" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

# Jula Signing Key (Private Key)
resource "google_secret_manager_secret" "signing_key" {
  secret_id = "jula-signing-key"
  replication {
    auto {}
  }
}
resource "google_secret_manager_secret_version" "signing_key" {
  secret      = google_secret_manager_secret.signing_key.id
  secret_data = tls_private_key.signing_key.private_key_pem
}

# Jula Public Key (Verification Key)
resource "google_secret_manager_secret" "public_key" {
  secret_id = "jula-public-key"
  replication {
    auto {}
  }
}
resource "google_secret_manager_secret_version" "public_key" {
  secret      = google_secret_manager_secret.public_key.id
  secret_data = tls_private_key.signing_key.public_key_pem
}

# Source Token
resource "google_secret_manager_secret" "source_token" {
  secret_id = var.source_token_secret_id
  replication {
    auto {}
  }
}
resource "google_secret_manager_secret_version" "source_token" {
  secret      = google_secret_manager_secret.source_token.id
  secret_data = var.source_token
}

# Dispatch Token
resource "google_secret_manager_secret" "dispatch_token" {
  secret_id = "jula-dispatch-token"
  replication {
    auto {}
  }
}
resource "google_secret_manager_secret_version" "dispatch_token" {
  secret      = google_secret_manager_secret.dispatch_token.id
  secret_data = var.dispatch_token
}

