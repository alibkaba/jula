# Adopt existing secrets rather than creating them, to prevent destroying the keys
data "google_secret_manager_secret" "signing_key" {
  secret_id = "jula-signing-key"
}

data "google_secret_manager_secret" "public_key" {
  secret_id = "jula-public-key"
}

data "google_secret_manager_secret" "source_token" {
  secret_id = var.source_token_secret_id
}

data "google_secret_manager_secret" "dispatch_token" {
  secret_id = "jula-dispatch-token"
}
