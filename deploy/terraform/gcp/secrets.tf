# Adopt existing secrets rather than creating them, to prevent destroying the keys
data "google_secret_manager_secret" "signing_key" {
  secret_id = "jula-signing-key"
}

data "google_secret_manager_secret" "public_key" {
  secret_id = "jula-public-key"
}

data "google_secret_manager_secret" "github_token" {
  secret_id = "jula-github-token"
}

data "google_secret_manager_secret" "aikido_client_id" {
  secret_id = "jula-aikido-client-id"
}

data "google_secret_manager_secret" "aikido_secret_key" {
  secret_id = "jula-aikido-secret-key"
}
