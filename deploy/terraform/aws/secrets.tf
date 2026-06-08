# Generate secure ECDSA key pair dynamically in Terraform
resource "tls_private_key" "signing_key" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

# Jula Signing Key (Private Key)
resource "aws_secretsmanager_secret" "signing_key" {
  name                    = "jula-signing-key"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "signing_key" {
  secret_id     = aws_secretsmanager_secret.signing_key.id
  secret_string = tls_private_key.signing_key.private_key_pem
}

# Jula Public Key (Verification Key)
resource "aws_secretsmanager_secret" "public_key" {
  name                    = "jula-public-key"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "public_key" {
  secret_id     = aws_secretsmanager_secret.public_key.id
  secret_string = tls_private_key.signing_key.public_key_pem
}

# Source Token (Git provider API token)
resource "aws_secretsmanager_secret" "source_token" {
  name                    = "jula-source-token"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "source_token" {
  secret_id     = aws_secretsmanager_secret.source_token.id
  secret_string = var.source_token
}

# Jula Dispatch Token
resource "aws_secretsmanager_secret" "dispatch_token" {
  name                    = "jula-dispatch-token"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "dispatch_token" {
  secret_id     = aws_secretsmanager_secret.dispatch_token.id
  secret_string = var.dispatch_token
}
