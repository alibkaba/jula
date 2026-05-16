package gcp

import (
	"encoding/json"
	"testing"
)

func TestServiceAccountKey_JSON(t *testing.T) {
	jsonData := `{
		"type": "service_account",
		"project_id": "test-project",
		"private_key_id": "pk-id",
		"private_key": "---BEGIN PRIVATE KEY---...",
		"client_email": "test@example.com",
		"client_id": "123",
		"auth_uri": "https://auth",
		"token_uri": "https://token",
		"auth_provider_x509_cert_url": "https://auth-cert",
		"client_x509_cert_url": "https://client-cert"
	}`

	var key serviceAccountKey
	err := json.Unmarshal([]byte(jsonData), &key)
	if err != nil {
		t.Fatalf("failed to unmarshal service account key: %v", err)
	}

	if key.ProjectID != "test-project" {
		t.Errorf("expected project_id test-project, got %s", key.ProjectID)
	}
}

func TestTokenResponse_JSON(t *testing.T) {
	jsonData := `{
		"access_token": "mock-token",
		"token_type": "Bearer",
		"expires_in": 3600
	}`

	var resp tokenResponse
	err := json.Unmarshal([]byte(jsonData), &resp)
	if err != nil {
		t.Fatalf("failed to unmarshal token response: %v", err)
	}

	if resp.AccessToken != "mock-token" {
		t.Errorf("expected access_token mock-token, got %s", resp.AccessToken)
	}
}
