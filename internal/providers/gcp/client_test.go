package gcp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// generateTestKeyJSON creates a temporary service account JSON key file for testing.
func generateTestKeyJSON(t *testing.T) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}

	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshalling PKCS8 key: %v", err)
	}

	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8,
	})

	saKey := serviceAccountKey{
		Type:         "service_account",
		ProjectID:    "test-project",
		PrivateKeyID: "key-id-123",
		PrivateKey:   string(pemBlock),
		ClientEmail:  "test@test-project.iam.gserviceaccount.com",
		ClientID:     "12345",
		TokenURI:     "https://oauth2.googleapis.com/token",
	}

	data, err := json.Marshal(saKey)
	if err != nil {
		t.Fatalf("marshalling key JSON: %v", err)
	}

	keyPath := filepath.Join(t.TempDir(), "sa-key.json")
	if err := os.WriteFile(keyPath, data, 0600); err != nil {
		t.Fatalf("writing key file: %v", err)
	}

	return keyPath
}

func TestGCPProvider_Name(t *testing.T) {
	p := &GCPProvider{}
	if p.Name() != "gcp" {
		t.Errorf("expected gcp, got %s", p.Name())
	}
}

func TestGCPProvider_Validate_MissingProjectID(t *testing.T) {
	t.Setenv("JULA_GCP_PROJECT_ID", "")
	t.Setenv("JULA_GCP_CREDENTIALS_JSON", "/tmp/fake.json")

	p := &GCPProvider{}
	err := p.Validate()
	if err == nil {
		t.Fatal("expected error for missing project ID")
	}
}

func TestGCPProvider_Validate_MissingCredentials(t *testing.T) {
	t.Setenv("JULA_GCP_PROJECT_ID", "test-project")
	t.Setenv("JULA_GCP_CREDENTIALS_JSON", "")

	p := &GCPProvider{}
	err := p.Validate()
	if err == nil {
		t.Fatal("expected error for missing credentials path")
	}
}

func TestGCPProvider_Validate_BadCredentialsPath(t *testing.T) {
	t.Setenv("JULA_GCP_PROJECT_ID", "test-project")
	t.Setenv("JULA_GCP_CREDENTIALS_JSON", "/nonexistent/path/key.json")

	p := &GCPProvider{}
	err := p.Validate()
	if err == nil {
		t.Fatal("expected error for nonexistent credentials file")
	}
}

func TestGCPProvider_Validate_InvalidJSON(t *testing.T) {
	t.Setenv("JULA_GCP_PROJECT_ID", "test-project")

	badFile := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(badFile, []byte("not json"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("JULA_GCP_CREDENTIALS_JSON", badFile)

	p := &GCPProvider{}
	err := p.Validate()
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestGCPProvider_Validate_ValidCredentials(t *testing.T) {
	t.Setenv("JULA_GCP_PROJECT_ID", "test-project")
	t.Setenv("JULA_GCP_CREDENTIALS_JSON", generateTestKeyJSON(t))

	p := &GCPProvider{}
	err := p.Validate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.projectID != "test-project" {
		t.Errorf("expected project test-project, got %s", p.projectID)
	}
}

func TestGCPProvider_Extract_RunsAllExtractors(t *testing.T) {
	// Set up a test server that returns valid responses for all three extractors.
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)

		switch {
		case callCount == 1:
			// Audit logging: IAM policy response.
			json.NewEncoder(w).Encode(map[string]any{
				"auditConfigs": []map[string]any{
					{
						"service": "allServices",
						"auditLogConfigs": []map[string]string{
							{"logType": "ADMIN_READ"},
						},
					},
				},
			})
		case callCount == 2:
			// Storage: bucket list.
			json.NewEncoder(w).Encode(map[string]any{
				"items": []map[string]any{
					{"name": "test-bucket"},
				},
			})
		case callCount == 3:
			// IAM: service account list.
			json.NewEncoder(w).Encode(map[string]any{
				"accounts": []map[string]any{},
			})
		default:
			json.NewEncoder(w).Encode(map[string]any{})
		}
	}))
	defer server.Close()

	p := &GCPProvider{
		projectID:  "test-project",
		httpClient: server.Client(),
		tokenSource: &tokenSource{
			cachedToken: "test-token",
			tokenExpiry: time.Now().Add(1 * time.Hour),
		},
	}
	p.httpClient.Transport = &testTransport{serverURL: server.URL}

	findings, err := p.Extract(context.Background(), "test-run")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) < 2 {
		t.Errorf("expected at least 2 findings, got %d", len(findings))
	}
}

func TestGCPProvider_Extract_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	p := &GCPProvider{
		projectID:  "test-project",
		httpClient: &http.Client{},
		tokenSource: &tokenSource{
			cachedToken: "test-token",
			tokenExpiry: time.Now().Add(1 * time.Hour),
		},
	}

	_, err := p.Extract(ctx, "test-run")
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

func TestGCPProvider_doRequest_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("expected Bearer test-token, got %s", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	p := &GCPProvider{
		projectID:  "test-project",
		httpClient: server.Client(),
		tokenSource: &tokenSource{
			cachedToken: "test-token",
			tokenExpiry: time.Now().Add(1 * time.Hour),
		},
	}

	body, err := p.doRequest(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(body) != `{"status": "ok"}` {
		t.Errorf("unexpected body: %s", string(body))
	}
}

func TestGCPProvider_doRequest_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error": "forbidden"}`))
	}))
	defer server.Close()

	p := &GCPProvider{
		projectID:  "test-project",
		httpClient: server.Client(),
		tokenSource: &tokenSource{
			cachedToken: "test-token",
			tokenExpiry: time.Now().Add(1 * time.Hour),
		},
	}

	_, err := p.doRequest(context.Background(), server.URL)
	if err == nil {
		t.Fatal("expected error for 403 response")
	}
}

func TestNewTokenSource_ValidKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	pemData := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})

	saKey := &serviceAccountKey{
		PrivateKey:  string(pemData),
		ClientEmail: "test@example.com",
	}

	ts, err := newTokenSource(saKey, &http.Client{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ts == nil {
		t.Fatal("expected non-nil token source")
	}
}

func TestNewTokenSource_InvalidPEM(t *testing.T) {
	saKey := &serviceAccountKey{
		PrivateKey: "not-a-pem-block",
	}

	_, err := newTokenSource(saKey, &http.Client{})
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestTokenSource_CachedToken(t *testing.T) {
	ts := &tokenSource{
		cachedToken: "cached-token-value",
		tokenExpiry: time.Now().Add(1 * time.Hour),
	}

	token, err := ts.Token()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "cached-token-value" {
		t.Errorf("expected cached-token-value, got %s", token)
	}
}

func TestTokenSource_Refresh(t *testing.T) {
	// Set up a mock token endpoint.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(tokenResponse{
			AccessToken: "fresh-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer server.Close()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	ts := &tokenSource{
		key: &serviceAccountKey{
			ClientEmail: "test@example.com",
		},
		privateKey:  key,
		scopes:      []string{"https://www.googleapis.com/auth/cloud-platform.read-only"},
		httpClient:  server.Client(),
		tokenURL:    server.URL,
		cachedToken: "",
		tokenExpiry: time.Time{}, // Expired.
	}

	token, err := ts.Token()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "fresh-token" {
		t.Errorf("expected fresh-token, got %s", token)
	}
	if ts.cachedToken != "fresh-token" {
		t.Errorf("token was not cached")
	}
}
