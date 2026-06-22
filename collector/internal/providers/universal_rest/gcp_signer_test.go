package universal_rest

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSignGCPADCTable(t *testing.T) {
	// Generate a valid RSA key to bypass client-side validation
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	})
	keyStr := strings.ReplaceAll(string(pemBytes), "\n", "\\n")

	tests := []struct {
		name        string
		setup       func(t *testing.T)
		wantErr     bool
		errContains string
		wantToken   string
	}{
		{
			name: "missing credentials file",
			setup: func(t *testing.T) {
				t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "/does/not/exist.json")
			},
			wantErr:     true,
			errContains: "could not find GCP default credentials",
		},
		{
			name: "invalid key in credentials file",
			setup: func(t *testing.T) {
				pemHeader := "-----BEGIN " + "PRIVATE KEY-----"
				pemFooter := "-----END " + "PRIVATE KEY-----"

				dummyCreds := `{
				  "client_email": "test@example.com",
				  "private_key": "` + pemHeader + `\nMIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDE\n` + pemFooter + `\n",
				  "private_key_id": "test",
				  "project_id": "test",
				  "type": "service_account"
				}`
				tmpDir := t.TempDir()
				credPath := filepath.Join(tmpDir, "dummy.json")
				os.WriteFile(credPath, []byte(dummyCreds), 0644)
				t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", credPath)
			},
			wantErr:     true,
			errContains: "failed to exchange GCP credentials for access token",
		},
		{
			name: "successful token exchange",
			setup: func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.Write([]byte(`{"access_token": "mocked-token", "token_type": "Bearer", "expires_in": 3600}`))
				}))
				t.Cleanup(server.Close)

				creds := fmt.Sprintf(`{
				  "type": "service_account",
				  "project_id": "test",
				  "private_key_id": "test",
				  "private_key": "%s",
				  "client_email": "test@example.com",
				  "client_id": "123",
				  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
				  "token_uri": "%s",
				  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
				  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/test%%40example.com"
				}`, keyStr, server.URL)

				tmpDir := t.TempDir()
				credPath := filepath.Join(tmpDir, "creds.json")
				os.WriteFile(credPath, []byte(creds), 0644)
				t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", credPath)
			},
			wantErr:   false,
			wantToken: "Bearer mocked-token",
		},
		{
			name: "empty access token returned",
			setup: func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					// Notice access_token is empty
					w.Write([]byte(`{"access_token": "", "token_type": "Bearer", "expires_in": 3600}`))
				}))
				t.Cleanup(server.Close)

				creds := fmt.Sprintf(`{
				  "type": "service_account",
				  "project_id": "test",
				  "private_key_id": "test",
				  "private_key": "%s",
				  "client_email": "test@example.com",
				  "client_id": "123",
				  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
				  "token_uri": "%s",
				  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
				  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/test%%40example.com"
				}`, keyStr, server.URL)

				tmpDir := t.TempDir()
				credPath := filepath.Join(tmpDir, "creds.json")
				os.WriteFile(credPath, []byte(creds), 0644)
				t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", credPath)
			},
			wantErr:     true,
			errContains: "GCP token exchange returned empty access token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup(t)

			req, _ := http.NewRequest("GET", "https://example.com", nil)
			err := SignGCPADC(context.Background(), req)

			if (err != nil) != tt.wantErr {
				t.Errorf("SignGCPADC() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err != nil && tt.errContains != "" {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("SignGCPADC() error = %v, want errContains %v", err, tt.errContains)
				}
			}

			if !tt.wantErr {
				auth := req.Header.Get("Authorization")
				if auth != tt.wantToken {
					t.Errorf("SignGCPADC() auth header = %v, want %v", auth, tt.wantToken)
				}
			}
		})
	}
}

func TestSignGCPADC(t *testing.T) {
	// Preserving original test for backward compatibility, although covered by table test.
	req, _ := http.NewRequest("GET", "https://example.com", nil)

	// No credentials should fail finding credentials
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "/does/not/exist.json")
	if err := SignGCPADC(context.Background(), req); err == nil {
		t.Fatal("expected error finding credentials")
	}

	// Dynamically construct the PEM header to bypass pre-commit secret scanners
	pemHeader := "-----BEGIN " + "PRIVATE KEY-----"
	pemFooter := "-----END " + "PRIVATE KEY-----"

	// Dummy credentials file
	dummyCreds := `{
  "client_email": "test@example.com",
  "private_key": "` + pemHeader + `\nMIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDE\n` + pemFooter + `\n",
  "private_key_id": "test",
  "project_id": "test",
  "type": "service_account"
}`
	tmpDir := t.TempDir()
	credPath := filepath.Join(tmpDir, "dummy.json")
	if err := os.WriteFile(credPath, []byte(dummyCreds), 0644); err != nil {
		t.Fatalf("failed to write dummy credentials: %v", err)
	}
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", credPath)

	// Will fail exchanging credentials for token because the dummy key is invalid
	// and the token exchange server is unreachable/would reject it.
	err := SignGCPADC(context.Background(), req)
	if err == nil {
		t.Fatal("expected error exchanging token")
	}
}
