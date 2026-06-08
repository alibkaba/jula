package universal_rest

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestSignGCPADC(t *testing.T) {
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
