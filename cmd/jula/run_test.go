package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func generateTestKey() (string, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return "", err
	}
	pemBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	}
	return string(pem.EncodeToMemory(pemBlock)), nil
}

// TestHandleRun_HappyPath verifies that handleRun passes CLI validation
// (PEM parsing, target/path resolution) before reaching the extraction
// stage. It is expected to fail at extraction since no cloud credentials
// or config files are available in CI.
func TestHandleRun_HappyPath(t *testing.T) {
	key, err := generateTestKey()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	t.Setenv("JULA_SIGNING_KEY", key)
	t.Setenv("JULA_OUTPUT_TARGET", "local")
	t.Setenv("JULA_OUTPUT_PATH", t.TempDir())

	err = handleRun([]string{})

	// It's expected to fail at extraction (no configs/creds in CI),
	// but should NOT fail at CLI validation.
	if err != nil {
		if strings.Contains(err.Error(), "failed to decode PEM block") ||
			strings.Contains(err.Error(), "parsing JULA_SIGNING_KEY") ||
			strings.Contains(err.Error(), "target is required") {
			t.Errorf("handleRun() failed at CLI validation stage: %v", err)
		}
	}
}

// TestHandleRun_MissingTarget verifies that handleRun requires a target.
func TestHandleRun_MissingTarget(t *testing.T) {
	key, _ := generateTestKey()
	t.Setenv("JULA_SIGNING_KEY", key)
	t.Setenv("JULA_OUTPUT_TARGET", "")
	t.Setenv("JULA_OUTPUT_PATH", "/tmp")

	err := handleRun([]string{})
	if err == nil || !strings.Contains(err.Error(), "target is required") {
		t.Errorf("expected 'target is required' error, got: %v", err)
	}
}

// TestHandleRun_MissingPath verifies that handleRun requires a path.
func TestHandleRun_MissingPath(t *testing.T) {
	key, _ := generateTestKey()
	t.Setenv("JULA_SIGNING_KEY", key)
	t.Setenv("JULA_OUTPUT_TARGET", "local")
	t.Setenv("JULA_OUTPUT_PATH", "")

	err := handleRun([]string{})
	if err == nil || !strings.Contains(err.Error(), "path is required") {
		t.Errorf("expected 'path is required' error, got: %v", err)
	}
}

// TestHandleRun_UnknownTarget verifies that unknown delivery targets are rejected.
func TestHandleRun_UnknownTarget(t *testing.T) {
	key, _ := generateTestKey()
	t.Setenv("JULA_SIGNING_KEY", key)
	t.Setenv("JULA_OUTPUT_TARGET", "s3")
	t.Setenv("JULA_OUTPUT_PATH", "s3://test-bucket")

	err := handleRun([]string{})
	if err == nil || !strings.Contains(err.Error(), "unknown target") {
		t.Errorf("expected 'unknown target' error, got: %v", err)
	}
}

// TestHandleRun_InvalidKey verifies that a non-PEM signing key is rejected.
func TestHandleRun_InvalidKey(t *testing.T) {
	t.Setenv("JULA_SIGNING_KEY", "invalid-hex-garbage")
	t.Setenv("JULA_OUTPUT_TARGET", "local")
	t.Setenv("JULA_OUTPUT_PATH", t.TempDir())

	err := handleRun([]string{})
	if err == nil {
		t.Fatal("expected error for invalid key")
	}
	if !strings.Contains(err.Error(), "failed to decode PEM block") {
		t.Errorf("expected PEM decode error, got: %v", err)
	}
}

// TestHandleRun_WrongKeyType verifies that an RSA key is rejected (we require EC).
func TestHandleRun_WrongKeyType(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	der := x509.MarshalPKCS1PrivateKey(privKey)
	pemBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}
	pemString := string(pem.EncodeToMemory(pemBlock))

	t.Setenv("JULA_SIGNING_KEY", pemString)
	t.Setenv("JULA_OUTPUT_TARGET", "local")
	t.Setenv("JULA_OUTPUT_PATH", t.TempDir())

	err := handleRun([]string{})
	if err == nil {
		t.Fatal("expected error for RSA key (expected EC)")
	}
	if !strings.Contains(err.Error(), "parsing JULA_SIGNING_KEY") {
		t.Errorf("expected parsing error, got: %v", err)
	}
}

// TestHandleRun_GCSTarget verifies that the GCS target passes CLI validation.
func TestHandleRun_GCSTarget(t *testing.T) {
	key, _ := generateTestKey()
	t.Setenv("JULA_SIGNING_KEY", key)
	t.Setenv("JULA_OUTPUT_TARGET", "gcs")
	t.Setenv("JULA_OUTPUT_PATH", "gs://test-bucket")

	err := handleRun([]string{})
	if err != nil && (strings.Contains(err.Error(), "failed to decode PEM block") || strings.Contains(err.Error(), "parsing JULA_SIGNING_KEY")) {
		t.Errorf("expected no PEM parsing error, got: %v", err)
	}
}

// TestHandleRun_InvalidTimeout verifies that invalid timeout durations are rejected.
func TestHandleRun_InvalidTimeout(t *testing.T) {
	key, _ := generateTestKey()
	t.Setenv("JULA_SIGNING_KEY", key)
	t.Setenv("JULA_OUTPUT_TARGET", "local")
	t.Setenv("JULA_OUTPUT_PATH", "/tmp")

	err := handleRun([]string{"-timeout", "not-a-duration"})
	if err == nil {
		t.Fatal("expected error for invalid timeout")
	}
}

// TestHandleRun_BadFlagParsing verifies that unknown CLI flags are rejected.
func TestHandleRun_BadFlagParsing(t *testing.T) {
	err := handleRun([]string{"--unknown-flag"})
	if err == nil {
		t.Fatal("expected error for unknown flag")
	}
}

// TestHandleRun_NoExtractionsAvailable verifies that when all provider configs
// are missing and no credentials are set, the engine returns a clear error
// rather than a panic or nil pointer.
func TestHandleRun_NoExtractionsAvailable(t *testing.T) {
	key, _ := generateTestKey()
	t.Setenv("JULA_SIGNING_KEY", key)
	t.Setenv("JULA_OUTPUT_TARGET", "local")
	t.Setenv("JULA_OUTPUT_PATH", t.TempDir())

	err := handleRun([]string{})
	if err == nil {
		t.Fatal("expected error when no extraction configs are available")
	}
	if !strings.Contains(err.Error(), "no extraction jobs available") && !strings.Contains(err.Error(), "job builder initialization failed") {
		t.Errorf("expected extraction error, got: %v", err)
	}
}

// TestHandleRun_FullExecution tests the full pipeline through extraction and delivery
// by utilizing a mocked SaaS HTTP endpoint to guarantee a successful extraction.
func TestHandleRun_FullExecution(t *testing.T) {
	// 1. Setup Mock HTTP Server to act as our SaaS provider
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "success", "data": "mock_evidence"}`))
	}))
	defer ts.Close()

	// 2. Create a temporary flat integration configuration pointing to our mock server
	outDir := t.TempDir()
	integrationDir := filepath.Join(outDir, "integrations")
	if err := os.MkdirAll(integrationDir, 0755); err != nil {
		t.Fatalf("failed to create integrations dir: %v", err)
	}

	mockIntegration := []byte(`
vendor_name: "saas_http"
base_url: "` + ts.URL + `"
auth_flow:
  type: "bearer"
  token_env: "MOCK_TOKEN"
endpoints:
  "/":
    evidence_id: "EVID-MOCK-01"
    description: "Mock HTTP Extraction"
`)
	if err := os.WriteFile(filepath.Join(integrationDir, "saas_mock.yaml"), mockIntegration, 0644); err != nil {
		t.Fatalf("failed to write mock config: %v", err)
	}

	// 3. Setup environment variables
	key, _ := generateTestKey()
	t.Setenv("JULA_SIGNING_KEY", key)
	t.Setenv("JULA_OUTPUT_TARGET", "local")
	t.Setenv("JULA_OUTPUT_PATH", outDir)
	t.Setenv("MOCK_TOKEN", "dummy")
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_ACCESS_KEY_ID", "DUMMYKEY")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "DUMMYSECRET")
	t.Setenv("GCP_PROJECT_ID", "dummy-project")

	// Force the engine to use our mock integration config
	t.Setenv("JULA_INTEGRATION_DIR", integrationDir)

	// 4. Run the command
	err := handleRun([]string{})

	// 5. Assertions
	if err != nil {
		t.Fatalf("expected full execution to succeed, but got error: %v", err)
	}

	// 8. Verify that the output was generated (checking for the manifest.json file)
	runDate := time.Now().UTC().Format("2006-01-02")
	manifestPath := filepath.Join(outDir, runDate, "manifest.json")
	if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
		t.Errorf("expected manifest.json to be created at %s", manifestPath)
	}
}
