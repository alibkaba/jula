package ingestion

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alibkaba/jula-evidence-evaluator/pkg/types"
)

type mockRoundTripper struct {
	roundTripFunc func(req *http.Request) (*http.Response, error)
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.roundTripFunc(req)
}

func TestParseGCSURL(t *testing.T) {
	tests := []struct {
		name       string
		gcsURL     string
		wantBucket string
		wantFolder string
	}{
		{
			name:       "Simple Bucket",
			gcsURL:     "gs://my-bucket",
			wantBucket: "my-bucket",
			wantFolder: "",
		},
		{
			name:       "Bucket with Folder",
			gcsURL:     "gs://my-bucket/runs/123",
			wantBucket: "my-bucket",
			wantFolder: "runs/123",
		},
		{
			name:       "Bucket with Folder and Trailing Slash",
			gcsURL:     "gs://my-bucket/runs/123/",
			wantBucket: "my-bucket",
			wantFolder: "runs/123",
		},
		{
			name:       "No Schema prefix",
			gcsURL:     "my-bucket/runs/abc",
			wantBucket: "my-bucket",
			wantFolder: "runs/abc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotBucket, gotFolder := parseGCSURL(tt.gcsURL)
			if gotBucket != tt.wantBucket {
				t.Errorf("parseGCSURL() gotBucket = %q, want %q", gotBucket, tt.wantBucket)
			}
			if gotFolder != tt.wantFolder {
				t.Errorf("parseGCSURL() gotFolder = %q, want %q", gotFolder, tt.wantFolder)
			}
		})
	}
}

func TestNewGCSReader(t *testing.T) {
	reader := NewGCSReader(nil)
	if reader == nil {
		t.Fatal("NewGCSReader returned nil")
	}
	if reader.httpClient == nil {
		t.Error("Expected default http client to be initialized")
	}

	customClient := &http.Client{Timeout: 5 * time.Second}
	readerCustom := NewGCSReader(customClient)
	if readerCustom.httpClient != customClient {
		t.Error("Expected custom http client to be set")
	}
}

func TestGCSReader_InitializeLocal(t *testing.T) {
	reader := NewGCSReader(nil)
	err := reader.Initialize("/tmp/local-path")
	if err != nil {
		t.Fatalf("Initialize returned error: %v", err)
	}
	if !reader.isLocal {
		t.Error("Expected isLocal to be true for non-gs path")
	}

	err = reader.Initialize("file:///tmp/local-path")
	if err != nil {
		t.Fatalf("Initialize returned error: %v", err)
	}
	if !reader.isLocal {
		t.Error("Expected isLocal to be true for file:// path")
	}
}

func TestGCSReader_LocalReadLifecycle(t *testing.T) {
	// Create a temporary directory structure
	tmpDir, err := os.MkdirTemp("", "jula-evaluator-test-*")
	if err != nil {
		t.Fatalf("Failed to create tmp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Write mock manifest
	mockManifest := types.Manifest{
		RunID:     "test-run-123",
		Timestamp: time.Now(),
		Providers: []string{"test-provider"},
		EvidenceFiles: []types.FileChecksum{
			{
				Path:   "evidence/file1.json",
				SHA256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
			},
			{
				Path:   "evidence/file2.json",
				SHA256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
			},
		},
	}

	manifestBytes, err := json.MarshalIndent(mockManifest, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal manifest: %v", err)
	}

	manifestPath := filepath.Join(tmpDir, "manifest.json")
	if err := os.WriteFile(manifestPath, manifestBytes, 0644); err != nil {
		t.Fatalf("Failed to write manifest: %v", err)
	}

	// Write evidence payloads
	evidenceDir := filepath.Join(tmpDir, "evidence")
	if err := os.Mkdir(evidenceDir, 0755); err != nil {
		t.Fatalf("Failed to create evidence dir: %v", err)
	}

	file1Content := []byte(`{"status": "compliant"}`)
	if err := os.WriteFile(filepath.Join(evidenceDir, "file1.json"), file1Content, 0644); err != nil {
		t.Fatalf("Failed to write file1: %v", err)
	}

	file2Content := []byte(`{"status": "non-compliant"}`)
	if err := os.WriteFile(filepath.Join(evidenceDir, "file2.json"), file2Content, 0644); err != nil {
		t.Fatalf("Failed to write file2: %v", err)
	}

	// Ingestion execution
	ctx := context.Background()
	reader := NewGCSReader(nil)

	err = reader.Initialize("file://" + tmpDir)
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// 1. Test ReadManifest
	manifest, err := reader.ReadManifest(ctx, tmpDir)
	if err != nil {
		t.Fatalf("ReadManifest failed: %v", err)
	}
	if manifest.RunID != "test-run-123" {
		t.Errorf("Expected run ID test-run-123, got %q", manifest.RunID)
	}

	// 2. Test ReadPayloads
	payloads, err := reader.ReadPayloads(ctx, tmpDir, manifest.EvidenceFiles)
	if err != nil {
		t.Fatalf("ReadPayloads failed: %v", err)
	}

	if len(payloads) != 2 {
		t.Errorf("Expected 2 payloads, got %d", len(payloads))
	}

	if string(payloads["evidence/file1.json"]) != `{"status": "compliant"}` {
		t.Errorf("Unexpected content for file1: %q", string(payloads["evidence/file1.json"]))
	}
	if string(payloads["evidence/file2.json"]) != `{"status": "non-compliant"}` {
		t.Errorf("Unexpected content for file2: %q", string(payloads["evidence/file2.json"]))
	}
}

func TestGCSReader_GCSReadLifecycle_MetadataAuth(t *testing.T) {
	// Ensure local env var is clean
	origCreds := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	defer os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", origCreds)

	mockClient := &http.Client{
		Transport: &mockRoundTripper{
			roundTripFunc: func(req *http.Request) (*http.Response, error) {
				// Intercept metadata token server
				if strings.Contains(req.URL.Host, "metadata.google.internal") {
					respJSON := `{"access_token": "mock-metadata-token"}`
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(respJSON)),
						Header:     make(http.Header),
					}, nil
				}

				// Intercept manifest download
				if strings.Contains(req.URL.Path, "manifest.json") {
					mockManifest := types.Manifest{
						RunID: "gcs-run-456",
						EvidenceFiles: []types.FileChecksum{
							{Path: "evidence/gcs-file.json", SHA256: "abc"},
						},
					}
					data, _ := json.Marshal(mockManifest)
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(bytes.NewReader(data)),
						Header:     make(http.Header),
					}, nil
				}

				// Intercept payload download
				if strings.Contains(req.URL.Path, "gcs-file.json") {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{"status":"compliant"}`)),
						Header:     make(http.Header),
					}, nil
				}

				return &http.Response{
					StatusCode: http.StatusNotFound,
					Body:       io.NopCloser(strings.NewReader("not found")),
				}, nil
			},
		},
	}

	reader := NewGCSReader(mockClient)
	err := reader.Initialize("gs://my-bucket/runs/123")
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	if reader.token != "mock-metadata-token" {
		t.Errorf("Expected token mock-metadata-token, got %q", reader.token)
	}

	ctx := context.Background()
	manifest, err := reader.ReadManifest(ctx, "gs://my-bucket/runs/123")
	if err != nil {
		t.Fatalf("ReadManifest failed: %v", err)
	}
	if manifest.RunID != "gcs-run-456" {
		t.Errorf("Expected run ID gcs-run-456, got %q", manifest.RunID)
	}

	payloads, err := reader.ReadPayloads(ctx, "gs://my-bucket/runs/123", manifest.EvidenceFiles)
	if err != nil {
		t.Fatalf("ReadPayloads failed: %v", err)
	}

	if string(payloads["evidence/gcs-file.json"]) != `{"status":"compliant"}` {
		t.Errorf("Unexpected payload content: %q", string(payloads["evidence/gcs-file.json"]))
	}
}

func TestGCSReader_GCSReadLifecycle_ServiceAccountAuth(t *testing.T) {
	// Generate an RSA private key
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// Wrap in a PKCS8 block because x509.ParsePrivateKey expects PKCS8 keys
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		t.Fatalf("Failed to marshal PKCS8: %v", err)
	}
	pkcs8PEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Bytes,
	})

	keyJSON := map[string]string{
		"type":         "service_account",
		"client_email": "test@my-project.iam.gserviceaccount.com",
		"private_key":  string(pkcs8PEM),
		"token_uri":    "http://oauth.mock/token",
	}

	keyData, err := json.Marshal(keyJSON)
	if err != nil {
		t.Fatalf("Failed to marshal key: %v", err)
	}

	tmpFile, err := os.CreateTemp("", "sa-key-*.json")
	if err != nil {
		t.Fatalf("Failed to create sa key file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(keyData); err != nil {
		t.Fatalf("Failed to write sa key file: %v", err)
	}
	tmpFile.Close()

	// Set env variable
	origCreds := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", tmpFile.Name())
	defer os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", origCreds)

	mockClient := &http.Client{
		Transport: &mockRoundTripper{
			roundTripFunc: func(req *http.Request) (*http.Response, error) {
				// Intercept oauth token server
				if strings.Contains(req.URL.Host, "oauth.mock") {
					respJSON := `{"access_token": "mock-sa-token"}`
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(respJSON)),
						Header:     make(http.Header),
					}, nil
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader("{}")),
					Header:     make(http.Header),
				}, nil
			},
		},
	}

	reader := NewGCSReader(mockClient)
	err = reader.Initialize("gs://my-bucket")
	if err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	if reader.token != "mock-sa-token" {
		t.Errorf("Expected token mock-sa-token, got %q", reader.token)
	}
}

func TestGCSReader_Failures(t *testing.T) {
	origCreds := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	defer os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", origCreds)

	// 1. Initialize metadata server returns 500 error
	mockClientFailInit := &http.Client{
		Transport: &mockRoundTripper{
			roundTripFunc: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusInternalServerError,
					Body:       io.NopCloser(strings.NewReader("server crash")),
					Header:     make(http.Header),
				}, nil
			},
		},
	}

	readerFailInit := NewGCSReader(mockClientFailInit)
	err := readerFailInit.Initialize("gs://my-bucket/runs/123")
	if err == nil {
		t.Error("Expected Initialize to fail when metadata server returns 500")
	}

	// 2. ReadManifest GCS returns 404 error
	mockClientFailManifest := &http.Client{
		Transport: &mockRoundTripper{
			roundTripFunc: func(req *http.Request) (*http.Response, error) {
				if strings.Contains(req.URL.Host, "metadata.google.internal") {
					respJSON := `{"access_token": "token"}`
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(respJSON)),
						Header:     make(http.Header),
					}, nil
				}
				return &http.Response{
					StatusCode: http.StatusNotFound,
					Body:       io.NopCloser(strings.NewReader("manifest not found")),
					Header:     make(http.Header),
				}, nil
			},
		},
	}

	readerFailManifest := NewGCSReader(mockClientFailManifest)
	_ = readerFailManifest.Initialize("gs://my-bucket/runs/123")

	_, err = readerFailManifest.ReadManifest(context.Background(), "gs://my-bucket/runs/123")
	if err == nil {
		t.Error("Expected ReadManifest to fail when GCS API returns 404")
	}
}
