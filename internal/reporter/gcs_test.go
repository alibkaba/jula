package reporter

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alibkaba/jula-evidence-collector/pkg/types"
)

// staticToken implements TokenProvider with a fixed token for testing.
type staticToken struct{ token string }

func (s *staticToken) Token() (string, error) { return s.token, nil }

func gcsTestEvidence() []types.Evidence {
	return []types.Evidence{
		{
			PayloadHash: "abc123hash",
			Finding: types.Finding{
				ErlID:     "E-TEST-01",
				Provider:  "gcp",
				RawData:   []byte(`{"status":"ok"}`),
				Timestamp: time.Now().UTC(),
				RunID:     "test-run",
			},
		},
	}
}

func TestGCSReporter_Name(t *testing.T) {
	r := &GCSReporter{}
	if r.Name() != "gcs" {
		t.Errorf("expected gcs, got %s", r.Name())
	}
}

func TestGCSReporter_Validate_MissingBucket(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	r := &GCSReporter{SigningKey: privKey, TokenProvider: &staticToken{"tok"}}
	if err := r.Validate(context.Background()); err == nil {
		t.Error("expected error for missing bucket")
	}
}

func TestGCSReporter_Validate_MissingSigningKey(t *testing.T) {
	r := &GCSReporter{BucketName: "test-bucket", TokenProvider: &staticToken{"tok"}}
	if err := r.Validate(context.Background()); err == nil {
		t.Error("expected error for missing signing key")
	}
}

func TestGCSReporter_Validate_MissingTokenProvider(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	r := &GCSReporter{BucketName: "test-bucket", SigningKey: privKey}
	if err := r.Validate(context.Background()); err == nil {
		t.Error("expected error for missing token provider")
	}
}

func TestGCSReporter_Validate_BucketNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	r := &GCSReporter{
		BucketName:    "nonexistent-bucket",
		SigningKey:    privKey,
		TokenProvider: &staticToken{"tok"},
		HTTPClient:    server.Client(),
		baseURL:       server.URL,
	}
	err := r.Validate(context.Background())
	if err == nil {
		t.Fatal("expected error for nonexistent bucket")
	}
}

func TestGCSReporter_Validate_Forbidden(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	r := &GCSReporter{
		BucketName:    "locked-bucket",
		SigningKey:    privKey,
		TokenProvider: &staticToken{"tok"},
		HTTPClient:    server.Client(),
		baseURL:       server.URL,
	}
	err := r.Validate(context.Background())
	if err == nil {
		t.Fatal("expected error for forbidden bucket")
	}
}

func TestGCSReporter_Validate_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"name": "test-bucket"})
	}))
	defer server.Close()

	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	r := &GCSReporter{
		BucketName:    "test-bucket",
		SigningKey:    privKey,
		TokenProvider: &staticToken{"tok"},
		HTTPClient:    server.Client(),
		baseURL:       server.URL,
	}
	if err := r.Validate(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGCSReporter_Deliver(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	var uploadedPaths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			uploadedPaths = append(uploadedPaths, r.URL.Query().Get("name"))
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer server.Close()

	r := &GCSReporter{
		BucketName:    "test-bucket",
		SigningKey:    privKey,
		TokenProvider: &staticToken{"test-token"},
		HTTPClient:    server.Client(),
		baseURL:       server.URL,
	}

	manifest, err := r.Deliver(context.Background(), gcsTestEvidence(), "test-run")
	if err != nil {
		t.Fatalf("deliver failed: %v", err)
	}

	// 1 evidence file + 1 manifest file = 2 uploads total
	if len(uploadedPaths) != 2 {
		t.Errorf("expected 2 uploads, got %d: %v", len(uploadedPaths), uploadedPaths)
	}

	foundEvidence := false
	foundManifest := false
	for _, p := range uploadedPaths {
		if strings.HasSuffix(p, "abc123hash.json") {
			foundEvidence = true
		}
		if strings.HasSuffix(p, "manifest.json") {
			foundManifest = true
		}
	}
	if !foundEvidence {
		t.Error("evidence file hash not found in uploaded paths")
	}
	if !foundManifest {
		t.Error("manifest.json not found in uploaded paths")
	}

	if len(manifest.EvidenceFiles) != 1 {
		t.Errorf("expected 1 evidence file logged in manifest, got %d", len(manifest.EvidenceFiles))
	}
}

func TestGCSReporter_Deliver_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	r := &GCSReporter{
		BucketName:    "test-bucket",
		SigningKey:    privKey,
		TokenProvider: &staticToken{"tok"},
		HTTPClient:    server.Client(),
		baseURL:       server.URL,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := r.Deliver(ctx, gcsTestEvidence(), "test-run")
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

func TestGCSReporter_Deliver_UploadFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("internal error"))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	r := &GCSReporter{
		BucketName:    "test-bucket",
		SigningKey:    privKey,
		TokenProvider: &staticToken{"tok"},
		HTTPClient:    server.Client(),
		baseURL:       server.URL,
	}

	_, err := r.Deliver(context.Background(), gcsTestEvidence(), "test-run")
	if err == nil {
		t.Fatal("expected error for failed upload")
	}
}

func TestGCSReporter_Deliver_AuthorizationHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer my-secret-token" {
			t.Errorf("expected Bearer my-secret-token, got %s", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer server.Close()

	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	r := &GCSReporter{
		BucketName:    "test-bucket",
		SigningKey:    privKey,
		TokenProvider: &staticToken{"my-secret-token"},
		HTTPClient:    server.Client(),
		baseURL:       server.URL,
	}

	_, err := r.Deliver(context.Background(), gcsTestEvidence(), "test-run")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseBucketName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"gs://my-bucket", "my-bucket"},
		{"gs://my-bucket/", "my-bucket"},
		{"my-bucket", "my-bucket"},
		{"  gs://my-bucket  ", "my-bucket"},
	}

	for _, tc := range tests {
		result := ParseBucketName(tc.input)
		if result != tc.expected {
			t.Errorf("ParseBucketName(%q) = %q, want %q", tc.input, result, tc.expected)
		}
	}
}

func TestGCSReporter_URLs_TableDriven(t *testing.T) {
	tests := []struct {
		name          string
		baseURL       string
		wantUploadURL string
		wantAPIURL    string
	}{
		{
			name:          "default urls",
			baseURL:       "",
			wantUploadURL: "https://storage.googleapis.com/upload/storage/v1",
			wantAPIURL:    "https://storage.googleapis.com/storage/v1",
		},
		{
			name:          "overridden urls",
			baseURL:       "http://localhost:8080",
			wantUploadURL: "http://localhost:8080",
			wantAPIURL:    "http://localhost:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reporter := &GCSReporter{baseURL: tt.baseURL}

			if got := reporter.gcsUploadURL(); got != tt.wantUploadURL {
				t.Errorf("gcsUploadURL() = %v, want %v", got, tt.wantUploadURL)
			}

			if got := reporter.gcsAPIURL(); got != tt.wantAPIURL {
				t.Errorf("gcsAPIURL() = %v, want %v", got, tt.wantAPIURL)
			}
		})
	}
}
