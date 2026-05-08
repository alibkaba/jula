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
			Finding: types.Finding{
				ID:        "gcp.audit_logging.enabled",
				Provider:  "gcp",
				Resource:  "audit_logging",
				Check:     "enabled",
				Status:    "PASS",
				Timestamp: time.Now().UTC(),
				RunID:     "test-run",
			},
			Framework:     "soc2",
			Criteria:      []string{"CC2.1"},
			ControlType:   "AUTOMATED",
			MappingRuleID: "soc2-cc2.1-audit-logging",
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

	tests := []struct {
		name           string
		format         string
		expectedSuffix string
		expectedCount  int
	}{
		{
			name:           "Deliver with JSON Format",
			format:         "json",
			expectedSuffix: ".json",
			expectedCount:  3, // 1 individual + 1 consolidated + 1 manifest
		},
		{
			name:           "Deliver with Markdown Format",
			format:         "markdown",
			expectedSuffix: "evidence_portfolio.md",
			expectedCount:  4, // 1 individual + 1 consolidated + 1 markdown + 1 manifest
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
				Format:        tt.format,
			}

			manifest, err := r.Deliver(context.Background(), gcsTestEvidence(), "test-run-"+tt.format)
			if err != nil {
				t.Fatalf("deliver failed: %v", err)
			}

			if len(uploadedPaths) != tt.expectedCount {
				t.Errorf("expected %d uploads, got %d: %v", tt.expectedCount, len(uploadedPaths), uploadedPaths)
			}

			found := false
			for _, f := range manifest.EvidenceFiles {
				if strings.HasSuffix(f.Path, tt.expectedSuffix) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("%s not found in manifest evidence files", tt.expectedSuffix)
			}
		})
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
