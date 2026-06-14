package reporter

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/alibkaba/jula-core/pkg/types"
)

// staticToken implements TokenProvider with a fixed token for testing.
type staticToken struct{ token string }

func (s *staticToken) Token() (string, error) { return s.token, nil }

func gcsTestEvidence() []types.Evidence {
	return []types.Evidence{
		{
			EvidenceID:       "EVID-TEST-01",
			ControlID:   "CTRL-1",
			SourceID:    "src-1",
			PayloadHash: "abc123hash",
			Finding: types.Finding{
				EvidenceID:     "EVID-TEST-01",
				ControlID: "CTRL-1",
				SourceID:  "src-1",
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

type errToken struct{}
func (e *errToken) Token() (string, error) { return "", fmt.Errorf("token error") }

func TestGCSReporter_Validate_Errors_TableDriven(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	tests := []struct {
		name          string
		bucketName    string
		tokenProvider TokenProvider
		httpClient    *http.Client
		baseURL       string
		wantErr       bool
	}{
		{
			name:          "token error",
			bucketName:    "test-bucket",
			tokenProvider: &errToken{},
			httpClient:    http.DefaultClient,
			baseURL:       "http://localhost",
			wantErr:       true,
		},
		{
			name:          "request error",
			bucketName:    "test-bucket",
			tokenProvider: &staticToken{"tok"},
			httpClient:    http.DefaultClient,
			baseURL:       "http://\x7f\x7f",
			wantErr:       true,
		},
		{
			name:          "client error",
			bucketName:    "test-bucket",
			tokenProvider: &staticToken{"tok"},
			httpClient: &http.Client{
				Transport: &http.Transport{
					Proxy: func(*http.Request) (*url.URL, error) {
						return nil, fmt.Errorf("client error")
					},
				},
			},
			baseURL: "http://localhost",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &GCSReporter{
				BucketName:    tt.bucketName,
				SigningKey:    privKey,
				TokenProvider: tt.tokenProvider,
				HTTPClient:    tt.httpClient,
				baseURL:       tt.baseURL,
			}
			err := r.Validate(context.Background())
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
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
		_ = json.NewEncoder(w).Encode(map[string]string{"name": "test-bucket"})
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
	t.Setenv("JULA_DEPLOYMENT_ID", "test-deploy-id")
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	var uploadedPaths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			uploadedPaths = append(uploadedPaths, r.URL.Query().Get("name"))
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
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

	// 1 evidence file + 1 provenance file + 1 manifest file = 3 uploads total
	if len(uploadedPaths) != 3 {
		t.Errorf("expected 3 uploads, got %d: %v", len(uploadedPaths), uploadedPaths)
	}

	foundEvidence := false
	foundProvenance := false
	foundManifest := false
	for _, p := range uploadedPaths {
		if strings.HasSuffix(p, "EVID-TEST-01_gcp_src-1.json") {
			foundEvidence = true
		}
		if strings.HasSuffix(p, "EVID-TEST-01_gcp_src-1.prov.json") {
			foundProvenance = true
		}
		if strings.HasSuffix(p, "manifest.json") {
			foundManifest = true
		}
	}
	if !foundEvidence {
		t.Error("evidence file not found in uploaded paths")
	}
	if !foundProvenance {
		t.Error("provenance file not found in uploaded paths")
	}
	if !foundManifest {
		t.Error("manifest.json not found in uploaded paths")
	}

	if len(manifest.EvidenceFiles) != 2 {
		t.Errorf("expected 2 evidence/provenance files logged in manifest, got %d", len(manifest.EvidenceFiles))
	}
}

func TestGCSReporter_Deliver_ContextCancellation(t *testing.T) {
	t.Setenv("JULA_DEPLOYMENT_ID", "test-deploy-id")
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
	t.Setenv("JULA_DEPLOYMENT_ID", "test-deploy-id")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("internal error"))
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

func TestGCSReporter_uploadObject_Errors_TableDriven(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	tests := []struct {
		name          string
		bucketName    string
		tokenProvider TokenProvider
		httpClient    *http.Client
		baseURL       string
		wantErr       bool
	}{
		{
			name:          "token error",
			bucketName:    "test-bucket",
			tokenProvider: &errToken{},
			httpClient:    http.DefaultClient,
			baseURL:       "http://localhost",
			wantErr:       true,
		},
		{
			name:          "request error",
			bucketName:    "test-bucket",
			tokenProvider: &staticToken{"tok"},
			httpClient:    http.DefaultClient,
			baseURL:       "http://\x7f\x7f",
			wantErr:       true,
		},
		{
			name:          "client error",
			bucketName:    "test-bucket",
			tokenProvider: &staticToken{"tok"},
			httpClient: &http.Client{
				Transport: &http.Transport{
					Proxy: func(*http.Request) (*url.URL, error) {
						return nil, fmt.Errorf("client error")
					},
				},
			},
			baseURL: "http://localhost",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &GCSReporter{
				BucketName:    tt.bucketName,
				SigningKey:    privKey,
				TokenProvider: tt.tokenProvider,
				HTTPClient:    tt.httpClient,
				baseURL:       tt.baseURL,
			}
			err := r.uploadObject(context.Background(), "obj", []byte("data"), "application/json")
			if (err != nil) != tt.wantErr {
				t.Errorf("uploadObject() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGCSReporter_Deliver_MissingDeploymentID(t *testing.T) {
	t.Setenv("JULA_DEPLOYMENT_ID", "")
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	r := &GCSReporter{
		BucketName:    "test-bucket",
		SigningKey:    privKey,
		TokenProvider: &staticToken{"tok"},
	}

	_, err := r.Deliver(context.Background(), gcsTestEvidence(), "test-run")
	if err == nil {
		t.Fatal("expected error for missing JULA_DEPLOYMENT_ID")
	}

	expectedErr := "JULA_DEPLOYMENT_ID environment variable is required"
	if !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("expected error to contain %q, got %q", expectedErr, err.Error())
	}
}

func TestGCSReporter_Deliver_AuthorizationHeader(t *testing.T) {
	t.Setenv("JULA_DEPLOYMENT_ID", "test-deploy-id")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer my-secret-token" {
			t.Errorf("expected Bearer my-secret-token, got %s", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
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
