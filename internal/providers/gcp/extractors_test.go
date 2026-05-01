package gcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alibkaba/jula-evidence-collector/pkg/types"
)

// newTestProvider creates a GCPProvider with a pre-cached token
// so no real OAuth2 exchange is needed during tests.
func newTestProvider(t *testing.T) *GCPProvider {
	t.Helper()

	return &GCPProvider{
		projectID:  "test-project",
		httpClient: &http.Client{},
		tokenSource: &tokenSource{
			cachedToken: "test-token",
			tokenExpiry: time.Now().Add(1 * time.Hour),
		},
	}
}

// testWithRedirect temporarily overrides the httpClient transport
// to redirect all requests to the test server URL.
func testWithRedirect(p *GCPProvider, serverURL string, fn func() ([]types.Finding, error)) ([]types.Finding, error) {
	origTransport := p.httpClient.Transport
	p.httpClient.Transport = &testTransport{serverURL: serverURL, base: origTransport}
	defer func() { p.httpClient.Transport = origTransport }()
	return fn()
}

// testTransport redirects all HTTP requests to the test server.
type testTransport struct {
	serverURL string
	base      http.RoundTripper
}

func (t *testTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = "http"
	req.URL.Host = t.serverURL[len("http://"):]
	if t.base != nil {
		return t.base.RoundTrip(req)
	}
	return http.DefaultTransport.RoundTrip(req)
}

// --- Audit Logging Tests ---

func TestExtractAuditLogging_Enabled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"auditConfigs": []map[string]any{
				{
					"service": "allServices",
					"auditLogConfigs": []map[string]string{
						{"logType": "ADMIN_READ"},
						{"logType": "DATA_READ"},
					},
				},
			},
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	p := newTestProvider(t)
	p.httpClient = server.Client()

	findings, err := testWithRedirect(p, server.URL, func() ([]types.Finding, error) {
		return p.extractAuditLogging(context.Background(), "test-run")
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	if findings[0].Status != "PASS" {
		t.Errorf("expected PASS, got %s", findings[0].Status)
	}
	if findings[0].ID != "gcp.audit_logging.enabled" {
		t.Errorf("unexpected finding ID: %s", findings[0].ID)
	}
	if findings[0].Provider != "gcp" {
		t.Errorf("expected provider gcp, got %s", findings[0].Provider)
	}
}

func TestExtractAuditLogging_Disabled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"auditConfigs": []map[string]any{},
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	p := newTestProvider(t)
	p.httpClient = server.Client()

	findings, err := testWithRedirect(p, server.URL, func() ([]types.Finding, error) {
		return p.extractAuditLogging(context.Background(), "test-run")
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	if findings[0].Status != "FAIL" {
		t.Errorf("expected FAIL, got %s", findings[0].Status)
	}
}

func TestExtractAuditLogging_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error": "permission denied"}`))
	}))
	defer server.Close()

	p := newTestProvider(t)
	p.httpClient = server.Client()

	_, err := testWithRedirect(p, server.URL, func() ([]types.Finding, error) {
		return p.extractAuditLogging(context.Background(), "test-run")
	})
	if err == nil {
		t.Fatal("expected error for 403 response")
	}
}

// --- Storage Encryption Tests ---

func TestExtractStorageEncryption_AllEncrypted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"items": []map[string]any{
				{"name": "my-bucket"},
				{"name": "my-other-bucket"},
			},
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	p := newTestProvider(t)
	p.httpClient = server.Client()

	findings, err := testWithRedirect(p, server.URL, func() ([]types.Finding, error) {
		return p.extractStorageEncryption(context.Background(), "test-run")
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	for _, f := range findings {
		if f.Status != "PASS" {
			t.Errorf("expected PASS for bucket, got %s", f.Status)
		}
		if f.ID != "gcp.storage.encryption_enabled" {
			t.Errorf("unexpected finding ID: %s", f.ID)
		}
	}
}

func TestExtractStorageEncryption_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "internal server error"}`))
	}))
	defer server.Close()

	p := newTestProvider(t)
	p.httpClient = server.Client()

	_, err := testWithRedirect(p, server.URL, func() ([]types.Finding, error) {
		return p.extractStorageEncryption(context.Background(), "test-run")
	})
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}

// --- Service Account Key Tests ---

func TestExtractServiceAccountKeys_NoUserManagedKeys(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			resp := map[string]any{
				"accounts": []map[string]any{
					{"email": "test@test-project.iam.gserviceaccount.com", "uniqueId": "123"},
				},
			}
			json.NewEncoder(w).Encode(resp)
			return
		}
		resp := map[string]any{
			"keys": []map[string]any{
				{
					"name":            "projects/test-project/serviceAccounts/test@test-project.iam.gserviceaccount.com/keys/abc",
					"validAfterTime":  time.Now().Add(-30 * 24 * time.Hour).Format(time.RFC3339),
					"validBeforeTime": time.Now().Add(365 * 24 * time.Hour).Format(time.RFC3339),
					"keyType":         "SYSTEM_MANAGED",
				},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	p := newTestProvider(t)
	p.httpClient = server.Client()

	findings, err := testWithRedirect(p, server.URL, func() ([]types.Finding, error) {
		return p.extractServiceAccountKeys(context.Background(), "test-run")
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for system-managed keys, got %d", len(findings))
	}
}

func TestExtractServiceAccountKeys_ExpiredKey(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			resp := map[string]any{
				"accounts": []map[string]any{
					{"email": "test@test-project.iam.gserviceaccount.com", "uniqueId": "123"},
				},
			}
			json.NewEncoder(w).Encode(resp)
			return
		}
		resp := map[string]any{
			"keys": []map[string]any{
				{
					"name":            "projects/test-project/serviceAccounts/test@test-project.iam.gserviceaccount.com/keys/abc",
					"validAfterTime":  time.Now().Add(-120 * 24 * time.Hour).Format(time.RFC3339),
					"validBeforeTime": time.Now().Add(365 * 24 * time.Hour).Format(time.RFC3339),
					"keyType":         "USER_MANAGED",
				},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	p := newTestProvider(t)
	p.httpClient = server.Client()

	findings, err := testWithRedirect(p, server.URL, func() ([]types.Finding, error) {
		return p.extractServiceAccountKeys(context.Background(), "test-run")
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Status != "FAIL" {
		t.Errorf("expected FAIL for expired key, got %s", findings[0].Status)
	}
}
