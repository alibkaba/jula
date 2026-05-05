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
		policy:     defaultTestPolicy(),
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

// --- Compute Firewalls Tests ---

func TestExtractComputeFirewalls_Pass_NoViolation(t *testing.T) {
	p := newTestProvider(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"items": []map[string]any{
				{
					"name":         "allow-https",
					"direction":    "INGRESS",
					"sourceRanges": []string{"0.0.0.0/0"},
					"allowed": []map[string]any{
						{"IPProtocol": "tcp", "ports": []string{"443"}},
					},
				},
			},
		})
	}))
	defer server.Close()

	findings, err := testWithRedirect(p, server.URL, func() ([]types.Finding, error) {
		return p.extractComputeFirewalls(context.Background(), "test-run")
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 || findings[0].Status != "PASS" {
		t.Errorf("expected PASS, got %s (count: %d)", findings[0].Status, len(findings))
	}
}

func TestExtractComputeFirewalls_Fail_SSHOpen(t *testing.T) {
	p := newTestProvider(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"items": []map[string]any{
				{
					"name":         "allow-ssh-all",
					"direction":    "INGRESS",
					"sourceRanges": []string{"0.0.0.0/0"},
					"allowed": []map[string]any{
						{"IPProtocol": "tcp", "ports": []string{"22"}},
					},
				},
			},
		})
	}))
	defer server.Close()

	findings, err := testWithRedirect(p, server.URL, func() ([]types.Finding, error) {
		return p.extractComputeFirewalls(context.Background(), "test-run")
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 || findings[0].Status != "FAIL" {
		t.Errorf("expected FAIL, got %s", findings[0].Status)
	}
}

func TestExtractComputeFirewalls_Exception(t *testing.T) {
	p := newTestProvider(t)
	p.policy.Exceptions = []Exception{
		{
			ID:        "EXC-001",
			FindingID: "gcp.compute.firewall_ingress",
			Resource:  "bastion-ssh",
			Reason:    "Approved bastion",
			Expires:   "2099-12-31",
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"items": []map[string]any{
				{
					"name":         "bastion-ssh",
					"direction":    "INGRESS",
					"sourceRanges": []string{"0.0.0.0/0"},
					"allowed": []map[string]any{
						{"IPProtocol": "tcp", "ports": []string{"22"}},
					},
				},
			},
		})
	}))
	defer server.Close()

	findings, err := testWithRedirect(p, server.URL, func() ([]types.Finding, error) {
		return p.extractComputeFirewalls(context.Background(), "test-run")
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 || findings[0].Status != "EXCEPTION" {
		t.Errorf("expected EXCEPTION, got %s", findings[0].Status)
	}
}

// --- Cloud SQL Tests ---

func TestExtractCloudSQL_NoInstances(t *testing.T) {
	p := newTestProvider(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"items": []any{}})
	}))
	defer server.Close()

	findings, err := testWithRedirect(p, server.URL, func() ([]types.Finding, error) {
		return p.extractCloudSQL(context.Background(), "test-run")
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 || findings[0].Status != "PASS" {
		t.Errorf("expected PASS for no instances, got %s", findings[0].Status)
	}
}

func TestExtractCloudSQL_Fail_NoBackup(t *testing.T) {
	p := newTestProvider(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"items": []map[string]any{
				{
					"name": "prod-db",
					"settings": map[string]any{
						"backupConfiguration": map[string]any{"enabled": false},
						"ipConfiguration":     map[string]any{"ipv4Enabled": false},
					},
				},
			},
		})
	}))
	defer server.Close()

	findings, err := testWithRedirect(p, server.URL, func() ([]types.Finding, error) {
		return p.extractCloudSQL(context.Background(), "test-run")
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 || findings[0].Status != "FAIL" {
		t.Errorf("expected FAIL for disabled backup, got %s", findings[0].Status)
	}
}

func TestExtractCloudSQL_Fail_PublicIP(t *testing.T) {
	p := newTestProvider(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"items": []map[string]any{
				{
					"name": "dev-db",
					"settings": map[string]any{
						"backupConfiguration": map[string]any{"enabled": true},
						"ipConfiguration":     map[string]any{"ipv4Enabled": true},
					},
				},
			},
		})
	}))
	defer server.Close()

	findings, err := testWithRedirect(p, server.URL, func() ([]types.Finding, error) {
		return p.extractCloudSQL(context.Background(), "test-run")
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 || findings[0].Status != "FAIL" {
		t.Errorf("expected FAIL for public IP, got %s", findings[0].Status)
	}
}

// --- KMS Key Rotation Tests ---

func TestExtractKMSKeyRotation_NoKeys(t *testing.T) {
	p := newTestProvider(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return empty locations so no keys are found.
		json.NewEncoder(w).Encode(map[string]any{"locations": []any{}})
	}))
	defer server.Close()

	findings, err := testWithRedirect(p, server.URL, func() ([]types.Finding, error) {
		return p.extractKMSKeyRotation(context.Background(), "test-run")
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 || findings[0].Status != "PASS" {
		t.Errorf("expected PASS for no KMS keys, got %s", findings[0].Status)
	}
}

func TestExtractKMSKeyRotation_PassGoodRotation(t *testing.T) {
	p := newTestProvider(t)
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		switch callCount {
		case 1:
			json.NewEncoder(w).Encode(map[string]any{
				"locations": []map[string]any{
					{"name": "projects/test-project/locations/us-central1"},
				},
			})
		case 2:
			json.NewEncoder(w).Encode(map[string]any{
				"keyRings": []map[string]any{
					{"name": "projects/test-project/locations/us-central1/keyRings/my-ring"},
				},
			})
		case 3:
			json.NewEncoder(w).Encode(map[string]any{
				"cryptoKeys": []map[string]any{
					{
						"name":           "projects/test-project/locations/us-central1/keyRings/my-ring/cryptoKeys/my-key",
						"purpose":        "ENCRYPT_DECRYPT",
						"rotationPeriod": "7776000s",
					},
				},
			})
		}
	}))
	defer server.Close()

	findings, err := testWithRedirect(p, server.URL, func() ([]types.Finding, error) {
		return p.extractKMSKeyRotation(context.Background(), "test-run")
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 || findings[0].Status != "PASS" {
		t.Errorf("expected PASS for good rotation, got %s (count: %d)", findings[0].Status, len(findings))
	}
}

func TestExtractKMSKeyRotation_FailNoRotation(t *testing.T) {
	p := newTestProvider(t)
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		switch callCount {
		case 1:
			json.NewEncoder(w).Encode(map[string]any{
				"locations": []map[string]any{
					{"name": "projects/test-project/locations/global"},
				},
			})
		case 2:
			json.NewEncoder(w).Encode(map[string]any{
				"keyRings": []map[string]any{
					{"name": "projects/test-project/locations/global/keyRings/default"},
				},
			})
		case 3:
			json.NewEncoder(w).Encode(map[string]any{
				"cryptoKeys": []map[string]any{
					{
						"name":    "projects/test-project/locations/global/keyRings/default/cryptoKeys/stale-key",
						"purpose": "ENCRYPT_DECRYPT",
					},
				},
			})
		}
	}))
	defer server.Close()

	findings, err := testWithRedirect(p, server.URL, func() ([]types.Finding, error) {
		return p.extractKMSKeyRotation(context.Background(), "test-run")
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 || findings[0].Status != "FAIL" {
		t.Errorf("expected FAIL for no rotation, got %s", findings[0].Status)
	}
}

// --- Specific Requested Tests ---

func TestExtractAuditLogging_Pass(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"auditConfigs": []map[string]any{
				{
					"service": "allServices",
					"auditLogConfigs": []map[string]any{
						{"logType": "ADMIN_READ"},
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
	if len(findings) == 0 || findings[0].Status != "PASS" {
		t.Errorf("expected PASS, got %s", findings[0].Status)
	}
}

func TestExtractAuditLogging_Fail(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"auditConfigs": []map[string]any{
				{
					"service":         "someOtherService",
					"auditLogConfigs": []map[string]any{},
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
	if len(findings) == 0 || findings[0].Status != "FAIL" {
		t.Errorf("expected FAIL, got %s", findings[0].Status)
	}
}

func TestExtractStorageEncryption_Pass(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"items": []map[string]any{
				{
					"name": "secure-bucket",
					"encryption": map[string]any{
						"defaultKmsKeyName": "projects/p/locations/l/keyRings/r/cryptoKeys/k",
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
		return p.extractStorageEncryption(context.Background(), "test-run")
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 || findings[0].Status != "PASS" {
		t.Errorf("expected PASS, got %s", findings[0].Status)
	}
}

func TestExtractStorageEncryption_NoCMEK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"items": []map[string]any{
				{
					"name": "basic-bucket",
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
		return p.extractStorageEncryption(context.Background(), "test-run")
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// GCS is encrypted by default, so PASS is expected even without CMEK.
	if len(findings) == 0 || findings[0].Status != "PASS" {
		t.Errorf("expected PASS for NoCMEK, got %s", findings[0].Status)
	}
}

func TestExtractServiceAccountKeys_KeyListError(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			resp := map[string]any{
				"accounts": []map[string]any{
					{"email": "error@test-project.iam.gserviceaccount.com", "uniqueId": "456"},
				},
			}
			json.NewEncoder(w).Encode(resp)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	p := newTestProvider(t)
	p.httpClient = server.Client()

	_, err := testWithRedirect(p, server.URL, func() ([]types.Finding, error) {
		return p.extractServiceAccountKeys(context.Background(), "test-run")
	})
	if err == nil {
		t.Fatal("expected error for failed key listing")
	}
}

func TestExtractKMSKeyRotation_LocationError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	p := newTestProvider(t)
	p.httpClient = server.Client()

	_, err := testWithRedirect(p, server.URL, func() ([]types.Finding, error) {
		return p.extractKMSKeyRotation(context.Background(), "test-run")
	})
	if err == nil {
		t.Fatal("expected error for failed location listing")
	}
}

func TestToRawPayload(t *testing.T) {
	input := map[string]string{"foo": "bar"}
	output := toRawPayload(input)
	if output["foo"] != "bar" {
		t.Errorf("expected bar, got %v", output["foo"])
	}

	// Test unmarshalable input (e.g. channel)
	if toRawPayload(make(chan int)) != nil {
		t.Error("expected nil for unmarshalable input")
	}
}
