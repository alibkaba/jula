package gcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alibkaba/jula-evidence-collector/pkg/types"
)

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
