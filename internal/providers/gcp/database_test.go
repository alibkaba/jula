package gcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alibkaba/jula-evidence-collector/pkg/types"
)

func TestExtractCloudSQL_NoInstances(t *testing.T) {
	p := newTestProvider(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"items": []any{}})
	}))
	defer server.Close()

	findings, err := testWithRedirect(p, server.URL, func() ([]types.Finding, error) {
		return p.extractDatabase(context.Background(), "test-run")
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 || findings[0].Status != "PASS" {
		t.Errorf("expected PASS for no instances, got %s", findings[0].Status)
	}
	if findings[0].ID != "gcp.database.secure_config" {
		t.Errorf("unexpected finding ID: %s", findings[0].ID)
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
		return p.extractDatabase(context.Background(), "test-run")
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
		return p.extractDatabase(context.Background(), "test-run")
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 || findings[0].Status != "FAIL" {
		t.Errorf("expected FAIL for public IP, got %s", findings[0].Status)
	}
}

func TestExtractDatabase_Exception(t *testing.T) {
	p := newTestProvider(t)
	// Configure policy to have an exception for this instance
	p.policy.Exceptions = []Exception{
		{
			FindingID: "gcp.database.secure_config",
			Resource:  "excepted-db",
			Reason:    "legacy system requiring public access",
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"items": []map[string]any{
				{
					"name": "excepted-db",
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
		return p.extractDatabase(context.Background(), "test-run")
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 || findings[0].Status != "EXCEPTION" {
		t.Errorf("expected EXCEPTION, got %s", findings[0].Status)
	}
}
