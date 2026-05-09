package gcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alibkaba/jula-evidence-collector/pkg/types"
)

func TestExtractRegistry_NoRepositories(t *testing.T) {
	p := newTestProvider(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/projects/test-project/locations" {
			json.NewEncoder(w).Encode(map[string]any{"locations": []map[string]any{{"locationId": "us-central1"}}})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"repositories": []any{}})
	}))
	defer server.Close()

	findings, err := testWithRedirect(p, server.URL, func() ([]types.Finding, error) {
		return p.extractRegistry(context.Background(), "test-run")
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 || findings[0].Status != "PASS" {
		t.Errorf("expected PASS finding for no repositories, got %s", findings[0].Status)
	}
	if findings[0].ID != "gcp.registry.image_scanned.none" {
		t.Errorf("unexpected finding ID: %s", findings[0].ID)
	}
}

func TestExtractRegistry_VulnerabilitiesFound(t *testing.T) {
	p := newTestProvider(t)
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		switch callCount {
		case 1: // List Locations
			json.NewEncoder(w).Encode(map[string]any{
				"locations": []map[string]any{
					{"locationId": "us-central1"},
				},
			})
		case 2: // List Repositories
			json.NewEncoder(w).Encode(map[string]any{
				"repositories": []map[string]any{
					{"name": "projects/test-project/locations/us-central1/repositories/my-repo"},
				},
			})
		case 3: // List Images
			json.NewEncoder(w).Encode(map[string]any{
				"dockerImages": []map[string]any{
					{
						"name": "projects/test-project/locations/us-central1/repositories/my-repo/dockerImages/my-image",
						"uri":  "us-central1-docker.pkg.dev/test-project/my-repo/my-image@sha256:abc",
					},
				},
			})
		case 4: // List Occurrences
			resp := map[string]any{
				"occurrences": []map[string]any{
					{
						"name": "projects/test-project/occurrences/vulnerability-123",
						"vulnerability": map[string]any{
							"effectiveSeverity": "HIGH",
							"shortDescription":  "CVE-2023-123",
						},
					},
				},
			}
			json.NewEncoder(w).Encode(resp)
		}
	}))
	defer server.Close()

	findings, err := testWithRedirect(p, server.URL, func() ([]types.Finding, error) {
		return p.extractRegistry(context.Background(), "test-run")
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 || findings[0].Status != "FAIL" {
		t.Fatalf("expected 1 FAIL finding, got %d (status: %s)", len(findings), findings[0].Status)
	}
}

func TestExtractRegistry_LocationListFailure(t *testing.T) {
	p := newTestProvider(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "API error", http.StatusInternalServerError)
	}))
	defer server.Close()

	_, err := testWithRedirect(p, server.URL, func() ([]types.Finding, error) {
		return p.extractRegistry(context.Background(), "test-run")
	})
	if err == nil {
		t.Fatal("expected error on location list failure, got nil")
	}
}

func TestIsSeverityAboveThreshold(t *testing.T) {
	p := newTestProvider(t)
	tests := []struct {
		severity  string
		threshold string
		expected  bool
	}{
		{"HIGH", "HIGH", true},
		{"CRITICAL", "HIGH", true},
		{"MEDIUM", "HIGH", false},
		{"LOW", "HIGH", false},
		{"INFORMATIONAL", "HIGH", false},
		{"HIGH", "LOW", true},
		{"HIGH", "CRITICAL", false},
	}

	for _, tt := range tests {
		result := p.isSeverityAboveThreshold(tt.severity, tt.threshold)
		if result != tt.expected {
			t.Errorf("isSeverityAboveThreshold(%s, %s) = %v; want %v", tt.severity, tt.threshold, result, tt.expected)
		}
	}
}
