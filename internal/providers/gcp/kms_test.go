package gcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alibkaba/jula-evidence-collector/pkg/types"
)

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
