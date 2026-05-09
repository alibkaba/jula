package gcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alibkaba/jula-evidence-collector/pkg/types"
)

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
		return p.extractObjectStorageEncryption(context.Background(), "test-run")
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
		if f.ID != "gcp.object_storage.encryption_enabled" {
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
		return p.extractObjectStorageEncryption(context.Background(), "test-run")
	})
	if err == nil {
		t.Fatal("expected error for 500 response")
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
		return p.extractObjectStorageEncryption(context.Background(), "test-run")
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
		return p.extractObjectStorageEncryption(context.Background(), "test-run")
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// GCS is encrypted by default, so PASS is expected even without CMEK.
	if len(findings) == 0 || findings[0].Status != "PASS" {
		t.Errorf("expected PASS for NoCMEK, got %s", findings[0].Status)
	}
}
