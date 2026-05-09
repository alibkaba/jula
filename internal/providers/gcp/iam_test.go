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
