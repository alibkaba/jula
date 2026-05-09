package gcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alibkaba/jula-evidence-collector/pkg/types"
)

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
