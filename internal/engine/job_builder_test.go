package engine

import (
	"context"
	"os"
	"testing"
)

func TestBuildHTTPGenericJobs(t *testing.T) {
	// Create a temp config file
	tmpDir := t.TempDir()
	configPath := tmpDir + "/saas_http.yaml"
	providersPath := tmpDir + "/providers.yaml"

	providersData := `
saas_http:
  base_url: "https://api.example.com"
  headers: {}
`
	if err := os.WriteFile(providersPath, []byte(providersData), 0644); err != nil {
		t.Fatalf("failed to write temp providers config: %v", err)
	}

	configData := `
SaaS-SCF-01:
  erl_id: "E-TEST-SaaS"
  description: "Test SaaS"
  provider: "saas_http"
  path: "/data"
`
	err := os.WriteFile(configPath, []byte(configData), 0644)
	if err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	o := New(RunConfig{
		SaaSConfigPath: configPath,
		RunID:          "test-run",
	})

	jobs, err := o.buildHTTPGenericJobs()
	if err != nil {
		t.Fatalf("failed to build jobs: %v", err)
	}

	if len(jobs) != 1 {
		t.Errorf("expected 1 job, got %d", len(jobs))
	}

	if jobs[0].erlID != "E-TEST-SaaS" {
		t.Errorf("expected erlID E-TEST-SaaS, got %s", jobs[0].erlID)
	}

	if jobs[0].scfID != "SaaS-SCF-01" {
		t.Errorf("expected scfID SaaS-SCF-01, got %s", jobs[0].scfID)
	}
}

func TestBuildAWSJobs_NoEnv(t *testing.T) {
	os.Unsetenv("AWS_REGION")
	os.Unsetenv("AWS_DEFAULT_REGION")

	o := New(RunConfig{})
	_, err := o.buildAWSJobs(context.Background())
	if err == nil {
		t.Error("expected error when AWS_REGION is missing")
	}
}

func TestBuildGCPJobs_InvalidPath(t *testing.T) {
	o := New(RunConfig{
		CAIConfigPath: "nonexistent.yaml",
	})
	_, err := o.buildGCPJobs(context.Background())
	if err == nil {
		t.Error("expected error when CAI config path is invalid")
	}
}
