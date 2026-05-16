package engine

import (
	"context"
	"os"
	"testing"
)

func TestBuildHTTPGenericJobs(t *testing.T) {
	// Create a temp config file
	tmpDir := t.TempDir()
	configPath := tmpDir + "/saas_http.json"
	
	configData := `{
		"E-TEST-SaaS": {
			"description": "Test SaaS",
			"provider": "saas_http",
			"endpoints": [
				{
					"url": "https://api.example.com/data",
					"method": "GET"
				}
			]
		}
	}`
	err := os.WriteFile(configPath, []byte(configData), 0644)
	if err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	o := New(RunConfig{
		SaaSConfigPath: configPath,
		RunID:         "test-run",
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
		CAIConfigPath: "nonexistent.json",
	})
	_, err := o.buildGCPJobs(context.Background())
	if err == nil {
		t.Error("expected error when CAI config path is invalid")
	}
}

