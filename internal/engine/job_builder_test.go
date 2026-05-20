package engine

import (
	"context"
	"os"
	"testing"
)

func TestBuildUniversalRESTJobs(t *testing.T) {
	// Create a temp config directory
	tmpDir := t.TempDir()

	blueprintData := `
vendor_name: "test-vendor"
base_url: "https://api.example.com"
auth_flow:
  type: "bearer"
  token_env: "TEST_TOKEN"
endpoints:
  "/data":
    erl_id: "E-TEST-SaaS"
    description: "Test SaaS"
`
	err := os.WriteFile(tmpDir+"/test_blueprint.yaml", []byte(blueprintData), 0644)
	if err != nil {
		t.Fatalf("failed to write temp blueprint: %v", err)
	}

	o := New(RunConfig{
		OpenAPIBlueprintsDir: tmpDir,
		RunID:                "test-run",
	})

	jobs, err := o.buildUniversalRESTJobs()
	if err != nil {
		t.Fatalf("failed to build jobs: %v", err)
	}

	if len(jobs) != 1 {
		t.Errorf("expected 1 job, got %d", len(jobs))
	}

	if jobs[0].erlID != "E-TEST-SaaS" {
		t.Errorf("expected erlID E-TEST-SaaS, got %s", jobs[0].erlID)
	}

	if jobs[0].scfID != "TEST-SaaS" {
		t.Errorf("expected scfID TEST-SaaS, got %s", jobs[0].scfID)
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
		NativeBlueprintsDir: "nonexistent",
	})
	_, err := o.buildGCPJobs(context.Background())
	if err == nil {
		t.Error("expected error when CAI config path is invalid")
	}
}
