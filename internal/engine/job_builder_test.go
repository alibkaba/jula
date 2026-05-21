package engine

import (
	"context"
	"os"
	"testing"
)

func TestBuildUniversalRESTJobs(t *testing.T) {
	// Create a temp config directory with the integrations/universal_rest structure
	tmpDir := t.TempDir()
	restDir := tmpDir + "/universal_rest"
	if err := os.MkdirAll(restDir, 0755); err != nil {
		t.Fatalf("failed to create rest dir: %v", err)
	}

	integrationData := `
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
	err := os.WriteFile(restDir+"/test_integration.yaml", []byte(integrationData), 0644)
	if err != nil {
		t.Fatalf("failed to write temp integration: %v", err)
	}

	o := New(RunConfig{
		IntegrationDir: tmpDir,
		RunID:          "test-run",
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



func TestBuildUniversalCloudJobs_InvalidPath(t *testing.T) {
	o := New(RunConfig{
		IntegrationDir: "nonexistent",
	})
	_, err := o.buildUniversalCloudJobs(context.Background())
	if err == nil {
		t.Error("expected error when universal_cloud config path is invalid")
	}
}
