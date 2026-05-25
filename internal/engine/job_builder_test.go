package engine

import (
	"context"
	"os"
	"testing"
)

func TestBuildJobs_RESTIntegration(t *testing.T) {
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_ACCESS_KEY_ID", "DUMMYKEY")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "DUMMYSECRET")
	t.Setenv("GCP_PROJECT_ID", "dummy-project")

	// Create a temp flat integrations directory
	tmpDir := t.TempDir()

	integrationData := `
vendor_name: "test-vendor"
base_url: "https://api.example.com"
auth_flow:
  type: "bearer"
  token_env: "TEST_TOKEN"
endpoints:
  "/data":
    evidence_id: "EVID-TEST-SaaS"
    description: "Test SaaS"
`
	err := os.WriteFile(tmpDir+"/test_integration.yaml", []byte(integrationData), 0644)
	if err != nil {
		t.Fatalf("failed to write temp integration: %v", err)
	}

	o := New(RunConfig{
		IntegrationDir: tmpDir,
		RunID:          "test-run",
	})

	jobs, err := o.buildJobs(context.Background())
	if err != nil {
		t.Fatalf("failed to build jobs: %v", err)
	}

	if len(jobs) != 1 {
		t.Errorf("expected 1 job, got %d", len(jobs))
	}

	if jobs[0].evidenceID != "EVID-TEST-SaaS" {
		t.Errorf("expected evidenceID EVID-TEST-SaaS, got %s", jobs[0].evidenceID)
	}

	if jobs[0].controlID != "TEST-SaaS" {
		t.Errorf("expected controlID TEST-SaaS, got %s", jobs[0].controlID)
	}
}

func TestBuildJobs_CloudIntegration(t *testing.T) {
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_ACCESS_KEY_ID", "DUMMYKEY")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "DUMMYSECRET")
	t.Setenv("GCP_PROJECT_ID", "dummy-project")

	// Create a temp flat integrations directory
	tmpDir := t.TempDir()

	cloudData := `
vendor_name: "aws"
provider: "aws"
auth_flow:
  type: "aws_sigv4"
endpoints:
  "https://config.us-east-1.amazonaws.com/":
    method: "POST"
    evidence_id: "EVID-TEST-CLOUD"
    description: "Test Cloud"
    body:
      Expression: "SELECT resourceId"
`
	err := os.WriteFile(tmpDir+"/aws_test.yaml", []byte(cloudData), 0644)
	if err != nil {
		t.Fatalf("failed to write temp cloud integration: %v", err)
	}

	o := New(RunConfig{
		IntegrationDir: tmpDir,
		RunID:          "test-run",
	})

	jobs, err := o.buildJobs(context.Background())
	if err != nil {
		t.Fatalf("failed to build jobs: %v", err)
	}

	if len(jobs) != 1 {
		t.Errorf("expected 1 job, got %d", len(jobs))
	}

	if jobs[0].evidenceID != "EVID-TEST-CLOUD" {
		t.Errorf("expected evidenceID EVID-TEST-CLOUD, got %s", jobs[0].evidenceID)
	}
}

func TestBuildJobs_InvalidPath(t *testing.T) {
	o := New(RunConfig{
		IntegrationDir: "nonexistent",
	})
	_, err := o.buildJobs(context.Background())
	if err == nil {
		t.Error("expected error when integrations directory path is invalid")
	}
}
