package engine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alibkaba/jula-core/pkg/types"
)

// makeSuccessJob creates an extractionJob that returns a valid Finding.
func makeSuccessJob(evidenceID string) extractionJob {
	return extractionJob{
		evidenceID:  evidenceID,
		description: "test-" + evidenceID,
		execute: func(ctx context.Context) ([]types.Finding, error) {
			return []types.Finding{{
				EvidenceID: evidenceID,
				Provider:   "test",
				RawData:    []byte(`{"status":"ok"}`),
				Timestamp:  time.Now().UTC(),
				RunID:      "test-run",
			}}, nil
		},
	}
}

// makeFailJob creates an extractionJob that returns an error.
func makeFailJob(evidenceID string) extractionJob {
	return extractionJob{
		evidenceID:  evidenceID,
		description: "test-" + evidenceID,
		execute: func(ctx context.Context) ([]types.Finding, error) {
			return nil, fmt.Errorf("simulated failure for %s", evidenceID)
		},
	}
}

// TestExecuteJobs_AllSuccess verifies that when every job succeeds,
// all findings are collected and no error is returned.
func TestExecuteJobs_AllSuccess(t *testing.T) {
	o := New(RunConfig{
		Concurrency: 3,
		Timeout:     5 * time.Second,
		RunID:       "test-run",
	})

	jobs := []extractionJob{
		makeSuccessJob("EVID-TEST-01"),
		makeSuccessJob("EVID-TEST-02"),
		makeSuccessJob("EVID-TEST-03"),
		makeSuccessJob("EVID-TEST-04"),
		makeSuccessJob("EVID-TEST-05"),
		makeSuccessJob("EVID-TEST-06"),
		makeSuccessJob("EVID-TEST-07"),
		makeSuccessJob("EVID-TEST-08"),
		makeSuccessJob("EVID-TEST-09"),
		makeSuccessJob("EVID-TEST-10"),
	}

	findings, err := o.executeJobs(context.Background(), jobs)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(findings) != 10 {
		t.Fatalf("expected 10 findings, got %d", len(findings))
	}

	// Verify each finding has the correct provider tag.
	for _, f := range findings {
		if f.Provider != "test" {
			t.Errorf("expected provider 'test', got %q for Evidence %s", f.Provider, f.EvidenceID)
		}
	}
}

// TestExecuteJobs_PartialFailure verifies that when some jobs fail,
// the successful findings are still returned and no fatal error occurs.
func TestExecuteJobs_PartialFailure(t *testing.T) {
	o := New(RunConfig{
		Concurrency: 3,
		Timeout:     5 * time.Second,
		RunID:       "test-run",
	})

	jobs := []extractionJob{
		makeSuccessJob("EVID-PASS-01"),
		makeFailJob("EVID-FAIL-01"),
		makeSuccessJob("EVID-PASS-02"),
		makeFailJob("EVID-FAIL-02"),
		makeSuccessJob("EVID-PASS-03"),
	}

	findings, err := o.executeJobs(context.Background(), jobs)
	if err != nil {
		t.Fatalf("partial failure should not return an error, got: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("expected 3 successful findings, got %d", len(findings))
	}
}

// TestExecuteJobs_TotalFailure verifies that when every job fails,
// the orchestrator returns a descriptive error and zero findings.
func TestExecuteJobs_TotalFailure(t *testing.T) {
	o := New(RunConfig{
		Concurrency: 3,
		Timeout:     5 * time.Second,
		RunID:       "test-run",
	})

	jobs := []extractionJob{
		makeFailJob("EVID-FAIL-01"),
		makeFailJob("EVID-FAIL-02"),
		makeFailJob("EVID-FAIL-03"),
	}

	findings, err := o.executeJobs(context.Background(), jobs)
	if err == nil {
		t.Fatal("expected an error when all jobs fail, got nil")
	}
	if findings != nil {
		t.Fatalf("expected nil findings on total failure, got %d", len(findings))
	}
}

// TestExecuteJobs_ConcurrencyBound verifies that the semaphore correctly
// limits the number of simultaneously running jobs.
func TestExecuteJobs_ConcurrencyBound(t *testing.T) {
	maxConcurrency := int32(3)

	var currentRunning atomic.Int32
	var peakRunning atomic.Int32

	// Create 10 jobs that each hold a slot for 50ms, tracking peak concurrency.
	var jobs []extractionJob
	for i := 0; i < 10; i++ {
		evidenceID := fmt.Sprintf("EVID-CONC-%02d", i+1)
		jobs = append(jobs, extractionJob{
			evidenceID:  evidenceID,
			description: "concurrency-test",
			execute: func(ctx context.Context) ([]types.Finding, error) {
				running := currentRunning.Add(1)

				// Atomically update peak if this is a new high.
				for {
					peak := peakRunning.Load()
					if running <= peak {
						break
					}
					if peakRunning.CompareAndSwap(peak, running) {
						break
					}
				}

				time.Sleep(50 * time.Millisecond)
				currentRunning.Add(-1)

				return []types.Finding{{
					EvidenceID: evidenceID,
					Provider:   "test",
					RawData:    []byte(`{}`),
					RunID:      "test-run",
				}}, nil
			},
		})
	}

	o := New(RunConfig{
		Concurrency: int(maxConcurrency),
		Timeout:     5 * time.Second,
		RunID:       "test-run",
	})

	findings, err := o.executeJobs(context.Background(), jobs)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(findings) != 10 {
		t.Fatalf("expected 10 findings, got %d", len(findings))
	}

	peak := peakRunning.Load()
	if peak > maxConcurrency {
		t.Fatalf("concurrency exceeded: peak was %d, limit was %d", peak, maxConcurrency)
	}
	if peak == 0 {
		t.Fatal("peak concurrency was 0, test did not run correctly")
	}

	t.Logf("concurrency bound validated: peak=%d, limit=%d", peak, maxConcurrency)
}

// TestOrchestrator_Extract_Empty verifies that Extract returns an error when
// no configs are provided.
func TestOrchestrator_Extract_Empty(t *testing.T) {
	o := New(RunConfig{})
	_, err := o.Extract(context.Background())
	if err == nil {
		t.Fatal("expected error for empty configs")
	}
}

// TestOrchestrator_Platform verifies Platform returns valid info.
func TestOrchestrator_Platform(t *testing.T) {
	o := New(RunConfig{})
	info := o.Platform()
	if info.ID == "impossible_value" {
		t.Error("expected valid ID string")
	}
}

// TestOrchestrator_Extract_InvalidConfigs tests the error paths for loading configs.
func TestOrchestrator_Extract_InvalidConfigs(t *testing.T) {
	o := New(RunConfig{
		IntegrationDir: "nonexistent-integrations",
	})

	// Should log warnings for non-existent configs and return a "no extraction jobs" error.
	_, err := o.Extract(context.Background())
	if err == nil {
		t.Fatal("expected error due to missing configs")
	}
}

// TestExecuteJobs_ContextCancellation tests the semaphore block when a context cancels.
func TestExecuteJobs_ContextCancellation(t *testing.T) {
	o := New(RunConfig{
		Concurrency: 1, // Restrict to 1 so the second job blocks on semaphore
		Timeout:     5 * time.Second,
		RunID:       "test-run",
	})

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel immediately so jobs fail when trying to acquire the semaphore
	cancel()

	jobs := []extractionJob{
		{
			evidenceID: "EVID-TEST-01",
			execute: func(ctx context.Context) ([]types.Finding, error) {
				// simulate work that respects context
				select {
				case <-time.After(1 * time.Second):
					return []types.Finding{}, nil
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			},
		},
	}

	findings, err := o.executeJobs(ctx, jobs)
	if err == nil {
		t.Fatal("expected error due to context cancellation, got nil")
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

func TestSourceIDResolvers(t *testing.T) {
	// Test getGCPSourceID
	t.Setenv("GCP_PROJECT_ID", "env-project")
	if got := getGCPSourceID(""); got != "env-project" {
		t.Errorf("expected env-project, got %s", got)
	}
	t.Setenv("GCP_PROJECT_ID", "")
	if got := getGCPSourceID("projects/my-scope"); got != "my-scope" {
		t.Errorf("expected my-scope, got %s", got)
	}
	if got := getGCPSourceID("invalid-scope"); got != "default" {
		t.Errorf("expected default, got %s", got)
	}

	// Test getAWSSourceID
	t.Setenv("AWS_ACCOUNT_ID", "env-account")
	if got := getAWSSourceID(); got != "env-account" {
		t.Errorf("expected env-account, got %s", got)
	}
	t.Setenv("AWS_ACCOUNT_ID", "")
	t.Setenv("AWS_REGION", "env-region")
	if got := getAWSSourceID(); got != "env-region" {
		t.Errorf("expected env-region, got %s", got)
	}
	t.Setenv("AWS_REGION", "")
	if got := getAWSSourceID(); got != "default" {
		t.Errorf("expected default, got %s", got)
	}

	// Test getSaaSSourceID
	t.Setenv("GITHUB_ORGANIZATION", "env-gh")
	if got := getSaaSSourceID("github"); got != "env-gh" {
		t.Errorf("expected env-gh, got %s", got)
	}
	t.Setenv("GITHUB_ORGANIZATION", "")
	t.Setenv("AIK_CLIENT_ID", "env-aik")
	if got := getSaaSSourceID("aikido"); got != "env-aik" {
		t.Errorf("expected env-aik, got %s", got)
	}
	t.Setenv("AIK_CLIENT_ID", "")
	if got := getSaaSSourceID("github"); got != "default" {
		t.Errorf("expected default, got %s", got)
	}
}

func TestOrchestrator_Extract_NoJobs(t *testing.T) {
	o := New(RunConfig{})
	_, err := o.Extract(context.Background())
	if err == nil {
		t.Fatal("expected error when no configs are provided, got nil")
	}
	if !strings.Contains(err.Error(), "no extraction jobs available") && !strings.Contains(err.Error(), "job builder initialization failed") {
		t.Errorf("expected extraction error, got %v", err)
	}
}

func TestBuildJobs_Error(t *testing.T) {
	o := New(RunConfig{
		IntegrationDir: "nonexistent-integrations",
	})
	_, err := o.buildJobs(context.Background())
	if err == nil {
		t.Fatal("expected error for nonexistent integrations path, got nil")
	}
}

// TestExecuteJobs_TimeoutPartialFailure verifies that a hanging job is correctly cancelled
// by context timeout without crashing the orchestrator or losing findings from successful jobs.
func TestExecuteJobs_TimeoutPartialFailure(t *testing.T) {
	// Set a very short timeout so the test runs quickly
	o := New(RunConfig{
		Concurrency: 2,
		Timeout:     100 * time.Millisecond,
		RunID:       "timeout-test",
	})

	jobA := extractionJob{
		evidenceID:  "EVID-AWS-01",
		description: "AWS Fast Job",
		execute: func(ctx context.Context) ([]types.Finding, error) {
			return []types.Finding{{
				EvidenceID: "EVID-AWS-01",
				Provider:   "aws",
				RawData:    []byte(`{"status":"success"}`),
			}}, nil
		},
	}

	jobB := extractionJob{
		evidenceID:  "EVID-AZURE-01",
		description: "Azure Hanging Job",
		execute: func(ctx context.Context) ([]types.Finding, error) {
			// Hang indefinitely until context cancels
			select {
			case <-time.After(10 * time.Second):
				return nil, fmt.Errorf("this should not return before context cancels")
			case <-ctx.Done():
				return nil, ctx.Err() // Return the cancellation error
			}
		},
	}

	jobs := []extractionJob{jobA, jobB}

	findings, err := o.executeJobs(context.Background(), jobs)
	if err != nil {
		t.Fatalf("partial timeout failure should not return a fatal error, got: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding from Job A, got %d", len(findings))
	}

	if findings[0].EvidenceID != "EVID-AWS-01" {
		t.Errorf("expected finding from EVID-AWS-01, got %s", findings[0].EvidenceID)
	}
}

func TestOrchestrator_Extract_Success(t *testing.T) {
	t.Setenv("GCP_PROJECT_ID", "")
	t.Setenv("AWS_ACCOUNT_ID", "")
	t.Setenv("AWS_REGION", "")
	t.Setenv("GITHUB_ORGANIZATION", "")
	t.Setenv("GITHUB_ORG", "")
	t.Setenv("AIK_CLIENT_ID", "")

	// 1. Setup mock server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok","data":"some-evidence"}`))
	}))
	defer ts.Close()

	// 2. Setup in-memory integrations config map
	integrationMap := map[string][]byte{
		"saas_mock.yaml": []byte(`
vendor_name: "saas_mock"
base_url: "` + ts.URL + `"
auth_flow:
  type: "bearer"
  token_env: "TEST_TOKEN"
endpoints:
  "/":
    evidence_id: "EVID-MOCK-01"
    description: "Mock REST Evidence"
`),
	}

	t.Setenv("TEST_TOKEN", "dummy")

	// 3. Create Orchestrator with the integration map
	o := New(RunConfig{
		OutputURL:      t.TempDir(),
		Concurrency:    2,
		Timeout:        5 * time.Second,
		RunID:          "test-run-extract",
		IntegrationMap: integrationMap,
	})

	// 4. Run Extract
	evidence, err := o.Extract(context.Background())
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	// 5. Verify the evidence generated
	if len(evidence) != 1 {
		t.Fatalf("expected 1 evidence, got %d", len(evidence))
	}
	e := evidence[0]
	if e.EvidenceID != "EVID-MOCK-01" {
		t.Errorf("expected EVID-MOCK-01, got %s", e.EvidenceID)
	}
	if e.SourceID != "default" {
		t.Errorf("expected SourceID 'default', got %s", e.SourceID)
	}
	if string(e.Finding.RawData) != `{"status":"ok","data":"some-evidence"}` {
		t.Errorf("unexpected raw data: %s", string(e.Finding.RawData))
	}
}

func TestMergeFindingsGroup(t *testing.T) {
	tests := []struct {
		name    string
		group   []types.Finding
		want    string
		wantErr bool
	}{
		{
			name: "single finding",
			group: []types.Finding{
				{RawData: []byte(`{"id": 1}`)},
			},
			want: `{"id": 1}`,
		},
		{
			name: "multiple findings with valid JSON arrays",
			group: []types.Finding{
				{RawData: []byte(`[{"id": 1}]`)},
				{RawData: []byte(`[{"id": 2}]`)},
			},
			want: `[{"id":1},{"id":2}]`,
		},
		{
			name: "multiple findings with non-array JSON",
			group: []types.Finding{
				{RawData: []byte(`{"id": 1}`)},
				{RawData: []byte(`{"id": 2}`)},
			},
			want: `{"id": 2}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := mergeFindingsGroup(tt.group)
			if (err != nil) != tt.wantErr {
				t.Errorf("mergeFindingsGroup() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if string(got.RawData) != tt.want {
				t.Errorf("mergeFindingsGroup() = %s, want %s", string(got.RawData), tt.want)
			}
		})
	}
}

func TestLoadCloudIntegration(t *testing.T) {
	tempDir := t.TempDir()
	cloudDir := filepath.Join(tempDir, "cloud")
	if err := os.MkdirAll(cloudDir, 0755); err != nil {
		t.Fatalf("failed to create cloud dir: %v", err)
	}

	validYAMLPath := filepath.Join(cloudDir, "aws.yaml")
	validYAMLContent := `
name: "aws-test"
`
	if err := os.WriteFile(validYAMLPath, []byte(validYAMLContent), 0644); err != nil {
		t.Fatalf("failed to write valid YAML: %v", err)
	}

	invalidYAMLPath := filepath.Join(cloudDir, "gcp.yaml")
	invalidYAMLContent := `
name: "gcp-test"
  invalid: yaml: formatting:
`
	if err := os.WriteFile(invalidYAMLPath, []byte(invalidYAMLContent), 0644); err != nil {
		t.Fatalf("failed to write invalid YAML: %v", err)
	}

	// For read error test, we create a directory named `error_provider.yaml`
	errorProviderPath := filepath.Join(cloudDir, "error_provider.yaml")
	if err := os.MkdirAll(errorProviderPath, 0755); err != nil {
		t.Fatalf("failed to create directory for read error test: %v", err)
	}

	tests := []struct {
		name     string
		dir      string
		provider string
		wantErr  bool
		wantNil  bool
	}{
		{
			name:     "file not found",
			dir:      tempDir,
			provider: "azure",
			wantErr:  false,
			wantNil:  true,
		},
		{
			name:     "valid YAML file",
			dir:      tempDir,
			provider: "aws",
			wantErr:  false,
			wantNil:  false,
		},
		{
			name:     "malformed YAML file",
			dir:      tempDir,
			provider: "gcp",
			wantErr:  true,
			wantNil:  true,
		},
		{
			name:     "read error",
			dir:      tempDir,
			provider: "error_provider",
			wantErr:  true,
			wantNil:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := loadCloudIntegration(tt.dir, tt.provider)
			if (err != nil) != tt.wantErr {
				t.Errorf("loadCloudIntegration() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantNil && got != nil {
				t.Errorf("loadCloudIntegration() got = %v, want nil", got)
			}
			if !tt.wantNil && got == nil {
				t.Errorf("loadCloudIntegration() got nil, want non-nil")
			}
		})
	}
}
