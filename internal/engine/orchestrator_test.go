package engine

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alibkaba/jula-core/pkg/types"
)

// makeSuccessJob creates an extractionJob that returns a valid Finding.
func makeSuccessJob(erlID string) extractionJob {
	return extractionJob{
		erlID:       erlID,
		description: "test-" + erlID,
		execute: func(ctx context.Context) (types.Finding, error) {
			return types.Finding{
				ErlID:     erlID,
				Provider:  "test",
				RawData:   []byte(`{"status":"ok"}`),
				Timestamp: time.Now().UTC(),
				RunID:     "test-run",
			}, nil
		},
	}
}

// makeFailJob creates an extractionJob that returns an error.
func makeFailJob(erlID string) extractionJob {
	return extractionJob{
		erlID:       erlID,
		description: "test-" + erlID,
		execute: func(ctx context.Context) (types.Finding, error) {
			return types.Finding{}, fmt.Errorf("simulated failure for %s", erlID)
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
		makeSuccessJob("E-TEST-01"),
		makeSuccessJob("E-TEST-02"),
		makeSuccessJob("E-TEST-03"),
		makeSuccessJob("E-TEST-04"),
		makeSuccessJob("E-TEST-05"),
		makeSuccessJob("E-TEST-06"),
		makeSuccessJob("E-TEST-07"),
		makeSuccessJob("E-TEST-08"),
		makeSuccessJob("E-TEST-09"),
		makeSuccessJob("E-TEST-10"),
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
			t.Errorf("expected provider 'test', got %q for ERL %s", f.Provider, f.ErlID)
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
		makeSuccessJob("E-PASS-01"),
		makeFailJob("E-FAIL-01"),
		makeSuccessJob("E-PASS-02"),
		makeFailJob("E-FAIL-02"),
		makeSuccessJob("E-PASS-03"),
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
		makeFailJob("E-FAIL-01"),
		makeFailJob("E-FAIL-02"),
		makeFailJob("E-FAIL-03"),
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
		erlID := fmt.Sprintf("E-CONC-%02d", i+1)
		jobs = append(jobs, extractionJob{
			erlID:       erlID,
			description: "concurrency-test",
			execute: func(ctx context.Context) (types.Finding, error) {
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

				return types.Finding{
					ErlID:    erlID,
					Provider: "test",
					RawData:  []byte(`{}`),
					RunID:    "test-run",
				}, nil
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
		CAIConfigPath:  "nonexistent-cai.yaml",
		AWSConfigPath:  "nonexistent-aws.yaml",
		SaaSConfigPath: "nonexistent-saas.yaml",
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
			erlID: "E-TEST-01",
			execute: func(ctx context.Context) (types.Finding, error) {
				// simulate work that respects context
				select {
				case <-time.After(1 * time.Second):
					return types.Finding{}, nil
				case <-ctx.Done():
					return types.Finding{}, ctx.Err()
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

// TestOrchestrator_BuildAWSJobs_NoRegion tests the AWS initialization guard rail.
func TestOrchestrator_BuildAWSJobs_NoRegion(t *testing.T) {
	// Unset AWS region env vars
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_DEFAULT_REGION", "")

	o := New(RunConfig{
		AWSConfigPath: "dummy.yaml",
	})

	_, err := o.buildAWSJobs(context.Background())
	if err == nil || err.Error() != "AWS_REGION or AWS_DEFAULT_REGION is required for AWS Config provider" {
		t.Errorf("expected missing AWS_REGION error, got %v", err)
	}
}

// TestOrchestrator_BuildGCPJobs tests the building of GCP CAI extraction jobs.
func TestOrchestrator_BuildGCPJobs(t *testing.T) {
	// A structurally valid JSON credential file to satisfy Google's application default credentials.
	// Note: We need a valid RSA private key to prevent ParseKey errors.

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	})

	credData := fmt.Sprintf(`{
		"type": "service_account",
		"project_id": "test-project",
		"private_key_id": "123",
		"private_key": %q,
		"client_email": "test@test-project.iam.gserviceaccount.com",
		"client_id": "123",
		"auth_uri": "https://accounts.google.com/o/oauth2/auth",
		"token_uri": "https://oauth2.googleapis.com/token",
		"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
		"client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/test%%40test-project.iam.gserviceaccount.com"
	}`, string(pemBytes))

	credFile := t.TempDir() + "/creds.json"
	if err := os.WriteFile(credFile, []byte(credData), 0644); err != nil {
		t.Fatalf("failed to write fake creds: %v", err)
	}
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", credFile)

	validConfigPath := t.TempDir() + "/cai_valid.yaml"
	validConfigData := `
GCP-SCF-01:
  erl_id: "E-TEST-GCP"
  description: "Test GCP"
  scope: "projects/test-project"
  query: "state:ACTIVE"
`
	if err := os.WriteFile(validConfigPath, []byte(validConfigData), 0644); err != nil {
		t.Fatalf("failed to write valid config: %v", err)
	}

	tests := []struct {
		name         string
		configPath   string
		expectErr    bool
		expectedJobs int
	}{
		{
			name:         "Success",
			configPath:   validConfigPath,
			expectErr:    false,
			expectedJobs: 1,
		},
		{
			name:         "Invalid Config Path",
			configPath:   "nonexistent_cai.yaml",
			expectErr:    true,
			expectedJobs: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o := New(RunConfig{
				CAIConfigPath: tc.configPath,
				RunID:         "test-run",
			})

			jobs, err := o.buildGCPJobs(context.Background())

			if tc.expectErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
				if len(jobs) != tc.expectedJobs {
					t.Errorf("expected %d jobs, got %d", tc.expectedJobs, len(jobs))
				}
				if len(jobs) > 0 {
					if jobs[0].erlID != "E-TEST-GCP" {
						t.Errorf("expected job erlID to be E-TEST-GCP, got %s", jobs[0].erlID)
					}
					if jobs[0].scfID != "GCP-SCF-01" {
						t.Errorf("expected job scfID to be GCP-SCF-01, got %s", jobs[0].scfID)
					}
				}
			}
		})
	}
}

// TestOrchestrator_BuildAWSJobs tests the building of AWS Config extraction jobs.
func TestOrchestrator_BuildAWSJobs(t *testing.T) {
	// Need to ensure AWS Region is set to get past the early guard rail
	t.Setenv("AWS_REGION", "us-east-1")

	validConfigPath := t.TempDir() + "/aws_valid.yaml"
	validConfigData := `
AWS-SCF-01:
  erl_id: "E-TEST-AWS"
  description: "Test AWS"
  query: "SELECT resourceId"
`
	if err := os.WriteFile(validConfigPath, []byte(validConfigData), 0644); err != nil {
		t.Fatalf("failed to write valid config: %v", err)
	}

	tests := []struct {
		name         string
		configPath   string
		expectErr    bool
		expectedJobs int
	}{
		{
			name:         "Success",
			configPath:   validConfigPath,
			expectErr:    false,
			expectedJobs: 1,
		},
		{
			name:         "Invalid Config Path",
			configPath:   "nonexistent_aws.yaml",
			expectErr:    true,
			expectedJobs: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o := New(RunConfig{
				AWSConfigPath: tc.configPath,
				RunID:         "test-run",
			})

			jobs, err := o.buildAWSJobs(context.Background())

			if tc.expectErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
				if len(jobs) != tc.expectedJobs {
					t.Errorf("expected %d jobs, got %d", tc.expectedJobs, len(jobs))
				}
				if len(jobs) > 0 {
					if jobs[0].erlID != "E-TEST-AWS" {
						t.Errorf("expected job erlID to be E-TEST-AWS, got %s", jobs[0].erlID)
					}
					if jobs[0].scfID != "AWS-SCF-01" {
						t.Errorf("expected job scfID to be AWS-SCF-01, got %s", jobs[0].scfID)
					}
				}
			}
		})
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
	if !strings.Contains(err.Error(), "no extraction jobs available") {
		t.Errorf("expected 'no extraction jobs available' error, got %v", err)
	}
}

func TestBuildHTTPGenericJobs_Error(t *testing.T) {
	o := New(RunConfig{
		SaaSConfigPath: "nonexistent_saas.yaml",
	})
	_, err := o.buildHTTPGenericJobs()
	if err == nil {
		t.Fatal("expected error for nonexistent saas config path, got nil")
	}
}
