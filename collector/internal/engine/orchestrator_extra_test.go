package engine

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/alibkaba/jula-core/pkg/types"
)

func TestLoadIntegrationsFromMap(t *testing.T) {
	tests := []struct {
		name           string
		integrationMap map[string][]byte
		wantErr        bool
		wantCount      int
	}{
		{
			name: "invalid yaml syntax",
			integrationMap: map[string][]byte{
				"test.yaml": []byte(`invalid yaml: - -`),
			},
			wantErr: true,
		},
		{
			name: "ignored file extension",
			integrationMap: map[string][]byte{
				"test.txt": []byte(`not evaluated`),
			},
			wantErr:   false,
			wantCount: 0,
		},
		{
			name: "valid yaml syntax",
			integrationMap: map[string][]byte{
				"test.yaml": []byte(`vendor_name: "test"`),
			},
			wantErr:   false,
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := loadIntegrationsFromMap(tt.integrationMap)
			if (err != nil) != tt.wantErr {
				t.Errorf("loadIntegrationsFromMap() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(res) != tt.wantCount {
				t.Errorf("loadIntegrationsFromMap() count = %v, want %v", len(res), tt.wantCount)
			}
		})
	}
}

func TestRunSingleExtractionJob(t *testing.T) {
	tests := []struct {
		name       string
		cancelCtx  bool
		wantErrors int
	}{
		{
			name:       "context canceled before start",
			cancelCtx:  true,
			wantErrors: 1,
		},
		{
			name:       "successful execution",
			cancelCtx:  false,
			wantErrors: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := New(RunConfig{Concurrency: 1, Timeout: 1 * time.Second})

			ctx := context.Background()
			var cancel context.CancelFunc
			if tt.cancelCtx {
				ctx, cancel = context.WithCancel(ctx)
				cancel() // cancel immediately
			}

			job := extractionJob{
				evidenceID: "TEST",
				execute: func(c context.Context) ([]types.Finding, error) {
					return nil, nil
				},
			}

			sem := make(chan struct{}, 1)
			if tt.cancelCtx {
				// Fill semaphore to block and force context path
				sem <- struct{}{}
			}

			var mu sync.Mutex
			var findings []types.Finding
			var realErrs []error
			var skipped []string

			o.runSingleExtractionJob(ctx, job, sem, &mu, &findings, &realErrs, &skipped)

			if len(realErrs) != tt.wantErrors {
				t.Errorf("runSingleExtractionJob() expected %v real errors, got %d", tt.wantErrors, len(realErrs))
			}
		})
	}
}

func TestLoadCloudIntegration(t *testing.T) {
	tmpDir := t.TempDir()
	cloudDir := filepath.Join(tmpDir, "cloud")
	if err := os.MkdirAll(cloudDir, 0755); err != nil {
		t.Fatal(err)
	}

	validYaml := []byte(`vendor_name: "aws"`)
	if err := os.WriteFile(filepath.Join(cloudDir, "aws.yaml"), validYaml, 0644); err != nil {
		t.Fatal(err)
	}

	malformedYaml := []byte(`
vendor_name: "test"
endpoints:
  - not
    - valid
`)
	if err := os.WriteFile(filepath.Join(cloudDir, "gcp.yaml"), malformedYaml, 0644); err != nil {
		t.Fatal(err)
	}

	// Create a dir to cause readfile error
	if err := os.MkdirAll(filepath.Join(cloudDir, "azure.yaml"), 0755); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		provider  string
		wantErr   bool
		wantCount int
	}{
		{
			name:      "integration does not exist",
			provider:  "non-existent",
			wantErr:   false,
			wantCount: 0,
		},
		{
			name:      "valid cloud integration",
			provider:  "aws",
			wantErr:   false,
			wantCount: 1,
		},
		{
			name:      "malformed cloud integration",
			provider:  "gcp",
			wantErr:   true,
			wantCount: 0,
		},
		{
			name:      "directory instead of file",
			provider:  "azure",
			wantErr:   true,
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := loadCloudIntegration(tmpDir, tt.provider)
			if (err != nil) != tt.wantErr {
				t.Errorf("loadCloudIntegration() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				resCount := 0
				if res != nil {
					resCount = 1
				}
				if resCount != tt.wantCount {
					t.Errorf("loadCloudIntegration() count = %v, want %v", resCount, tt.wantCount)
				}
			}
		})
	}
}

func TestLoadIntegrationsFromDir(t *testing.T) {
	tmpDir := t.TempDir()

	validYaml := []byte(`
vendor_name: "test"
endpoints: {}
`)
	if err := os.WriteFile(filepath.Join(tmpDir, "valid.yaml"), validYaml, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "valid2.yml"), validYaml, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "ignored.txt"), []byte("text"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create a dir to be ignored
	if err := os.MkdirAll(filepath.Join(tmpDir, "ignored_dir"), 0755); err != nil {
		t.Fatal(err)
	}

	malformedDir := t.TempDir()
	malformedYaml := []byte(`
vendor_name: "test"
endpoints:
  - not
    - valid
`)
	if err := os.WriteFile(filepath.Join(malformedDir, "malformed.yaml"), malformedYaml, 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		dir       string
		wantErr   bool
		wantCount int
	}{
		{
			name:      "directory does not exist",
			dir:       "non-existent-dir-for-sure",
			wantErr:   true,
			wantCount: 0,
		},
		{
			name:      "valid integrations",
			dir:       tmpDir,
			wantErr:   false,
			wantCount: 2,
		},
		{
			name:      "malformed integration",
			dir:       malformedDir,
			wantErr:   true,
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := loadIntegrationsFromDir(tt.dir)
			if (err != nil) != tt.wantErr {
				t.Errorf("loadIntegrationsFromDir() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(res) != tt.wantCount {
				t.Errorf("loadIntegrationsFromDir() count = %v, want %v", len(res), tt.wantCount)
			}
		})
	}
}

func TestDetermineSourceID(t *testing.T) {
	tests := []struct {
		name       string
		vendorName string
		evidenceID string
		env        map[string]string
		want       string
	}{
		{
			name:       "fallback to AWS",
			vendorName: "aws",
			evidenceID: "EVID-1",
			env:        map[string]string{"AWS_ACCOUNT_ID": "123"},
			want:       "123",
		},
		{
			name:       "fallback to GCP",
			vendorName: "gcp",
			evidenceID: "EVID-1",
			env:        map[string]string{"AWS_ACCOUNT_ID": "", "AWS_REGION": "", "GCP_PROJECT_ID": "456"},
			want:       "456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			o := New(RunConfig{})
			if got := o.determineSourceID(tt.vendorName, tt.evidenceID); got != tt.want {
				t.Errorf("determineSourceID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLoadIntegrationsFromConfig(t *testing.T) {
	tmpDir := t.TempDir()
	cloudDir := filepath.Join(tmpDir, "cloud")
	if err := os.MkdirAll(cloudDir, 0755); err != nil {
		t.Fatal(err)
	}

	validYaml := []byte(`vendor_name: "aws"`)
	if err := os.WriteFile(filepath.Join(cloudDir, "aws.yaml"), validYaml, 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		cfg     RunConfig
		wantErr bool
		want    int
	}{
		{
			name: "preferred from map",
			cfg: RunConfig{
				Provider: "aws",
				IntegrationMap: map[string][]byte{
					"test.yaml": []byte(`vendor_name: "test"`),
				},
			},
			wantErr: false,
			want:    1,
		},
		{
			name: "cloud integration",
			cfg: RunConfig{
				Provider:       "aws",
				IntegrationDir: tmpDir,
			},
			wantErr: false,
			want:    1,
		},
		{
			name: "directory error",
			cfg: RunConfig{
				IntegrationDir: "non-existent-dir",
			},
			wantErr: true,
			want:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := New(tt.cfg)
			res, err := o.loadIntegrationsFromConfig(context.Background())
			if (err != nil) != tt.wantErr {
				t.Errorf("loadIntegrationsFromConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(res) != tt.want {
				t.Errorf("loadIntegrationsFromConfig() count = %v, want %v", len(res), tt.want)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	tmpDir := t.TempDir()
	tests := []struct {
		name    string
		cfg     RunConfig
		wantErr bool
	}{
		{
			name: "build jobs error due to missing configs",
			cfg: RunConfig{
				IntegrationDir: "really-non-existent-dir",
			},
			wantErr: true,
		},
		{
			name: "no jobs due to empty dir",
			cfg: RunConfig{
				IntegrationDir: tmpDir,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := New(tt.cfg)
			_, err := o.Extract(context.Background())
			if (err != nil) != tt.wantErr {
				t.Errorf("Extract() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
