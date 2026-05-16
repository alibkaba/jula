package reporter

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alibkaba/jula-evidence-collector/pkg/crypto"
	"github.com/alibkaba/jula-evidence-collector/pkg/types"
)

func testEvidence() []types.Evidence {
	return []types.Evidence{
		{
			ErlID:       "E-TEST-01",
			PayloadHash: "abc123hash",
			Finding: types.Finding{
				ErlID:     "E-TEST-01",
				Provider:  "gcp_cai",
				RawData:   []byte(`{"status":"ok"}`),
				Timestamp: time.Now().UTC(),
				RunID:     "test-run",
			},
		},
		{
			ErlID:       "E-TEST-02",
			PayloadHash: "def456hash",
			Finding: types.Finding{
				ErlID:     "E-TEST-02",
				Provider:  "aws_config",
				RawData:   []byte(`{"status":"ok"}`),
				Timestamp: time.Now().UTC(),
				RunID:     "test-run",
			},
		},
	}
}

func TestLocalReporter_Name(t *testing.T) {
	r := &LocalReporter{}
	if r.Name() != "local" {
		t.Errorf("expected local, got %s", r.Name())
	}
}

func TestLocalReporter_Validate(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	tests := []struct {
		name    string
		r       *LocalReporter
		wantErr bool
	}{
		{
			name:    "Missing OutputDir",
			r:       &LocalReporter{SigningKey: privKey},
			wantErr: true,
		},
		{
			name:    "Missing SigningKey",
			r:       &LocalReporter{OutputDir: "/tmp"},
			wantErr: true,
		},
		{
			name:    "Valid Config",
			r:       &LocalReporter{OutputDir: "/tmp", SigningKey: privKey},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.r.Validate(context.Background())
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestLocalReporter_Deliver(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpDir := t.TempDir()

	r := &LocalReporter{
		OutputDir:  tmpDir,
		SigningKey: privKey,
	}

	manifest, err := r.Deliver(context.Background(), testEvidence(), "test-run")
	if err != nil {
		t.Fatalf("deliver failed: %v", err)
	}

	if len(manifest.EvidenceFiles) != 2 {
		t.Errorf("expected 2 evidence files in manifest, got %d", len(manifest.EvidenceFiles))
	}

	foundGCP := false
	foundAWS := false
	for _, f := range manifest.EvidenceFiles {
		if strings.HasSuffix(f.Path, "gcp_cai_abc123hash.json") {
			foundGCP = true
		}
		if strings.HasSuffix(f.Path, "aws_config_def456hash.json") {
			foundAWS = true
		}
	}

	if !foundGCP {
		t.Error("GCP evidence file not found in manifest")
	}
	if !foundAWS {
		t.Error("AWS evidence file not found in manifest")
	}
}

func TestLocalReporter_EvidenceFileContainsValidJSON(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpDir := t.TempDir()
	reporter := &LocalReporter{
		OutputDir:  tmpDir,
		SigningKey: privKey,
	}

	if _, err := reporter.Deliver(context.Background(), testEvidence(), "test-run"); err != nil {
		t.Fatalf("deliver failed: %v", err)
	}

	runDate := time.Now().UTC().Format("2006-01-02")
	filePath := filepath.Join(tmpDir, runDate, "evidence", "E-TEST-01", "gcp_cai_abc123hash.json")

	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("reading evidence file: %v", err)
	}

	var ev types.Evidence
	if err := json.Unmarshal(data, &ev); err != nil {
		t.Fatalf("evidence file is not valid JSON: %v", err)
	}

	if ev.Finding.ErlID != "E-TEST-01" {
		t.Errorf("unexpected finding ERL ID in file: %s", ev.Finding.ErlID)
	}
}

func TestLocalReporter_ContextCancellation(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpDir := t.TempDir()
	r := &LocalReporter{
		OutputDir:  tmpDir,
		SigningKey: privKey,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := r.Deliver(ctx, testEvidence(), "test-run")
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

func TestLocalReporter_ManifestSignature(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpDir := t.TempDir()
	r := &LocalReporter{
		OutputDir:  tmpDir,
		SigningKey: privKey,
	}

	manifest, err := r.Deliver(context.Background(), testEvidence(), "test-run")
	if err != nil {
		t.Fatalf("deliver failed: %v", err)
	}

	valid, err := crypto.VerifyManifest(manifest, &privKey.PublicKey)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if !valid {
		t.Error("manifest signature is invalid")
	}
}

// TestLocalReporter_Deliver_Negative tests file system error paths.
func TestLocalReporter_Deliver_Negative(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Create a deeply invalid path by using a file as a directory path
	// This forces os.MkdirAll to fail deterministically
	tempFile := filepath.Join(t.TempDir(), "invalid_dir_file")
	if err := os.WriteFile(tempFile, []byte("file content"), 0644); err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	reporter := &LocalReporter{
		OutputDir:  tempFile,
		SigningKey: key,
	}

	evidence := []types.Evidence{
		{ErlID: "E-TEST", Finding: types.Finding{RawData: []byte(`{}`)}},
	}

	_, err := reporter.Deliver(context.Background(), evidence, "test-run")
	if err == nil {
		t.Fatal("expected delivery to fail due to invalid output directory")
	}
	if !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("expected 'not a directory' error, got %v", err)
	}
}
