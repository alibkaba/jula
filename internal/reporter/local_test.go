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
			Finding: types.Finding{
				ID:        "gcp.audit_logging.enabled",
				Provider:  "gcp",
				Resource:  "audit_logging",
				Check:     "enabled",
				Status:    "PASS",
				Timestamp: time.Now().UTC(),
				RunID:     "test-run",
			},
			Framework:     "soc2",
			Criteria:      []string{"CC2.1"},
			ControlType:   "AUTOMATED",
			MappingRuleID: "soc2-cc2.1-audit-logging",
		},
		{
			Finding: types.Finding{
				ID:        "gcp.storage.encryption_enabled",
				Provider:  "gcp",
				Resource:  "storage",
				Check:     "encryption_enabled",
				Status:    "PASS",
				Timestamp: time.Now().UTC(),
				RunID:     "test-run",
			},
			Framework:     "soc2",
			Criteria:      []string{"C1.1"},
			ControlType:   "AUTOMATED",
			MappingRuleID: "soc2-c1.1-storage-encryption",
		},
	}
}

func TestLocalReporter_Deliver(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpDir := t.TempDir()

	tests := []struct {
		name           string
		format         string
		expectedSuffix string
	}{
		{
			name:           "Deliver with JSON Format",
			format:         "json",
			expectedSuffix: ".json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &LocalReporter{
				OutputDir:  tmpDir,
				SigningKey: privKey,
				Format:     tt.format,
			}

			manifest, err := r.Deliver(context.Background(), testEvidence(), "test-run-"+tt.format)
			if err != nil {
				t.Fatalf("deliver failed: %v", err)
			}

			found := false
			for _, f := range manifest.EvidenceFiles {
				if strings.HasSuffix(f.Path, tt.expectedSuffix) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("%s not found in manifest evidence files", tt.expectedSuffix)
			}
		})
	}
}

func TestLocalReporter_Name(t *testing.T) {
	r := &LocalReporter{}
	if r.Name() != "local" {
		t.Errorf("expected local, got %s", r.Name())
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
	// Check for renamed consolidated file
	consolidatedPath := filepath.Join(tmpDir, runDate, "soc2", "soc2_all_controls.json")
	if _, err := os.Stat(consolidatedPath); os.IsNotExist(err) {
		t.Errorf("consolidated file %s not found", consolidatedPath)
	}

	// Reporter uses Finding.ResourceIdentifier (sanitized) for filenames.
	// When ResourceIdentifier is empty, SanitizeResourceID returns "global_resource".
	filePath := filepath.Join(tmpDir, runDate, "soc2", "CC2.1", "gcp.audit_logging.enabled_global_resource_test-run.json")

	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("reading evidence file: %v", err)
	}

	var ev types.Evidence
	if err := json.Unmarshal(data, &ev); err != nil {
		t.Fatalf("evidence file is not valid JSON: %v", err)
	}

	if ev.Finding.ID != "gcp.audit_logging.enabled" {
		t.Errorf("unexpected finding ID in file: %s", ev.Finding.ID)
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
