package reporter

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
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

func TestLocalReporter_DeliverCreatesCorrectStructure(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpDir := t.TempDir()
	reporter := &LocalReporter{
		OutputDir:  tmpDir,
		SigningKey: privKey,
	}

	manifest, err := reporter.Deliver(context.Background(), testEvidence(), "test-run")
	if err != nil {
		t.Fatalf("deliver failed: %v", err)
	}

	// Verify manifest fields.
	if manifest.RunID != "test-run" {
		t.Errorf("expected run_id test-run, got %s", manifest.RunID)
	}
	if manifest.Signature == "" {
		t.Error("manifest signature should not be empty")
	}
	if len(manifest.EvidenceFiles) != 2 {
		t.Errorf("expected 2 evidence files, got %d", len(manifest.EvidenceFiles))
	}

	// Verify the manifest signature is valid.
	valid, err := crypto.VerifyManifest(manifest, &privKey.PublicKey)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if !valid {
		t.Error("manifest signature is invalid")
	}

	// Verify directory structure exists.
	runDate := time.Now().UTC().Format("2006-01-02")

	cc21Path := filepath.Join(tmpDir, runDate, "soc2", "CC2.1", "gcp.audit_logging.enabled_test-run.json")
	if _, err := os.Stat(cc21Path); os.IsNotExist(err) {
		t.Errorf("expected evidence file at %s", cc21Path)
	}

	c11Path := filepath.Join(tmpDir, runDate, "soc2", "C1.1", "gcp.storage.encryption_enabled_test-run.json")
	if _, err := os.Stat(c11Path); os.IsNotExist(err) {
		t.Errorf("expected evidence file at %s", c11Path)
	}

	// Verify manifest file exists at the run root.
	manifestPath := filepath.Join(tmpDir, runDate, "manifest.json")
	if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
		t.Errorf("expected manifest at %s", manifestPath)
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
	filePath := filepath.Join(tmpDir, runDate, "soc2", "CC2.1", "gcp.audit_logging.enabled_test-run.json")

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

func TestLocalReporter_ValidateRequiresOutputDir(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	reporter := &LocalReporter{SigningKey: privKey}
	if err := reporter.Validate(context.Background()); err == nil {
		t.Error("expected error for empty output dir")
	}
}

func TestLocalReporter_ValidateRequiresSigningKey(t *testing.T) {
	reporter := &LocalReporter{OutputDir: "/tmp/test"}
	if err := reporter.Validate(context.Background()); err == nil {
		t.Error("expected error for empty signing key")
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
	cancel() // Cancel immediately.

	_, err := r.Deliver(ctx, testEvidence(), "test-run")
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}


func TestLocalReporter_ValidateSuccess(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	r := &LocalReporter{
		OutputDir:  "/tmp/test",
		SigningKey: privKey,
	}
	if err := r.Validate(context.Background()); err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}
