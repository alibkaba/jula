package ingestion

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/alibkaba/jula-core/pkg/types"
)

func TestNewCloudReader_Local(t *testing.T) {
	dir := t.TempDir()
	reader, err := NewCloudReader(dir)
	if err != nil {
		t.Fatalf("NewCloudReader failed: %v", err)
	}
	if reader == nil {
		t.Fatal("expected non-nil reader")
	}
}

func TestNewCloudReader_FileScheme(t *testing.T) {
	dir := t.TempDir()
	reader, err := NewCloudReader("file://" + dir)
	if err != nil {
		t.Fatalf("NewCloudReader with file:// failed: %v", err)
	}
	if reader == nil {
		t.Fatal("expected non-nil reader")
	}
}

func TestNewCloudReader_GCSScheme(t *testing.T) {
	reader, err := NewCloudReader("gs://my-bucket/deploy-abc/2026-01-15")
	if err != nil {
		t.Fatalf("NewCloudReader with gs:// failed: %v", err)
	}
	if reader == nil {
		t.Fatal("expected non-nil reader")
	}
}

func TestNewCloudReader_S3Scheme(t *testing.T) {
	reader, err := NewCloudReader("s3://my-bucket/deploy-abc/2026-01-15")
	if err != nil {
		t.Fatalf("NewCloudReader with s3:// failed: %v", err)
	}
	if reader == nil {
		t.Fatal("expected non-nil reader")
	}
}

func TestCloudReader_LocalLifecycle(t *testing.T) {
	dir := t.TempDir()

	// Create a manifest file.
	manifest := types.Manifest{
		RunID:     "run-test-123",
		Providers: []string{"gcp", "github"},
		EvidenceFiles: []types.FileChecksum{
			{Path: "evidence/ctrl-1/ev1.json", SHA256: "abc123"},
		},
	}
	manifestData, _ := json.MarshalIndent(manifest, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), manifestData, 0644); err != nil {
		t.Fatalf("failed to write manifest: %v", err)
	}

	// Create an evidence file.
	evidenceDir := filepath.Join(dir, "evidence", "ctrl-1")
	if err := os.MkdirAll(evidenceDir, 0700); err != nil {
		t.Fatalf("failed to create evidence dir: %v", err)
	}
	evidenceData := []byte(`{"finding": "test-evidence"}`)
	if err := os.WriteFile(filepath.Join(evidenceDir, "ev1.json"), evidenceData, 0644); err != nil {
		t.Fatalf("failed to write evidence: %v", err)
	}

	// Create reader.
	reader, err := NewCloudReader(dir)
	if err != nil {
		t.Fatalf("NewCloudReader failed: %v", err)
	}

	ctx := context.Background()

	// Read manifest.
	m, err := reader.ReadManifest(ctx)
	if err != nil {
		t.Fatalf("ReadManifest failed: %v", err)
	}
	if m.RunID != "run-test-123" {
		t.Fatalf("expected run ID 'run-test-123', got %q", m.RunID)
	}
	if len(m.EvidenceFiles) != 1 {
		t.Fatalf("expected 1 evidence file, got %d", len(m.EvidenceFiles))
	}

	// Read payloads.
	payloads, err := reader.ReadPayloads(ctx, m.EvidenceFiles)
	if err != nil {
		t.Fatalf("ReadPayloads failed: %v", err)
	}
	if len(payloads) != 1 {
		t.Fatalf("expected 1 payload, got %d", len(payloads))
	}
	if !bytes.Equal(payloads["evidence/ctrl-1/ev1.json"], evidenceData) {
		t.Fatalf("payload content mismatch")
	}

	// Write file.
	writeData := []byte(`{"result": "pass"}`)
	if err := reader.WriteFile(ctx, "assessor_ledger.json", writeData); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// Verify written file.
	written, err := os.ReadFile(filepath.Join(dir, "assessor_ledger.json"))
	if err != nil {
		t.Fatalf("written file not found: %v", err)
	}
	if !bytes.Equal(written, writeData) {
		t.Fatalf("written content mismatch")
	}
}

func TestCloudReader_ReadManifest_NotFound(t *testing.T) {
	dir := t.TempDir()
	reader, _ := NewCloudReader(dir)

	_, err := reader.ReadManifest(context.Background())
	if err == nil {
		t.Fatal("expected error for missing manifest")
	}
}

func TestCloudReader_ReadPayloads_MissingFile(t *testing.T) {
	dir := t.TempDir()
	reader, _ := NewCloudReader(dir)

	files := []types.FileChecksum{
		{Path: "nonexistent.json", SHA256: "abc"},
	}

	_, err := reader.ReadPayloads(context.Background(), files)
	if err == nil {
		t.Fatal("expected error for missing payload file")
	}
}

func TestCloudReader_ReadManifest_InvalidJSON(t *testing.T) {
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte("{invalid"), 0644); err != nil {
		t.Fatalf("failed to write manifest: %v", err)
	}

	reader, _ := NewCloudReader(dir)

	_, err := reader.ReadManifest(context.Background())
	if err == nil {
		t.Fatal("expected error for invalid json manifest")
	}
}

func TestCloudReader_ReadPayloads_CancelContext(t *testing.T) {
	reader, _ := NewCloudReader("http://127.0.0.1:0")

	files := []types.FileChecksum{
		{Path: "f1.json", SHA256: "abc"},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := reader.ReadPayloads(ctx, files)
	if err == nil {
		t.Fatal("expected error for canceled context")
	}
}
