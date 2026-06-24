package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/alibkaba/jula-core/pkg/crypto"
)

// TestSignEvidenceEndToEnd exercises the full local signing flow:
// create evidence files → run signing logic → verify the manifest.
func TestSignEvidenceEndToEnd(t *testing.T) {
	// Generate a test ECDSA key pair.
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	// Create a temp input directory with test evidence files.
	inputDir := t.TempDir()
	outputDir := t.TempDir()

	testFiles := map[string]string{
		"s3_buckets.json":     `{"buckets": [{"name": "test-bucket", "encryption": "AES256"}]}`,
		"iam_policies.json":   `{"policies": [{"name": "admin-policy", "bindings": 3}]}`,
		"subdir/nested.json":  `{"nested": true}`,
		"raw_export.csv":      "control_id,status\nAC-1,pass\nAC-2,fail\n",
	}

	for name, content := range testFiles {
		fullPath := filepath.Join(inputDir, name)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
			t.Fatalf("failed to create dir for %s: %v", name, err)
		}
		if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
			t.Fatalf("failed to write %s: %v", name, err)
		}
	}

	// Run the signing logic (extracted from main for testability).
	manifest, err := signDirectory(context.Background(), signConfig{
		inputDir:     inputDir,
		outputURL:    outputDir,
		signingKey:   privKey,
		runID:        "test-run-001",
		deploymentID: "test-deploy",
		provider:     "test-provider",
		noSchema:     true,
	})
	if err != nil {
		t.Fatalf("signDirectory failed: %v", err)
	}

	// Verify manifest fields.
	if manifest.RunID != "test-run-001" {
		t.Errorf("expected run_id %q, got %q", "test-run-001", manifest.RunID)
	}
	if len(manifest.Providers) != 1 || manifest.Providers[0] != "test-provider" {
		t.Errorf("unexpected providers: %v", manifest.Providers)
	}

	// Each file produces an evidence entry + a provenance sidecar entry = 2 entries per file.
	expectedEntries := len(testFiles) * 2
	if len(manifest.EvidenceFiles) != expectedEntries {
		t.Errorf("expected %d evidence file entries, got %d", expectedEntries, len(manifest.EvidenceFiles))
	}

	// Verify signature is valid.
	ok, err := crypto.VerifyManifest(manifest, &privKey.PublicKey)
	if err != nil {
		t.Fatalf("VerifyManifest error: %v", err)
	}
	if !ok {
		t.Fatal("manifest signature verification failed")
	}

	// Verify each evidence file hash matches the uploaded content.
	for _, fc := range manifest.EvidenceFiles {
		fullPath := filepath.Join(outputDir, fc.Path)
		data, err := os.ReadFile(fullPath)
		if err != nil {
			t.Fatalf("failed to read uploaded file %q: %v", fc.Path, err)
		}
		actualHash := crypto.HashFile(data)
		if actualHash != fc.SHA256 {
			t.Errorf("hash mismatch for %q: manifest=%s, actual=%s", fc.Path, fc.SHA256, actualHash)
		}
	}

	// Verify each provenance sidecar is valid.
	for _, fc := range manifest.EvidenceFiles {
		if filepath.Ext(fc.Path) != ".json" {
			continue
		}
		fullPath := filepath.Join(outputDir, fc.Path)
		data, err := os.ReadFile(fullPath)
		if err != nil {
			t.Fatalf("failed to read %q: %v", fc.Path, err)
		}

		// Try to parse as provenance (only .prov.json files will succeed).
		var prov crypto.Provenance
		if json.Unmarshal(data, &prov) == nil && prov.Signature != "" {
			ok, err := crypto.VerifyProvenance(&prov, &privKey.PublicKey)
			if err != nil {
				t.Errorf("VerifyProvenance error for %q: %v", fc.Path, err)
			}
			if !ok {
				t.Errorf("provenance signature verification failed for %q", fc.Path)
			}
		}
	}

	// Verify the manifest.json was written to disk.
	manifestPath := filepath.Join(outputDir, "deploy-test-deploy", manifest.Timestamp.Format("2006-01-02"), "manifest.json")
	if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
		// Try without the date subfolder in case the path structure differs.
		entries, _ := filepath.Glob(filepath.Join(outputDir, "**", "manifest.json"))
		if len(entries) == 0 {
			// Check recursively
			found := false
			filepath.WalkDir(outputDir, func(path string, d os.DirEntry, err error) error {
				if d != nil && d.Name() == "manifest.json" {
					found = true
				}
				return nil
			})
			if !found {
				t.Error("manifest.json was not written to output directory")
			}
		}
	}
}

func TestSignDirectoryEmptyDir(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	emptyDir := t.TempDir()
	outputDir := t.TempDir()

	_, err := signDirectory(context.Background(), signConfig{
		inputDir:   emptyDir,
		outputURL:  outputDir,
		signingKey: privKey,
		runID:      "empty-test",
		provider:   "test",
	})

	if err == nil {
		t.Fatal("expected error for empty directory, got nil")
	}
}

func TestDetectContentType(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"data.json", "application/json"},
		{"export.csv", "text/csv"},
		{"report.xml", "application/xml"},
		{"doc.pdf", "application/pdf"},
		{"archive.gz", "application/gzip"},
		{"unknown.bin", "application/octet-stream"},
		{"DATA.JSON", "application/json"},
	}

	for _, tt := range tests {
		got := detectContentType(tt.path)
		if got != tt.expected {
			t.Errorf("detectContentType(%q) = %q, want %q", tt.path, got, tt.expected)
		}
	}
}

func TestTamperedManifestFails(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	inputDir := t.TempDir()
	outputDir := t.TempDir()

	os.WriteFile(filepath.Join(inputDir, "test.json"), []byte(`{"test": true}`), 0644)

	manifest, err := signDirectory(context.Background(), signConfig{
		inputDir:   inputDir,
		outputURL:  outputDir,
		signingKey: privKey,
		runID:      "tamper-test",
		provider:   "test",
		noSchema:   true,
	})
	if err != nil {
		t.Fatalf("signDirectory failed: %v", err)
	}

	// Tamper with the manifest by changing a hash.
	if len(manifest.EvidenceFiles) > 0 {
		manifest.EvidenceFiles[0].SHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
	}

	// Re-verify: signature should now fail because the content changed.
	ok, err := crypto.VerifyManifest(manifest, &privKey.PublicKey)
	if err != nil {
		t.Fatalf("VerifyManifest error: %v", err)
	}
	if ok {
		t.Fatal("expected verification to fail for tampered manifest, but it passed")
	}
}

// TestWrongKeyFails verifies that a manifest signed with one key
// does not verify with a different key.
func TestWrongKeyFails(t *testing.T) {
	privKey1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	privKey2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	inputDir := t.TempDir()
	outputDir := t.TempDir()

	os.WriteFile(filepath.Join(inputDir, "test.json"), []byte(`{"test": true}`), 0644)

	manifest, err := signDirectory(context.Background(), signConfig{
		inputDir:   inputDir,
		outputURL:  outputDir,
		signingKey: privKey1,
		runID:      "wrong-key-test",
		provider:   "test",
		noSchema:   true,
	})
	if err != nil {
		t.Fatalf("signDirectory failed: %v", err)
	}

	// Verify with a different key should fail.
	ok, err := crypto.VerifyManifest(manifest, &privKey2.PublicKey)
	if err != nil {
		t.Fatalf("VerifyManifest error: %v", err)
	}
	if ok {
		t.Fatal("expected verification to fail with wrong key, but it passed")
	}
}
