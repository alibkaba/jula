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
	"time"
	"strings"

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

func TestSignDirectory_SchemaValidation(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	tests := []struct {
		name       string
		file       string
		content    string
		wantError  bool
		errMessage string
	}{
		{
			name:      "Valid JSON schema",
			file:      "valid.json",
			content:   `{"control_id":"CTL-1","evidence_id":"EVID-1","source_id":"SRC-1","finding":{"control_id":"CTL-1","evidence_id":"EVID-1","source_id":"SRC-1","provider":"prov","raw_data":{"key":"val"},"timestamp":"2023-10-10T10:00:00Z","run_id":"run-1"},"payload_hash":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}`,
			wantError: false,
		},
		{
			name:       "Invalid JSON schema",
			file:       "invalid.json",
			content:    `{"missing":"required_fields"}`,
			wantError:  true,
			errMessage: "schema validation failed for",
		},
		{
			name:      "Non-JSON file skipped",
			file:      "ignored.txt",
			content:   "just some text",
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputDir := t.TempDir()
			outputDir := t.TempDir()

			fullPath := filepath.Join(inputDir, tt.file)
			if err := os.WriteFile(fullPath, []byte(tt.content), 0644); err != nil {
				t.Fatalf("failed to write file %s: %v", tt.file, err)
			}

			_, err := signDirectory(context.Background(), signConfig{
				inputDir:   inputDir,
				outputURL:  outputDir,
				signingKey: privKey,
				runID:      "schema-test",
				provider:   "test",
				noSchema:   false, // Explicitly enable schema validation
			})

			if tt.wantError {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.errMessage)
				}
				if !strings.Contains(err.Error(), tt.errMessage) {
					t.Errorf("expected error containing %q, got %v", tt.errMessage, err)
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
			}
		})
	}
}

func TestSignDirectory_ObjectStoreError(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	inputDir := t.TempDir()

	// Need at least one file so we don't fail the length check
	if err := os.WriteFile(filepath.Join(inputDir, "test.txt"), []byte("test"), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	invalidURL := string([]byte{0x00}) + "://invalid-url"

	_, err = signDirectory(context.Background(), signConfig{
		inputDir:   inputDir,
		outputURL:  invalidURL,
		signingKey: privKey,
		runID:      "test",
		provider:   "test",
		noSchema:   true,
	})

	if err == nil {
		t.Fatalf("expected error from invalid output URL, got nil")
	}
	if !strings.Contains(err.Error(), "creating object store") && !strings.Contains(err.Error(), "uploading evidence") {
		t.Errorf("expected error containing 'creating object store', got %v", err)
	}
}

func TestSignDirectory_UploadProvenanceError(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	inputDir := t.TempDir()

	// Create a dummy file
	os.WriteFile(filepath.Join(inputDir, "test.json"), []byte(`{}`), 0644)

	// To cause upload error for provenance, we can create a fake read-only directory
	// and use it as the output URL
	outputDir := t.TempDir()

	// Pre-create the provenance file as a directory so it fails when trying to create a file
	provPath := filepath.Join(outputDir, time.Now().UTC().Format("2006-01-02"), "evidence", "test.json.prov.json")
	os.MkdirAll(provPath, 0755)

	_, err := signDirectory(context.Background(), signConfig{
		inputDir:   inputDir,
		outputURL:  outputDir,
		signingKey: privKey,
		runID:      "test",
		provider:   "test",
		noSchema:   true,
	})

	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "uploading provenance") {
		t.Errorf("expected error to contain 'uploading provenance', got: %v", err)
	}
}

func TestSignDirectory_UploadEvidenceError(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	inputDir := t.TempDir()

	// Create a dummy file
	os.WriteFile(filepath.Join(inputDir, "test.txt"), []byte(`test`), 0644)

	outputDir := t.TempDir()

	// Pre-create the evidence file as a directory so it fails when trying to create a file
	evidencePath := filepath.Join(outputDir, time.Now().UTC().Format("2006-01-02"), "evidence", "test.txt")
	os.MkdirAll(evidencePath, 0755)

	_, err := signDirectory(context.Background(), signConfig{
		inputDir:   inputDir,
		outputURL:  outputDir,
		signingKey: privKey,
		runID:      "test",
		provider:   "test",
		noSchema:   true,
	})

	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "uploading evidence") {
		t.Errorf("expected error to contain 'uploading evidence', got: %v", err)
	}
}

func TestSignDirectory_UploadManifestError(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	inputDir := t.TempDir()

	// Create a dummy file
	os.WriteFile(filepath.Join(inputDir, "test.json"), []byte(`{}`), 0644)

	outputDir := t.TempDir()

	// Pre-create the manifest file as a directory so it fails when trying to create a file
	manifestPath := filepath.Join(outputDir, time.Now().UTC().Format("2006-01-02"), "manifest.json")
	os.MkdirAll(manifestPath, 0755)

	_, err := signDirectory(context.Background(), signConfig{
		inputDir:   inputDir,
		outputURL:  outputDir,
		signingKey: privKey,
		runID:      "test",
		provider:   "test",
		noSchema:   true,
	})

	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "uploading manifest") {
		t.Errorf("expected error to contain 'uploading manifest', got: %v", err)
	}
}

func TestSignDirectory_UnreadableFile(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	inputDir := t.TempDir()
	outputDir := t.TempDir()

	unreadableFile := filepath.Join(inputDir, "unreadable.txt")
	// creating directory instead of file will cause read error on some systems
	// on linux, os.ReadFile on a directory returns an error
	os.WriteFile(unreadableFile, []byte("test"), 0000)

	_, err := signDirectory(context.Background(), signConfig{
		inputDir:   inputDir,
		outputURL:  outputDir,
		signingKey: privKey,
		runID:      "test",
		provider:   "test",
		noSchema:   true,
	})

	if err == nil {
		t.Fatalf("expected error reading file, got nil")
	}
	if !strings.Contains(err.Error(), "reading file") {
		t.Errorf("expected error containing 'reading file', got %v", err)
	}
}

func TestSignDirectory_WalkDirError(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	inputDir := t.TempDir()

	// Create a subdirectory with no execute permissions to trigger walkErr
	subDir := filepath.Join(inputDir, "restricted")
	os.MkdirAll(subDir, 0000)

	_, err := signDirectory(context.Background(), signConfig{
		inputDir:   inputDir,
		outputURL:  t.TempDir(),
		signingKey: privKey,
		runID:      "test",
		provider:   "test",
		noSchema:   true,
	})

	if err == nil {
		t.Fatalf("expected error reading restricted directory, got nil")
	}
	if !strings.Contains(err.Error(), "walking input directory") {
		t.Errorf("expected error containing 'walking input directory', got %v", err)
	}

	// Cleanup so t.TempDir can be removed
	os.Chmod(subDir, 0755)
}

func TestSignDirectory_NilKeyError(t *testing.T) {
	inputDir := t.TempDir()

	// Create a dummy file
	os.WriteFile(filepath.Join(inputDir, "test.txt"), []byte(`test`), 0644)

	outputDir := t.TempDir()

	_, err := signDirectory(context.Background(), signConfig{
		inputDir:   inputDir,
		outputURL:  outputDir,
		signingKey: nil,
		runID:      "test",
		provider:   "test",
		noSchema:   true,
	})

	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "signing provenance for") {
		t.Errorf("expected error to contain 'signing provenance for', got: %v", err)
	}
}
