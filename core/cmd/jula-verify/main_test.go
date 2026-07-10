package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alibkaba/jula-core/pkg/crypto"
	"github.com/alibkaba/jula-core/pkg/types"
)

// buildTestEvidenceDir creates a signed evidence directory for testing.
// Returns the output dir path and the private key used.
func buildTestEvidenceDir(t *testing.T) (string, *ecdsa.PrivateKey) {
	t.Helper()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	outputDir := t.TempDir()
	evidenceDir := filepath.Join(outputDir, "evidence")
	os.MkdirAll(evidenceDir, 0755)

	// Write a test evidence file.
	evidenceContent := []byte(`{"buckets": [{"name": "test", "encryption": "AES256"}]}`)
	evidencePath := filepath.Join(evidenceDir, "s3_buckets.json")
	os.WriteFile(evidencePath, evidenceContent, 0644)

	evidenceHash := crypto.HashFile(evidenceContent)

	// Create and sign provenance sidecar.
	prov := &crypto.Provenance{
		EvidenceID:  "s3_buckets.json",
		Provider:    "test-provider",
		SourceID:    "test-deploy",
		PayloadHash: evidenceHash,
		Timestamp:   time.Now().UTC(),
		ExtractionMetadata: map[string]string{
			"source_tool": "test-provider",
		},
	}
	if err := crypto.SignProvenance(prov, privKey); err != nil {
		t.Fatalf("signing provenance: %v", err)
	}

	provData, _ := json.MarshalIndent(prov, "", "  ")
	provPath := filepath.Join(evidenceDir, "s3_buckets.json.prov.json")
	os.WriteFile(provPath, provData, 0644)

	// Build manifest.
	manifest := &types.Manifest{
		RunID:     "test-run-001",
		Timestamp: time.Now().UTC(),
		Providers: []string{"test-provider"},
		EvidenceFiles: []types.FileChecksum{
			{Path: "evidence/s3_buckets.json", SHA256: evidenceHash},
			{Path: "evidence/s3_buckets.json.prov.json", SHA256: crypto.HashFile(provData)},
		},
	}

	if err := crypto.SignManifest(manifest, privKey); err != nil {
		t.Fatalf("signing manifest: %v", err)
	}

	manifestData, _ := json.MarshalIndent(manifest, "", "  ")
	os.WriteFile(filepath.Join(outputDir, "manifest.json"), manifestData, 0644)

	return outputDir, privKey
}

func TestVerifyChainSuccess(t *testing.T) {
	outputDir, privKey := buildTestEvidenceDir(t)

	result, err := verifyChain(context.Background(), verifyConfig{
		manifestPath: filepath.Join(outputDir, "manifest.json"),
		evidenceKey:  &privKey.PublicKey,
	})
	if err != nil {
		t.Fatalf("verifyChain failed: %v", err)
	}

	if result.runID != "test-run-001" {
		t.Errorf("expected run_id %q, got %q", "test-run-001", result.runID)
	}
	if result.filesVerified != 2 {
		t.Errorf("expected 2 files verified, got %d", result.filesVerified)
	}
	if result.provenanceVerified != 1 {
		t.Errorf("expected 1 provenance verified, got %d", result.provenanceVerified)
	}
}

func TestVerifyChainTamperedEvidence(t *testing.T) {
	outputDir, privKey := buildTestEvidenceDir(t)

	// Tamper with the evidence file.
	evidencePath := filepath.Join(outputDir, "evidence", "s3_buckets.json")
	os.WriteFile(evidencePath, []byte(`{"buckets": [{"name": "HACKED"}]}`), 0644)

	_, err := verifyChain(context.Background(), verifyConfig{
		manifestPath: filepath.Join(outputDir, "manifest.json"),
		evidenceKey:  &privKey.PublicKey,
	})
	if err == nil {
		t.Fatal("expected verification to fail for tampered evidence, got nil")
	}
	if got := err.Error(); !contains(got, "TAMPERING") {
		t.Errorf("expected TAMPERING error, got: %s", got)
	}
}

func TestVerifyChainWrongKey(t *testing.T) {
	outputDir, _ := buildTestEvidenceDir(t)

	// Use a different key for verification.
	wrongKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	_, err := verifyChain(context.Background(), verifyConfig{
		manifestPath: filepath.Join(outputDir, "manifest.json"),
		evidenceKey:  &wrongKey.PublicKey,
	})
	if err == nil {
		t.Fatal("expected verification to fail with wrong key, got nil")
	}
	if got := err.Error(); !contains(got, "INVALID") {
		t.Errorf("expected INVALID error, got: %s", got)
	}
}

func TestVerifyChainTamperedManifest(t *testing.T) {
	outputDir, privKey := buildTestEvidenceDir(t)

	// Load manifest, tamper with it, write back.
	manifestPath := filepath.Join(outputDir, "manifest.json")
	data, _ := os.ReadFile(manifestPath)
	var manifest types.Manifest
	json.Unmarshal(data, &manifest)

	// Change the run ID (content changes but signature stays the same).
	manifest.RunID = "tampered-run"
	tamperedData, _ := json.MarshalIndent(manifest, "", "  ")
	os.WriteFile(manifestPath, tamperedData, 0644)

	_, err := verifyChain(context.Background(), verifyConfig{
		manifestPath: manifestPath,
		evidenceKey:  &privKey.PublicKey,
	})
	if err == nil {
		t.Fatal("expected verification to fail for tampered manifest, got nil")
	}
}

func TestVerifyChainWithVerdict(t *testing.T) {
	outputDir, privKey := buildTestEvidenceDir(t)

	// Create and sign a verdict with a separate key (Key C).
	verdictKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	verdict := &crypto.Verdict{
		RunID:          "test-run-001",
		LedgerHash:     "abc123",
		ControlsPassed: 5,
		ControlsFailed: 1,
		ControlsTotal:  6,
		Timestamp:      time.Now().UTC(),
	}
	if err := crypto.SignVerdict(verdict, verdictKey); err != nil {
		t.Fatalf("signing verdict: %v", err)
	}

	verdictData, _ := json.MarshalIndent(verdict, "", "  ")
	verdictPath := filepath.Join(outputDir, "verdict.json")
	os.WriteFile(verdictPath, verdictData, 0644)

	// Also create and sign a policy bundle with another key (Key B).
	bundleKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	bundle := &crypto.PolicyBundle{
		BundleHash: "def456",
		Timestamp:  time.Now().UTC(),
	}
	if err := crypto.SignBundle(bundle, bundleKey); err != nil {
		t.Fatalf("signing bundle: %v", err)
	}

	bundleData, _ := json.MarshalIndent(bundle, "", "  ")
	bundlePath := filepath.Join(outputDir, "policy-bundle.json")
	os.WriteFile(bundlePath, bundleData, 0644)

	// Export public keys as PEM for the config.
	bundleKeyPEM := exportPublicKeyPEM(t, &bundleKey.PublicKey)
	verdictKeyPEM := exportPublicKeyPEM(t, &verdictKey.PublicKey)

	result, err := verifyChain(context.Background(), verifyConfig{
		manifestPath:  filepath.Join(outputDir, "manifest.json"),
		evidenceKey:   &privKey.PublicKey,
		bundlePath:    bundlePath,
		policyKeyPEM:  bundleKeyPEM,
		verdictPath:   verdictPath,
		verdictKeyPEM: verdictKeyPEM,
	})
	if err != nil {
		t.Fatalf("verifyChain failed: %v", err)
	}

	if !result.bundleVerified {
		t.Error("expected bundle to be verified")
	}
	if !result.verdictVerified {
		t.Error("expected verdict to be verified")
	}
}

func TestResolveBaseDir(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/tmp/output/manifest.json", "/tmp/output"},
		{"gs://bucket/prefix/manifest.json", "gs://bucket/prefix"},
		{"s3://bucket/prefix/sub/manifest.json", "s3://bucket/prefix/sub"},
	}
	for _, tt := range tests {
		got := resolveBaseDir(tt.input)
		if got != tt.expected {
			t.Errorf("resolveBaseDir(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

// exportPublicKeyPEM marshals an ECDSA public key to PEM format for testing.
func exportPublicKeyPEM(t *testing.T, pub *ecdsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshaling public key: %v", err)
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	return string(pem.EncodeToMemory(block))
}

// contains checks if a string contains a substring (simple helper for test assertions).
func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestResolveRelativeTo(t *testing.T) {
	// Create a temp directory to test local file walking
	tmpDir := t.TempDir()

	// Set up a directory structure:
	// tmpDir/output/deploy-abc/2026-06-23/manifest.json (dir: tmpDir/output/deploy-abc/2026-06-23)
	// tmpDir/output/deploy-abc/2026-06-23/evidence/file.json

	manifestDir := filepath.Join(tmpDir, "output", "deploy-abc", "2026-06-23")
	if err := os.MkdirAll(filepath.Join(manifestDir, "evidence"), 0755); err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	// Create the evidence file so os.Stat finds it
	evidencePathLocal := filepath.Join(manifestDir, "evidence", "file.json")
	if err := os.WriteFile(evidencePathLocal, []byte("test"), 0644); err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	tests := []struct {
		name         string
		baseDir      string
		evidencePath string
		want         string
	}{
		{
			name:         "GCS URL",
			baseDir:      "gs://my-bucket/prefix/deploy-abc/2026-06-23",
			evidencePath: "deploy-abc/2026-06-23/evidence/file.json",
			want:         "gs://my-bucket/deploy-abc/2026-06-23/evidence/file.json",
		},
		{
			name:         "S3 URL",
			baseDir:      "s3://my-bucket/prefix/deploy-abc/2026-06-23",
			evidencePath: "deploy-abc/2026-06-23/evidence/file.json",
			want:         "s3://my-bucket/deploy-abc/2026-06-23/evidence/file.json",
		},
		{
			name:         "Local path found by walking up",
			baseDir:      manifestDir,
			evidencePath: "deploy-abc/2026-06-23/evidence/file.json",
			want:         evidencePathLocal,
		},
		{
			name:         "Local path fallback (not found)",
			baseDir:      manifestDir,
			evidencePath: "does-not-exist/evidence.json",
			want:         filepath.Join(manifestDir, "does-not-exist/evidence.json"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveRelativeTo(tt.baseDir, tt.evidencePath)
			if got != tt.want {
				t.Errorf("resolveRelativeTo() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestReadArtifact(t *testing.T) {
	tmpDir := t.TempDir()
	validFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(validFile, []byte("hello world"), 0644); err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{
			name:    "Local file success",
			path:    validFile,
			wantErr: false,
		},
		{
			name:    "Local file not found",
			path:    filepath.Join(tmpDir, "nonexistent.txt"),
			wantErr: true,
		},
		{
			name:    "Cloud URL parsing failure",
			path:    "gs://my-bucket/prefix/\x00/invalid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := readArtifact(context.Background(), tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("readArtifact() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(data) == 0 {
				t.Errorf("readArtifact() returned empty data for valid path")
			}
		})
	}
}
