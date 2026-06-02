package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	pkgCrypto "github.com/alibkaba/jula-core/pkg/crypto"
	"github.com/alibkaba/jula-core/pkg/types"
)

func generateMockKeyPair() (*ecdsa.PrivateKey, string, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	der, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, "", err
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}
	return privKey, string(pem.EncodeToMemory(block)), nil
}

func TestRunApp_MissingBucketURL(t *testing.T) {
	t.Setenv("JULA_BUCKET_URL", "")
	t.Setenv("JULA_POLICY_URL", "policies/")
	args := []string{"--policy-url", "policies/"}
	err := handleRun(args)
	if err == nil {
		t.Errorf("expected error for missing bucket URL, got nil")
	}
}

func TestRunApp_MissingPolicyURL(t *testing.T) {
	t.Setenv("JULA_BUCKET_URL", "gs://mock-bucket")
	t.Setenv("JULA_POLICY_URL", "")
	args := []string{"--bucket-url", "gs://mock-bucket"}
	err := handleRun(args)
	if err == nil {
		t.Errorf("expected error for missing policy URL, got nil")
	}
}

func TestRunApp_MissingPublicKey(t *testing.T) {
	t.Setenv("JULA_BUCKET_URL", "gs://mock-bucket")
	t.Setenv("JULA_POLICY_URL", "policies/")
	t.Setenv("JULA_PUBLIC_KEY", "")
	args := []string{"--bucket-url", "gs://mock-bucket", "--policy-url", "policies/"}
	err := handleRun(args)
	if err == nil {
		t.Errorf("expected error for missing public key, got nil")
	}
}

func TestRunApp_InvalidPublicKey(t *testing.T) {
	t.Setenv("JULA_BUCKET_URL", "gs://mock-bucket")
	t.Setenv("JULA_POLICY_URL", "policies/")
	t.Setenv("JULA_PUBLIC_KEY", "invalid-pem-key")
	args := []string{"--bucket-url", "gs://mock-bucket", "--policy-url", "policies/"}
	err := handleRun(args)
	if err == nil {
		t.Errorf("expected error for invalid public key, got nil")
	}
}

func TestRunApp_FullIntegration(t *testing.T) {
	// 1. Generate key pair and set JULA_PUBLIC_KEY.
	privKey, pubKeyPEM, err := generateMockKeyPair()
	if err != nil {
		t.Fatalf("failed to generate mock keys: %v", err)
	}
	t.Setenv("JULA_PUBLIC_KEY", pubKeyPEM)

	// 2. Create mock GCS/local bucket directory.
	mockBucket, err := os.MkdirTemp("", "jula-mock-bucket-*")
	if err != nil {
		t.Fatalf("failed to create temp bucket dir: %v", err)
	}
	defer os.RemoveAll(mockBucket)

	// Create directories for evidence files.
	evidenceDir := filepath.Join(mockBucket, "evidence", "BCD-11.4")
	if err := os.MkdirAll(evidenceDir, 0755); err != nil {
		t.Fatalf("failed to create evidence dir: %v", err)
	}

	// 3. Define compliant evidence content.
	rawFindingData := []byte(`[
		{
			"resource": {
				"data": {
					"settings": {
						"ipConfiguration": {
							"requireSsl": true
						}
					}
				}
			}
		}
	]`)

	rawHash := pkgCrypto.HashFile(rawFindingData)
	evidenceObj := &types.Evidence{
		ControlID:  "BCD-11.4",
		EvidenceID: "EVID-BCM-16",
		SourceID:   "src-1",
		Finding: types.Finding{
			ControlID:  "BCD-11.4",
			EvidenceID: "EVID-BCM-16",
			SourceID:   "src-1",
			Provider:   "gcp_cai",
			RawData:    rawFindingData,
			Timestamp:  time.Now().UTC(),
			RunID:      "test-run-1",
		},
		PayloadHash: rawHash,
	}
	evidenceContent, err := json.Marshal(evidenceObj)
	if err != nil {
		t.Fatalf("failed to marshal evidence: %v", err)
	}

	evidencePath := "evidence/BCD-11.4/db_cai.json"
	fullEvidencePath := filepath.Join(mockBucket, evidencePath)
	if err := os.WriteFile(fullEvidencePath, evidenceContent, 0644); err != nil {
		t.Fatalf("failed to write evidence file: %v", err)
	}
	evidenceHash := pkgCrypto.HashFile(evidenceContent)

	// 4. Create signed provenance sidecar.
	prov := &pkgCrypto.Provenance{
		EvidenceID:  "EVID-BCM-16",
		Provider:    "gcp_cai",
		SourceID:    "src-1",
		PayloadHash: rawHash,
		Timestamp:   time.Now().UTC(),
	}
	if err := pkgCrypto.SignProvenance(prov, privKey); err != nil {
		t.Fatalf("failed to sign provenance: %v", err)
	}
	provBytes, err := json.Marshal(prov)
	if err != nil {
		t.Fatalf("failed to marshal provenance: %v", err)
	}

	provPath := "evidence/BCD-11.4/db_cai.prov.json"
	fullProvPath := filepath.Join(mockBucket, provPath)
	if err := os.WriteFile(fullProvPath, provBytes, 0644); err != nil {
		t.Fatalf("failed to write provenance file: %v", err)
	}
	provHash := pkgCrypto.HashFile(provBytes)

	// 5. Create signed manifest file.
	manifest := &types.Manifest{
		RunID:     "test-run-1",
		Timestamp: time.Now().UTC(),
		Providers: []string{"gcp"},
		EvidenceFiles: []types.FileChecksum{
			{Path: evidencePath, SHA256: evidenceHash},
			{Path: provPath, SHA256: provHash},
		},
	}
	if err := pkgCrypto.SignManifest(manifest, privKey); err != nil {
		t.Fatalf("failed to sign manifest: %v", err)
	}

	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("failed to marshal manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(mockBucket, "manifest.json"), manifestBytes, 0644); err != nil {
		t.Fatalf("failed to write manifest file: %v", err)
	}

	// 6. Create OPA Policies directory.
	mockPolicies, err := os.MkdirTemp("", "jula-mock-policies-*")
	if err != nil {
		t.Fatalf("failed to create temp policies dir: %v", err)
	}
	defer os.RemoveAll(mockPolicies)

	policyContent := []byte(`package compliance.controls.bcd_11_4

import rego.v1

evaluation := {
	"control_id": "BCD-11.4",
	"customer_control_id": "CC-1",
	"compliant": is_compliant
}

default is_compliant = false

is_compliant if {
	db_checks := input.findings["EVID-BCM-16"]
	every _, check in db_checks {
		check.raw_data[0].resource.data.settings.ipConfiguration.requireSsl == true
	}
}
`)
	if err := os.WriteFile(filepath.Join(mockPolicies, "gcp_db_encryption.rego"), policyContent, 0644); err != nil {
		t.Fatalf("failed to write policy file: %v", err)
	}

	// 7. Run handleRun with these resources!
	args := []string{
		"--bucket-url", "file://" + mockBucket,
		"--policy-url", mockPolicies,
	}

	err = handleRun(args)
	if err != nil {
		t.Errorf("expected nil error (compliant audit), got %v", err)
	}

	// Verify the evaluator_ledger.json file was written to the mock bucket
	ledgerPath := filepath.Join(mockBucket, "evaluator_ledger.json")
	ledgerData, err := os.ReadFile(ledgerPath)
	if err != nil {
		t.Fatalf("expected evaluator_ledger.json to be written, got error: %v", err)
	}

	// Verify it contains valid JSON (not null)
	var ledgerFindings []map[string]interface{}
	if err := json.Unmarshal(ledgerData, &ledgerFindings); err != nil {
		t.Fatalf("expected valid JSON array in evaluator_ledger.json, got error: %v", err)
	}

	if len(ledgerFindings) == 0 {
		t.Errorf("expected at least 1 finding in evaluator_ledger.json, got 0")
	}
}

func TestResolvers_Main(t *testing.T) {

}

func TestPrintUsage(t *testing.T) {
	printUsage() // just ensure it doesn't panic
}

func TestLoadMetadata(t *testing.T) {
	// Test nonexistent file
	_, err := loadMetadata("nonexistent.yaml")
	if err == nil {
		t.Errorf("expected error for non-existent file")
	}

	// Test valid file
	meta, err := loadMetadata("metadata_test.json")
	if err != nil {
		t.Errorf("expected no error for valid file, got %v", err)
	}
	if meta["key"] != "value" {
		t.Errorf("expected key to be value")
	}
}

func TestDownloadPolicies_LocalPath(t *testing.T) {
	ctx := context.Background()
	path, err := downloadPolicies(ctx, "local/path/to/policies")
	if err != nil {
		t.Errorf("expected no error for local path, got %v", err)
	}
	if path != "local/path/to/policies" {
		t.Errorf("expected path to be returned unmodified")
	}
}

func TestDispatchDriftAlert_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"success"}`))
	}))
	defer ts.Close()

	t.Setenv("JULA_GOVERNOR_REPO", "test/governor")
	t.Setenv("JULA_DISPATCH_TOKEN", "test-token")

	oldClient := dispatchClient
	defer func() { dispatchClient = oldClient }()
	dispatchClient = ts.Client()

	dispatchDriftAlert("gcp", "storage", "raw-payload")
}

func TestDispatchDriftAlert_Unconfigured(t *testing.T) {
	t.Setenv("JULA_GOVERNOR_REPO", "")
	t.Setenv("JULA_DISPATCH_TOKEN", "")

	dispatchDriftAlert("gcp", "storage", "raw-payload")
}

func TestLoadMetadata_URLSuccess(t *testing.T) {
	t.Setenv("JULA_TEST_ENV", "true")
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"key":"value-url"}`))
	}))
	defer ts.Close()

	oldNewSafeHTTPClient := newSafeHTTPClient
	defer func() { newSafeHTTPClient = oldNewSafeHTTPClient }()
	newSafeHTTPClient = func(timeout time.Duration) *http.Client {
		return ts.Client()
	}

	meta, err := loadMetadata(ts.URL)
	if err != nil {
		t.Fatalf("loadMetadata failed: %v", err)
	}
	if meta["key"] != "value-url" {
		t.Errorf("expected key to be value-url, got %v", meta["key"])
	}
}

func TestDownloadPolicies_URLSuccess(t *testing.T) {
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)

	policyContent := `package compliance.controls.test_policy
evaluation := {"control_id": "TEST-1", "compliant": true}`

	hdr := &tar.Header{
		Name: "test_policy.rego",
		Mode: 0644,
		Size: int64(len(policyContent)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("failed to write tar header: %v", err)
	}
	if _, err := tw.Write([]byte(policyContent)); err != nil {
		t.Fatalf("failed to write tar body: %v", err)
	}

	tw.Close()
	gzw.Close()

	tarGzBytes := buf.Bytes()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		w.WriteHeader(http.StatusOK)
		w.Write(tarGzBytes)
	}))
	defer ts.Close()

	oldDefaultHTTPClient := defaultHTTPClient
	defer func() { defaultHTTPClient = oldDefaultHTTPClient }()
	defaultHTTPClient = ts.Client()

	ctx := context.Background()
	policiesDir, err := downloadPolicies(ctx, ts.URL)
	if err != nil {
		t.Fatalf("downloadPolicies failed: %v", err)
	}
	defer os.RemoveAll(policiesDir)

	extractedFile := filepath.Join(policiesDir, "test_policy.rego")
	content, err := os.ReadFile(extractedFile)
	if err != nil {
		t.Fatalf("failed to read extracted file: %v", err)
	}
	if string(content) != policyContent {
		t.Errorf("extracted content mismatch. Expected %q, got %q", policyContent, string(content))
	}
}
