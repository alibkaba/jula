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
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

	// Verify the assessor_ledger.json file was written to the mock bucket
	ledgerPath := filepath.Join(mockBucket, "assessor_ledger.json")
	ledgerData, err := os.ReadFile(ledgerPath)
	if err != nil {
		t.Fatalf("expected assessor_ledger.json to be written, got error: %v", err)
	}

	// Verify it contains valid JSON (not null)
	var ledgerFindings []map[string]interface{}
	if err := json.Unmarshal(ledgerData, &ledgerFindings); err != nil {
		t.Fatalf("expected valid JSON array in assessor_ledger.json, got error: %v", err)
	}

	if len(ledgerFindings) == 0 {
		t.Errorf("expected at least 1 finding in assessor_ledger.json, got 0")
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

	oldNewSafe := newSafeHTTPClient
	defer func() { newSafeHTTPClient = oldNewSafe }()
	newSafeHTTPClient = func(timeout time.Duration) *http.Client {
		return ts.Client()
	}

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

	oldNewSafe := newSafeHTTPClient
	defer func() { newSafeHTTPClient = oldNewSafe }()
	newSafeHTTPClient = func(timeout time.Duration) *http.Client {
		return ts.Client()
	}

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

func TestIsInvalidIP(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{"loopback ipv4", "127.0.0.1", true},
		{"loopback ipv6", "::1", true},
		{"link local unicast", "169.254.1.1", true},
		{"link local multicast", "224.0.0.251", true},
		{"valid internal", "10.0.0.1", false},
		{"valid external", "8.8.8.8", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if got := isInvalidIP(ip); got != tt.want {
				t.Errorf("isInvalidIP() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestShouldBlockIP(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		testEnv string
		want    bool
	}{
		{"test env true", "127.0.0.1", "true", false},
		{"invalid ip, test env false", "127.0.0.1", "false", true},
		{"invalid ip, test env empty", "169.254.169.254", "", true},
		{"valid ip", "8.8.8.8", "", false},
		{"non-ip host", "example.com", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("JULA_TEST_ENV", tt.testEnv)
			if got := shouldBlockIP(tt.host); got != tt.want {
				t.Errorf("shouldBlockIP() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateMetadataURL(t *testing.T) {
	tests := []struct {
		name      string
		pathOrURL string
		testEnv   string
		wantErr   bool
	}{
		{"valid url", "https://metadata.example.com", "", false},
		{"invalid scheme", "http://metadata.example.com", "", true},
		{"empty host", "https://", "", true},
		{"blocked ip", "https://169.254.169.254", "", true},
		{"blocked ip allowed in test env", "https://169.254.169.254", "true", false},
		{"unparseable url", "https://user:password@meta\x00data.example.com", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("JULA_TEST_ENV", tt.testEnv)
			_, err := validateMetadataURL(tt.pathOrURL)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateMetadataURL() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifyPolicyBundleSignature(t *testing.T) {
	privKey1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	privKey2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	pubKeyPEM1 := string(exportPublicKeyPEM(t, &privKey1.PublicKey))
	pubKeyPEM2 := string(exportPublicKeyPEM(t, &privKey2.PublicKey))

	tests := []struct {
		name        string
		setup       func(dir string) string // returns the pubKeyPEM to use
		wantErr     bool
		errContains string
	}{
		{
			name: "happy path",
			setup: func(dir string) string {
				bundle := &pkgCrypto.PolicyBundle{
					BundleHash: "test-hash",
					Timestamp:  time.Now().UTC(),
				}
				if err := pkgCrypto.SignBundle(bundle, privKey1); err != nil {
					t.Fatalf("failed to sign bundle: %v", err)
				}
				data, _ := json.Marshal(bundle)
				os.WriteFile(filepath.Join(dir, "bundle-manifest.json"), data, 0644)
				return pubKeyPEM1
			},
			wantErr: false,
		},
		{
			name: "invalid PEM",
			setup: func(dir string) string {
				return "invalid-pem"
			},
			wantErr:     true,
			errContains: "parse policy public key PEM",
		},
		{
			name: "missing bundle manifest",
			setup: func(dir string) string {
				return pubKeyPEM1
			},
			wantErr:     true,
			errContains: "bundle-manifest.json not found",
		},
		{
			name: "invalid JSON",
			setup: func(dir string) string {
				os.WriteFile(filepath.Join(dir, "bundle-manifest.json"), []byte("invalid json"), 0644)
				return pubKeyPEM1
			},
			wantErr:     true,
			errContains: "parse bundle-manifest.json",
		},
		{
			name: "invalid signature - wrong key",
			setup: func(dir string) string {
				bundle := &pkgCrypto.PolicyBundle{
					BundleHash: "test-hash",
					Timestamp:  time.Now().UTC(),
				}
				// Sign with key 1
				if err := pkgCrypto.SignBundle(bundle, privKey1); err != nil {
					t.Fatalf("failed to sign bundle: %v", err)
				}
				data, _ := json.Marshal(bundle)
				os.WriteFile(filepath.Join(dir, "bundle-manifest.json"), data, 0644)
				// Try to verify with key 2
				return pubKeyPEM2
			},
			wantErr:     true,
			errContains: "POLICY GATE FAILURE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			pem := tt.setup(dir)

			err := verifyPolicyBundleSignature(dir, pem)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				} else if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("expected error containing %q, got %v", tt.errContains, err)
				}
			} else {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
			}
		})
	}
}

func exportPublicKeyPEM(t *testing.T, pub *ecdsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshaling public key: %v", err)
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	return string(pem.EncodeToMemory(block))
}
