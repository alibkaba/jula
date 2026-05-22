package main

import (
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
		SCFID:    "BCD-11.4",
		ErlID:    "E-BCM-16",
		SourceID: "src-1",
		Finding: types.Finding{
			SCFID:     "BCD-11.4",
			ErlID:     "E-BCM-16",
			SourceID:  "src-1",
			Provider:  "gcp_cai",
			RawData:   rawFindingData,
			Timestamp: time.Now().UTC(),
			RunID:     "test-run-1",
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
		ErlID:       "E-BCM-16",
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

	policyContent := []byte(`package compliance.scf.bcd_11_4
import rego.v1

default compliant = false
scf_id := "BCD-11.4"
customer_control_id := "CC-1"

compliant if {
	db_checks := input.findings["E-BCM-16"]
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
}

func TestResolvers_Main(t *testing.T) {
	// Test resolveScfIDFromPath
	scfTests := []struct {
		path     string
		expected string
	}{
		{"evidence/BCD-11.4/db_cai.json", "BCD-11.4"},
		{"evidence/E-BCM-16/db_cai.json", "E-BCM-16"},
		{"nested/evidence/SCF-1/file.json", "SCF-1"},
		{"no_evidence/here/file.json", ""},
	}
	for _, tc := range scfTests {
		if got := resolveScfIDFromPath(tc.path); got != tc.expected {
			t.Errorf("resolveScfIDFromPath(%s) = %s, expected %s", tc.path, got, tc.expected)
		}
	}
}
