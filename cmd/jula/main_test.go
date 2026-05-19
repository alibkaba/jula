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

	pkgCrypto "github.com/alibkaba/jula-evidence-evaluator/pkg/crypto"
	"github.com/alibkaba/jula-evidence-evaluator/pkg/types"
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

func TestRunApp_Compile_MissingCSV(t *testing.T) {
	args := []string{"jula", "compile"}
	exitCode := runApp(args)
	if exitCode != 1 {
		t.Errorf("expected exit code 1 for missing csv parameter, got %d", exitCode)
	}
}

func TestRunApp_Compile_Success(t *testing.T) {
	csvFile, err := os.CreateTemp("", "catalog-*.csv")
	if err != nil {
		t.Fatalf("failed to create temp CSV: %v", err)
	}
	defer os.Remove(csvFile.Name())

	csvContent := `Control ID,ERL ID
BCD-11.4,E-BCM-16
`
	if _, err := csvFile.Write([]byte(csvContent)); err != nil {
		t.Fatalf("failed to write CSV content: %v", err)
	}
	csvFile.Close()

	outputFile, err := os.CreateTemp("", "mappings-*.json")
	if err != nil {
		t.Fatalf("failed to create temp JSON output: %v", err)
	}
	outputFile.Close()
	defer os.Remove(outputFile.Name())

	args := []string{"jula", "compile", "--csv", csvFile.Name(), "--output", outputFile.Name()}
	exitCode := runApp(args)
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}

	// Verify output file exists
	if _, err := os.Stat(outputFile.Name()); os.IsNotExist(err) {
		t.Errorf("expected output file to exist, but it doesn't")
	}
}

func TestRunApp_MissingBucketURL(t *testing.T) {
	t.Setenv("JULA_BUCKET_URL", "")
	t.Setenv("JULA_POLICY_URL", "policies/")
	args := []string{"jula", "--policy-url", "policies/"}
	exitCode := runApp(args)
	if exitCode != 1 {
		t.Errorf("expected exit code 1 for missing bucket URL, got %d", exitCode)
	}
}

func TestRunApp_MissingPolicyURL(t *testing.T) {
	t.Setenv("JULA_BUCKET_URL", "gs://mock-bucket")
	t.Setenv("JULA_POLICY_URL", "")
	args := []string{"jula", "--bucket-url", "gs://mock-bucket"}
	exitCode := runApp(args)
	if exitCode != 1 {
		t.Errorf("expected exit code 1 for missing policy URL, got %d", exitCode)
	}
}

func TestRunApp_MissingPublicKey(t *testing.T) {
	t.Setenv("JULA_BUCKET_URL", "gs://mock-bucket")
	t.Setenv("JULA_POLICY_URL", "policies/")
	t.Setenv("JULA_PUBLIC_KEY", "")
	args := []string{"jula", "--bucket-url", "gs://mock-bucket", "--policy-url", "policies/"}
	exitCode := runApp(args)
	if exitCode != 1 {
		t.Errorf("expected exit code 1 for missing public key, got %d", exitCode)
	}
}

func TestRunApp_InvalidPublicKey(t *testing.T) {
	t.Setenv("JULA_BUCKET_URL", "gs://mock-bucket")
	t.Setenv("JULA_POLICY_URL", "policies/")
	t.Setenv("JULA_PUBLIC_KEY", "invalid-pem-key")
	args := []string{"jula", "--bucket-url", "gs://mock-bucket", "--policy-url", "policies/"}
	exitCode := runApp(args)
	if exitCode != 1 {
		t.Errorf("expected exit code 1 for invalid public key, got %d", exitCode)
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
		PayloadHash: evidenceHash,
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

	// 4b. Create fallback ERL file (no SCF prefix in path, is just filename in root of bucket)
	rawFindingDataFallback := []byte(`{"key": "value"}`)
	evidenceObjFallback := &types.Evidence{
		SCFID:    "",
		ErlID:    "E-BCM-16",
		SourceID: "src-2",
		Finding: types.Finding{
			SCFID:     "",
			ErlID:     "E-BCM-16",
			SourceID:  "src-2",
			Provider:  "gcp_cai",
			RawData:   rawFindingDataFallback,
			Timestamp: time.Now().UTC(),
			RunID:     "test-run-1",
		},
	}
	evidenceContentFallback, err := json.Marshal(evidenceObjFallback)
	if err != nil {
		t.Fatalf("failed to marshal fallback evidence: %v", err)
	}

	evidencePathFallback := "E-BCM-16_db_cai.json"
	fullEvidencePathFallback := filepath.Join(mockBucket, evidencePathFallback)
	if err := os.WriteFile(fullEvidencePathFallback, evidenceContentFallback, 0644); err != nil {
		t.Fatalf("failed to write fallback evidence file: %v", err)
	}
	evidenceHashFallback := pkgCrypto.HashFile(evidenceContentFallback)

	provFallback := &pkgCrypto.Provenance{
		ErlID:       "E-BCM-16",
		Provider:    "gcp_cai",
		SourceID:    "src-2",
		PayloadHash: evidenceHashFallback,
		Timestamp:   time.Now().UTC(),
	}
	if err := pkgCrypto.SignProvenance(provFallback, privKey); err != nil {
		t.Fatalf("failed to sign fallback provenance: %v", err)
	}
	provBytesFallback, err := json.Marshal(provFallback)
	if err != nil {
		t.Fatalf("failed to marshal fallback provenance: %v", err)
	}

	provPathFallback := "E-BCM-16_db_cai.prov.json"
	fullProvPathFallback := filepath.Join(mockBucket, provPathFallback)
	if err := os.WriteFile(fullProvPathFallback, provBytesFallback, 0644); err != nil {
		t.Fatalf("failed to write fallback provenance file: %v", err)
	}
	provHashFallback := pkgCrypto.HashFile(provBytesFallback)

	// 5. Create signed manifest file.
	manifest := &types.Manifest{
		RunID:     "test-run-1",
		Timestamp: time.Now().UTC(),
		Providers: []string{"gcp"},
		EvidenceFiles: []types.FileChecksum{
			{Path: evidencePath, SHA256: evidenceHash},
			{Path: provPath, SHA256: provHash},
			{Path: evidencePathFallback, SHA256: evidenceHashFallback},
			{Path: provPathFallback, SHA256: provHashFallback},
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
import data.control_mappings

default compliant = false
scf_id := "BCD-11.4"
customer_control_id := control_mappings[scf_id]

compliant if {
	db_checks := input.findings["databases"]
	every _, check in db_checks {
		check.normalized_data.instances[0].resource.data.settings.ipConfiguration.requireSsl == true
	}
}
`)
	if err := os.WriteFile(filepath.Join(mockPolicies, "gcp_db_encryption.rego"), policyContent, 0644); err != nil {
		t.Fatalf("failed to write policy file: %v", err)
	}

	policyContentFallback := []byte(`package compliance.scf.bcm_16
import rego.v1

default compliant = false
scf_id := "E-BCM-16"

compliant if {
	input.findings.generic["src-2"].normalized_data.data.key == "value"
}
`)
	if err := os.WriteFile(filepath.Join(mockPolicies, "gcp_bcm.rego"), policyContentFallback, 0644); err != nil {
		t.Fatalf("failed to write fallback policy file: %v", err)
	}

	// 7. Create control mappings.
	mappingsFile, err := os.CreateTemp("", "control-mappings-*.json")
	if err != nil {
		t.Fatalf("failed to create temp mappings file: %v", err)
	}
	defer os.Remove(mappingsFile.Name())
	mappingsFile.Write([]byte(`{"BCD-11.4": "CC-1"}`))
	mappingsFile.Close()

	// 8. Run runApp with these resources!
	args := []string{
		"jula",
		"--bucket-url", "file://" + mockBucket,
		"--policy-url", mockPolicies,
		"--mappings-path", mappingsFile.Name(),
	}

	exitCode := runApp(args)
	if exitCode != 0 {
		t.Errorf("expected exit code 0 (compliant audit), got %d", exitCode)
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

	// Test resolveErlIDFromPath
	erlTests := []struct {
		path     string
		expected string
	}{
		{"evidence/E-BCM-16/db_cai.json", "E-BCM-16"},
		{"E-BCM-16_db_cai.json", "E-BCM-16"},
		{"nested/folder/E-DCH-10_file.json", "E-DCH-10"},
		{"nested/E-TEST-01/file.json", "E-TEST-01"},
		{"no_erl_id/file.json", ""},
		{"E-BCM-16", "E-BCM-16"},
	}
	for _, tc := range erlTests {
		if got := resolveErlIDFromPath(tc.path); got != tc.expected {
			t.Errorf("resolveErlIDFromPath(%s) = %s, expected %s", tc.path, got, tc.expected)
		}
	}
}
