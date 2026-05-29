package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	pkgCrypto "github.com/alibkaba/jula-core/pkg/crypto"
	"github.com/alibkaba/jula-core/pkg/types"
)

func TestServeMux_Health(t *testing.T) {
	mux := newServeMux()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()

	mux.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	expected := "{\"status\":\"ok\"}\n"
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), expected)
	}
}

func TestServeMux_Run_MethodNotAllowed(t *testing.T) {
	mux := newServeMux()
	req := httptest.NewRequest(http.MethodGet, "/run", nil)
	rr := httptest.NewRecorder()

	mux.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusMethodNotAllowed {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusMethodNotAllowed)
	}
}

func TestHandleServe(t *testing.T) {
	os.Setenv("PORT", "0") // Port 0 binds to a random available port
	defer os.Unsetenv("PORT")

	errCh := make(chan error)
	go func() {
		errCh <- handleServe([]string{})
	}()
	
	time.Sleep(100 * time.Millisecond) // Give the server a moment to start
}

func TestServeMux_Run_Success(t *testing.T) {
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
		ControlID:    "BCD-11.4",
		EvidenceID:    "EVID-BCM-16",
		SourceID: "src-1",
		Finding: types.Finding{
			ControlID:     "BCD-11.4",
			EvidenceID:     "EVID-BCM-16",
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
		EvidenceID:       "EVID-BCM-16",
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

	// 7. Set Env Variables for the mux invocation
	t.Setenv("JULA_BUCKET_URL", "file://"+mockBucket)
	t.Setenv("JULA_POLICY_URL", mockPolicies)

	// 8. Invoke `/run`
	mux := newServeMux()
	req := httptest.NewRequest(http.MethodPost, "/run", nil)
	rr := httptest.NewRecorder()

	mux.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v. Body: %s",
			status, http.StatusOK, rr.Body.String())
	}
}
