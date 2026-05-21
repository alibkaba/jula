package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/alibkaba/jula-core/pkg/types"
)

func testManifest() *types.Manifest {
	return &types.Manifest{
		RunID:     "test-run-123",
		Timestamp: time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC),
		Providers: []string{"gcp"},

		EvidenceFiles: []types.FileChecksum{
			{Path: "soc2/CC2.1/gcp.audit_logging.enabled.json", SHA256: "abc123"},
		},
	}
}

func TestSignManifest_Success(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	m := testManifest()
	if err := SignManifest(m, privKey); err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	if m.Signature == "" {
		t.Error("signature should not be empty")
	}
}

func TestVerifyManifest_ValidSignature(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	m := testManifest()
	if err := SignManifest(m, privKey); err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	valid, err := VerifyManifest(m, &privKey.PublicKey)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if !valid {
		t.Error("expected valid signature")
	}
}

func TestVerifyManifest_TamperedManifest(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	m := testManifest()
	if err := SignManifest(m, privKey); err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	// Tamper with the manifest after signing.
	m.RunID = "tampered-run-id"

	valid, err := VerifyManifest(m, &privKey.PublicKey)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if valid {
		t.Error("expected invalid signature for tampered manifest")
	}
}

func TestVerifyManifest_WrongKey(t *testing.T) {
	privKey1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	privKey2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	m := testManifest()
	if err := SignManifest(m, privKey1); err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	valid, err := VerifyManifest(m, &privKey2.PublicKey)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if valid {
		t.Error("expected invalid signature when verified with wrong public key")
	}
}

func TestHashFile_ProducesCorrectSHA256(t *testing.T) {
	// Known input: "hello world" -> known SHA-256.
	input := []byte("hello world")
	expected := "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"

	got := HashFile(input)
	if got != expected {
		t.Errorf("SHA-256 mismatch\ngot:  %s\nwant: %s", got, expected)
	}
}

func TestSignManifest_NilKey(t *testing.T) {
	m := testManifest()
	err := SignManifest(m, nil)
	if err == nil {
		t.Error("expected error when signing with nil private key")
	}
}

func TestVerifyManifest_NilKey(t *testing.T) {
	m := testManifest()
	m.Signature = "deadbeef"

	_, err := VerifyManifest(m, nil)
	if err == nil {
		t.Error("expected error when verifying with nil public key")
	}
}

func TestVerifyManifest_EmptySignature(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	m := testManifest()
	m.Signature = ""

	_, err := VerifyManifest(m, &privKey.PublicKey)
	if err == nil {
		t.Error("expected error when signature is empty")
	}
}

func TestVerifyManifest_MalformedSignature(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	m := testManifest()
	m.Signature = "not-valid-hex-!@#$"

	_, err := VerifyManifest(m, &privKey.PublicKey)
	if err == nil {
		t.Error("expected error when signature is not valid hex")
	}
}

func TestSignManifest_Negative(t *testing.T) {
	manifest := &types.Manifest{RunID: "test-run"}

	err := SignManifest(manifest, nil)
	if err == nil || err.Error() != "signer is nil" {
		t.Errorf("expected 'signer is nil' error, got %v", err)
	}
}

func TestVerifyManifest_Negative(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubKey := &privKey.PublicKey
	manifest := &types.Manifest{RunID: "test-run"}

	// Test 1: Nil Public Key
	_, err := VerifyManifest(manifest, nil)
	if err == nil || err.Error() != "public key is nil" {
		t.Errorf("expected 'public key is nil' error, got %v", err)
	}

	// Test 2: Empty Signature
	manifest.Signature = ""
	_, err = VerifyManifest(manifest, pubKey)
	if err == nil || err.Error() != "signature is empty" {
		t.Errorf("expected 'signature is empty' error, got %v", err)
	}

	// Test 3: Invalid Hex Signature
	manifest.Signature = "not-a-hex-string"
	_, err = VerifyManifest(manifest, pubKey)
	if err == nil || !strings.Contains(err.Error(), "failed to decode signature") {
		t.Errorf("expected signature decode error, got %v", err)
	}
}

func TestProvenance_SignAndVerify(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	prov := &Provenance{
		ErlID:       "E-TEST-01",
		Provider:    "gcp_cai",
		SourceID:    "src-1",
		PayloadHash: "abc123hash",
		Timestamp:   time.Now().UTC(),
		ExtractionMetadata: map[string]string{
			"gcp_project_id": "test-project",
		},
	}

	if err := SignProvenance(prov, privKey); err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	if prov.Signature == "" {
		t.Error("signature should not be empty")
	}

	valid, err := VerifyProvenance(prov, &privKey.PublicKey)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if !valid {
		t.Error("expected valid signature")
	}

	// Tamper and verify
	prov.SourceID = "tampered"
	valid, err = VerifyProvenance(prov, &privKey.PublicKey)
	if err != nil {
		t.Fatalf("verify failed on tampered: %v", err)
	}
	if valid {
		t.Error("expected invalid signature on tampered provenance")
	}
}

func TestSignProvenance_Negative(t *testing.T) {
	prov := &Provenance{ErlID: "E-TEST-01"}
	err := SignProvenance(prov, nil)
	if err == nil || err.Error() != "signer is nil" {
		t.Errorf("expected 'signer is nil' error, got %v", err)
	}
}
