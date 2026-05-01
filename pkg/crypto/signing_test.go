package crypto

import (
	"testing"
	"time"

	"github.com/alibkaba/jula-evidence-collector/pkg/types"
)

func testManifest() *types.Manifest {
	return &types.Manifest{
		RunID:      "test-run-123",
		Timestamp:  time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC),
		Providers:  []string{"gcp"},
		Frameworks: []string{"soc2"},
		EvidenceFiles: []types.FileChecksum{
			{Path: "soc2/CC2.1/gcp.audit_logging.enabled.json", SHA256: "abc123"},
		},
	}
}

func TestSignManifest_ProducesConsistentSignature(t *testing.T) {
	key := []byte("test-signing-key")

	m1 := testManifest()
	m2 := testManifest()

	if err := SignManifest(m1, key); err != nil {
		t.Fatalf("sign failed: %v", err)
	}
	if err := SignManifest(m2, key); err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	if m1.Signature != m2.Signature {
		t.Errorf("same manifest + same key should produce same signature\ngot: %s\nwant: %s", m1.Signature, m2.Signature)
	}

	if m1.Signature == "" {
		t.Error("signature should not be empty")
	}
}

func TestSignManifest_DifferentKeysProduceDifferentSignatures(t *testing.T) {
	m1 := testManifest()
	m2 := testManifest()

	if err := SignManifest(m1, []byte("key-one")); err != nil {
		t.Fatalf("sign failed: %v", err)
	}
	if err := SignManifest(m2, []byte("key-two")); err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	if m1.Signature == m2.Signature {
		t.Error("different keys should produce different signatures")
	}
}

func TestSignManifest_EmptyKeyReturnsError(t *testing.T) {
	m := testManifest()
	if err := SignManifest(m, []byte{}); err == nil {
		t.Fatal("expected error for empty key")
	}
}

func TestVerifyManifest_ValidSignature(t *testing.T) {
	key := []byte("test-signing-key")
	m := testManifest()

	if err := SignManifest(m, key); err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	valid, err := VerifyManifest(m, key)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if !valid {
		t.Error("expected valid signature")
	}
}

func TestVerifyManifest_TamperedManifest(t *testing.T) {
	key := []byte("test-signing-key")
	m := testManifest()

	if err := SignManifest(m, key); err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	// Tamper with the manifest after signing.
	m.RunID = "tampered-run-id"

	valid, err := VerifyManifest(m, key)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if valid {
		t.Error("expected invalid signature for tampered manifest")
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
