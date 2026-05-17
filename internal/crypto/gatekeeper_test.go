package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	eeCrypto "github.com/alibkaba/jula-evidence-evaluator/pkg/crypto"
	"github.com/alibkaba/jula-evidence-evaluator/pkg/types"
)

func TestParseECDSAPublicKey(t *testing.T) {
	// Generate a dummy ECDSA key.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}

	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})

	// Parse the PEM back.
	parsedPub, err := ParseECDSAPublicKey(string(pemBlock))
	if err != nil {
		t.Fatalf("failed to parse public key PEM: %v", err)
	}

	if parsedPub.X.Cmp(priv.PublicKey.X) != 0 || parsedPub.Y.Cmp(priv.PublicKey.Y) != 0 {
		t.Errorf("parsed key does not match original key")
	}
}

func TestVerifyManifestSignatureAndPayloads(t *testing.T) {
	// 1. Generate keys.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// 2. Setup mock payload and hash it.
	fileName := "2026-05-17/evidence/E-BCM-16/gcp_cai_mock.json"
	fileContent := []byte(`{"status": "compliant"}`)
	fileHash := eeCrypto.HashFile(fileContent)

	manifest := &types.Manifest{
		RunID:     "test-run-id",
		Timestamp: time.Now().UTC(),
		Providers: []string{"gcp_cai"},
		EvidenceFiles: []types.FileChecksum{
			{
				Path:   fileName,
				SHA256: fileHash,
			},
		},
	}

	// 3. Sign the manifest using the native local crypto package.
	if err := eeCrypto.SignManifest(manifest, priv); err != nil {
		t.Fatalf("failed to sign manifest: %v", err)
	}

	// 4. Test gatekeeper signature verification.
	if err := VerifyManifestSignature(manifest, &priv.PublicKey); err != nil {
		t.Fatalf("expected successful signature verification, got: %v", err)
	}

	// 5. Test payload verification (valid scenario).
	payloads := map[string][]byte{
		fileName: fileContent,
	}
	if err := VerifyPayloads(manifest, payloads); err != nil {
		t.Errorf("expected successful payload verification, got: %v", err)
	}

	// 6. Test signature validation failure with incorrect key.
	wrongPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := VerifyManifestSignature(manifest, &wrongPriv.PublicKey); err == nil {
		t.Error("expected signature verification failure with incorrect public key, but got nil error")
	}

	// 7. Test payload verification failure (tampering: changed content).
	tamperedPayloads := map[string][]byte{
		fileName: []byte(`{"status": "NON-COMPLIANT"}`),
	}
	if err := VerifyPayloads(manifest, tamperedPayloads); err == nil {
		t.Error("expected gatekeeper hash mismatch error for tampered content, but got nil error")
	}

	// 8. Test payload verification failure (missing file).
	missingPayloads := map[string][]byte{}
	if err := VerifyPayloads(manifest, missingPayloads); err == nil {
		t.Error("expected gatekeeper missing file error, but got nil error")
	}
}
