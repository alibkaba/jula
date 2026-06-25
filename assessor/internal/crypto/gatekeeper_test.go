package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	eeCrypto "github.com/alibkaba/jula-core/pkg/crypto"
	"github.com/alibkaba/jula-core/pkg/types"
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
	parsedPub, err := eeCrypto.ParseECDSAPublicKey(string(pemBlock))
	if err != nil {
		t.Fatalf("failed to parse public key PEM: %v", err)
	}

	if parsedPub.X.Cmp(priv.PublicKey.X) != 0 || parsedPub.Y.Cmp(priv.PublicKey.Y) != 0 {
		t.Errorf("parsed key does not match original key")
	}

	// Test invalid PEM
	_, err = eeCrypto.ParseECDSAPublicKey("invalid-pem")
	if err == nil {
		t.Errorf("expected error for invalid PEM")
	}

	// Test invalid PEM
	_, err = eeCrypto.ParseECDSAPublicKey("invalid-pem")
	if err == nil {
		t.Errorf("expected error for invalid PEM")
	}
}

func TestVerifyManifestSignatureAndPayloads(t *testing.T) {
	// 1. Generate keys.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// 2. Setup mock payload and hash it.
	fileName := "2026-05-17/evidence/EVID-BCM-16/gcp_cai_mock.json"
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
	if err := VerifyPayloads(manifest.EvidenceFiles, payloads); err != nil {
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
	if err := VerifyPayloads(manifest.EvidenceFiles, tamperedPayloads); err == nil {
		t.Error("expected gatekeeper hash mismatch error for tampered content, but got nil error")
	}

	// 8. Test payload verification failure (missing file).
	missingPayloads := map[string][]byte{}
	if err := VerifyPayloads(manifest.EvidenceFiles, missingPayloads); err == nil {
		t.Error("expected gatekeeper missing file error, but got nil error")
	}
}

func TestVerifyPolicyBundle_ValidSignature(t *testing.T) {
	keyB, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Key B: %v", err)
	}

	bundle := &eeCrypto.PolicyBundle{
		BundleHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		Timestamp:  time.Now().UTC(),
	}

	if err := eeCrypto.SignBundle(bundle, keyB); err != nil {
		t.Fatalf("failed to sign bundle: %v", err)
	}

	if err := VerifyPolicyBundle(bundle, &keyB.PublicKey); err != nil {
		t.Fatalf("expected successful policy bundle verification, got: %v", err)
	}
}

func TestVerifyPolicyBundle_TamperedHash(t *testing.T) {
	keyB, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Key B: %v", err)
	}

	bundle := &eeCrypto.PolicyBundle{
		BundleHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		Timestamp:  time.Now().UTC(),
	}

	if err := eeCrypto.SignBundle(bundle, keyB); err != nil {
		t.Fatalf("failed to sign bundle: %v", err)
	}

	// Tamper with the bundle hash after signing.
	bundle.BundleHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	if err := VerifyPolicyBundle(bundle, &keyB.PublicKey); err == nil {
		t.Error("expected policy bundle verification failure for tampered hash, but got nil error")
	}
}

func TestVerifyPolicyBundle_WrongKey_KeyAvsKeyB(t *testing.T) {
	// Core Zero Trust test: a bundle signed with Key B must NOT verify with Key A.
	keyA, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyB, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	bundle := &eeCrypto.PolicyBundle{
		BundleHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		Timestamp:  time.Now().UTC(),
	}

	if err := eeCrypto.SignBundle(bundle, keyB); err != nil {
		t.Fatalf("failed to sign bundle with Key B: %v", err)
	}

	// Verify with Key A's public key (must fail).
	if err := VerifyPolicyBundle(bundle, &keyA.PublicKey); err == nil {
		t.Error("expected verification failure when using Key A to verify Key B's signature (cryptographic separation violated)")
	}
}

func TestVerifyPolicyBundle_EmptySignature(t *testing.T) {
	keyB, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	bundle := &eeCrypto.PolicyBundle{
		BundleHash: "abc123",
		Signature:  "",
	}

	if err := VerifyPolicyBundle(bundle, &keyB.PublicKey); err == nil {
		t.Error("expected error for empty signature")
	}
}

func TestVerifyPolicyBundle_NilKey(t *testing.T) {
	bundle := &eeCrypto.PolicyBundle{
		BundleHash: "abc123",
		Signature:  "deadbeef",
	}

	if err := VerifyPolicyBundle(bundle, nil); err == nil {
		t.Error("expected error for nil public key")
	}
}

func TestParseECDSAPrivateKey(t *testing.T) {
	// Generate a dummy ECDSA key.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	tests := []struct {
		name    string
		setup   func() string
		wantErr bool
	}{
		{
			name: "valid SEC1 private key",
			setup: func() string {
				privBytes, err := x509.MarshalECPrivateKey(priv)
				if err != nil {
					t.Fatalf("failed to marshal private key: %v", err)
				}
				pemBlock := pem.EncodeToMemory(&pem.Block{
					Type:  "EC PRIVATE KEY",
					Bytes: privBytes,
				})
				return string(pemBlock)
			},
			wantErr: false,
		},
		{
			name: "valid PKCS8 private key",
			setup: func() string {
				privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
				if err != nil {
					t.Fatalf("failed to marshal private key: %v", err)
				}
				pemBlock := pem.EncodeToMemory(&pem.Block{
					Type:  "PRIVATE KEY",
					Bytes: privBytes,
				})
				return string(pemBlock)
			},
			wantErr: false,
		},
		{
			name: "invalid PEM format",
			setup: func() string {
				return "invalid-pem"
			},
			wantErr: true,
		},
		{
			name: "invalid private key bytes",
			setup: func() string {
				pemBlock := pem.EncodeToMemory(&pem.Block{
					Type:  "PRIVATE KEY",
					Bytes: []byte("invalid-bytes"),
				})
				return string(pemBlock)
			},
			wantErr: true,
		},
		{
			name: "PKCS8 key is not ECDSA",
			setup: func() string {
				// PKCS8 wrapper for an ed25519 key (OID 1.3.101.112), not ECDSA.
				return "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIBEBIwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g\n-----END PRIVATE KEY-----\n"
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pemStr := tt.setup()
			parsedPriv, err := eeCrypto.ParseECDSAPrivateKey(pemStr)

			if (err != nil) != tt.wantErr {
				t.Errorf("ParseECDSAPrivateKey() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr && parsedPriv == nil {
				t.Errorf("ParseECDSAPrivateKey() returned nil private key for valid input")
			}
		})
	}
}
