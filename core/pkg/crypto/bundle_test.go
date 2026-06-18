package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func testBundle() *PolicyBundle {
	return &PolicyBundle{
		BundleHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		Timestamp:  time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC),
	}
}

func TestSignBundle_Success(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	b := testBundle()
	if err := SignBundle(b, privKey); err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	if b.Signature == "" {
		t.Error("signature should not be empty")
	}
}

func TestVerifyBundle_ValidSignature(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	b := testBundle()
	if err := SignBundle(b, privKey); err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	valid, err := VerifyBundle(b, &privKey.PublicKey)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if !valid {
		t.Error("expected valid signature")
	}
}

func TestVerifyBundle_TamperedHash(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	b := testBundle()
	if err := SignBundle(b, privKey); err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	// Tamper with the bundle hash after signing.
	b.BundleHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	valid, err := VerifyBundle(b, &privKey.PublicKey)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if valid {
		t.Error("expected invalid signature for tampered bundle hash")
	}
}

func TestVerifyBundle_WrongKey_CryptographicSeparation(t *testing.T) {
	// This test enforces the core Zero Trust requirement: Key A and Key B
	// are distinct keys. A bundle signed with Key B must NOT verify with Key A's public key.
	keyA, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyB, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	b := testBundle()
	if err := SignBundle(b, keyB); err != nil {
		t.Fatalf("sign with Key B failed: %v", err)
	}

	// Verify with Key A's public key (should fail: cryptographic separation enforced).
	valid, err := VerifyBundle(b, &keyA.PublicKey)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if valid {
		t.Error("expected invalid signature when verified with Key A (cryptographic separation violated)")
	}
}

func TestSignBundle_NilSigner(t *testing.T) {
	b := testBundle()
	err := SignBundle(b, nil)
	if err == nil || err.Error() != "signer is nil" {
		t.Errorf("expected 'signer is nil' error, got %v", err)
	}
}

func TestSignBundle_EmptyHash(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b := &PolicyBundle{
		BundleHash: "",
		Timestamp:  time.Now().UTC(),
	}
	err := SignBundle(b, privKey)
	if err == nil || err.Error() != "bundle hash is empty" {
		t.Errorf("expected 'bundle hash is empty' error, got %v", err)
	}
}

func TestSignBundle_SignerError(t *testing.T) {
	b := testBundle()
	err := SignBundle(b, errorSigner{})
	if err == nil || !strings.Contains(err.Error(), "failed to sign bundle") {
		t.Errorf("expected sign error, got: %v", err)
	}
}

func TestVerifyBundle_Negative(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	tests := []struct {
		name      string
		bundle    *PolicyBundle
		pubKey    *ecdsa.PublicKey
		wantErr   bool
		errString string
	}{
		{
			name: "Nil public key",
			bundle: &PolicyBundle{
				BundleHash: "abc123",
				Signature:  "deadbeef",
			},
			pubKey:    nil,
			wantErr:   true,
			errString: "public key is nil",
		},
		{
			name: "Empty signature",
			bundle: &PolicyBundle{
				BundleHash: "abc123",
				Signature:  "",
			},
			pubKey:    &privKey.PublicKey,
			wantErr:   true,
			errString: "signature is empty",
		},
		{
			name: "Malformed signature",
			bundle: &PolicyBundle{
				BundleHash: "abc123",
				Signature:  "not-a-valid-hex-!@#",
			},
			pubKey:    &privKey.PublicKey,
			wantErr:   true,
			errString: "failed to decode signature",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := VerifyBundle(tt.bundle, tt.pubKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyBundle() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && err != nil && !strings.Contains(err.Error(), tt.errString) {
				t.Errorf("expected error containing %q, got: %v", tt.errString, err)
			}
		})
	}
}

func TestBundleJSONMarshalErrors(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	invalidTime := time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)

	bundleSign := &PolicyBundle{
		BundleHash: "abc123",
		Timestamp:  invalidTime,
	}

	bundleVerify := &PolicyBundle{
		BundleHash: "abc123",
		Timestamp:  invalidTime,
		Signature:  "deadbeef",
	}

	tests := []struct {
		name      string
		operation func() error
		errString string
	}{
		{
			name: "SignBundle Marshal Error",
			operation: func() error {
				return SignBundle(bundleSign, privKey)
			},
			errString: "failed to marshal bundle",
		},
		{
			name: "VerifyBundle Marshal Error",
			operation: func() error {
				_, err := VerifyBundle(bundleVerify, &privKey.PublicKey)
				return err
			},
			errString: "failed to marshal bundle",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.operation()
			if err == nil {
				t.Errorf("expected error containing %q, got nil", tt.errString)
			} else if !strings.Contains(err.Error(), tt.errString) {
				t.Errorf("expected error containing %q, got: %v", tt.errString, err)
			}
		})
	}
}
