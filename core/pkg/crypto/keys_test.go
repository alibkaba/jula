package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
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

	// Test invalid PEM.
	_, err = ParseECDSAPublicKey("invalid-pem")
	if err == nil {
		t.Errorf("expected error for invalid PEM")
	}

	// Test non-ECDSA key type (RSA PEM block with garbage bytes).
	badBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: []byte("not-a-real-key"),
	})
	_, err = ParseECDSAPublicKey(string(badBlock))
	if err == nil {
		t.Errorf("expected error for non-ECDSA PEM content")
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
			parsedPriv, err := ParseECDSAPrivateKey(pemStr)

			if (err != nil) != tt.wantErr {
				t.Errorf("ParseECDSAPrivateKey() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr && parsedPriv == nil {
				t.Errorf("ParseECDSAPrivateKey() returned nil private key for valid input")
			}
		})
	}
}
