package universal_rest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"testing"
)

func generateECPrivateKeyPEM() string {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(privKey)
	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	}
	return string(pem.EncodeToMemory(block))
}

func TestSignJWSFinancial(t *testing.T) {
	req, _ := http.NewRequest("POST", "https://example.com", nil)

	if err := SignJWSFinancial(req, nil); err == nil {
		t.Fatal("expected error with no key")
	}

	t.Setenv("JWS_PRIVATE_KEY", "invalid_pem")
	if err := SignJWSFinancial(req, nil); err == nil {
		t.Fatal("expected error with invalid PEM")
	}

	validPEM := generateECPrivateKeyPEM()
	t.Setenv("JWS_PRIVATE_KEY", validPEM)
	t.Setenv("JWS_KEY_ID", "key-123")

	err := SignJWSFinancial(req, []byte("payload"))
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	if req.Header.Get("X-JWS-Signature") == "" {
		t.Fatal("expected X-JWS-Signature to be set")
	}
}
