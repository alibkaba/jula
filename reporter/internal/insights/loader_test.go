package insights

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/alibkaba/jula-core/pkg/crypto"
)

func TestVerifyVerdictSignature(t *testing.T) {
	// 1. Generate a real ECDSA key pair for testing
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	// 2. Marshal public key to PEM format
	pubASN1, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})

	// 3. Create and sign a valid verdict
	verdict := &crypto.Verdict{
		RunID:          "test-run",
		LedgerHash:     "sha256:abc",
		ControlsPassed: 1,
		ControlsFailed: 0,
		ControlsTotal:  1,
		Timestamp:      time.Now(),
	}

	if err := crypto.SignVerdict(verdict, privateKey); err != nil {
		t.Fatalf("failed to sign verdict: %v", err)
	}

	tests := []struct {
		name      string
		verdict   *crypto.Verdict
		pubKeyPEM string
		wantValid bool
		wantErr   bool
	}{
		{
			name:      "valid signature",
			verdict:   verdict,
			pubKeyPEM: string(pubPEM),
			wantValid: true,
			wantErr:   false,
		},
		{
			name:      "invalid public key format",
			verdict:   verdict,
			pubKeyPEM: "not a valid pem key",
			wantValid: false,
			wantErr:   true,
		},
		{
			name: "tampered verdict",
			verdict: &crypto.Verdict{
				RunID:          "tampered-run", // Changed RunID
				LedgerHash:     verdict.LedgerHash,
				ControlsPassed: verdict.ControlsPassed,
				ControlsFailed: verdict.ControlsFailed,
				ControlsTotal:  verdict.ControlsTotal,
				Timestamp:      verdict.Timestamp,
				Signature:      verdict.Signature, // Original signature
			},
			pubKeyPEM: string(pubPEM),
			wantValid: false,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, err := VerifyVerdictSignature(tt.verdict, tt.pubKeyPEM)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyVerdictSignature() error = %v, wantErr %v", err, tt.wantErr)
			}
			if valid != tt.wantValid {
				t.Errorf("VerifyVerdictSignature() valid = %v, wantValid %v", valid, tt.wantValid)
			}
		})
	}
}
