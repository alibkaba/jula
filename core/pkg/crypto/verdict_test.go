package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func testVerdict() *Verdict {
	return &Verdict{
		RunID:          "RUN-2026-06-18-001",
		LedgerHash:     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		ControlsPassed: 42,
		ControlsFailed: 3,
		ControlsTotal:  45,
		Timestamp:      time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC),
	}
}

func TestSignVerdict_Success(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	v := testVerdict()
	if err := SignVerdict(v, privKey); err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	if v.Signature == "" {
		t.Error("signature should not be empty")
	}
}

func TestVerifyVerdict_ValidSignature(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	v := testVerdict()
	if err := SignVerdict(v, privKey); err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	valid, err := VerifyVerdict(v, &privKey.PublicKey)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if !valid {
		t.Error("expected valid signature")
	}
}

func TestVerifyVerdict_TamperedControlCount(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	v := testVerdict()
	if err := SignVerdict(v, privKey); err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	// Tamper with the control count after signing.
	v.ControlsPassed = 45
	v.ControlsFailed = 0

	valid, err := VerifyVerdict(v, &privKey.PublicKey)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if valid {
		t.Error("expected invalid signature for tampered verdict (control count manipulation)")
	}
}

func TestVerifyVerdict_TamperedLedgerHash(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	v := testVerdict()
	if err := SignVerdict(v, privKey); err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	// Tamper with the ledger hash.
	v.LedgerHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	valid, err := VerifyVerdict(v, &privKey.PublicKey)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if valid {
		t.Error("expected invalid signature for tampered ledger hash")
	}
}

func TestVerifyVerdict_WrongKey(t *testing.T) {
	keyA, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyC, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	v := testVerdict()
	if err := SignVerdict(v, keyC); err != nil {
		t.Fatalf("sign with Key C failed: %v", err)
	}

	// Verify with Key A's public key (must fail).
	valid, err := VerifyVerdict(v, &keyA.PublicKey)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if valid {
		t.Error("expected invalid signature when verified with wrong key")
	}
}

func TestSignVerdict_NilSigner(t *testing.T) {
	v := testVerdict()
	err := SignVerdict(v, nil)
	if err == nil || err.Error() != "signer is nil" {
		t.Errorf("expected 'signer is nil' error, got %v", err)
	}
}

func TestSignVerdict_EmptyRunID(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	v := &Verdict{
		RunID:      "",
		LedgerHash: "abc123",
		Timestamp:  time.Now().UTC(),
	}
	err := SignVerdict(v, privKey)
	if err == nil || err.Error() != "run ID is empty" {
		t.Errorf("expected 'run ID is empty' error, got %v", err)
	}
}

func TestSignVerdict_EmptyLedgerHash(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	v := &Verdict{
		RunID:      "RUN-001",
		LedgerHash: "",
		Timestamp:  time.Now().UTC(),
	}
	err := SignVerdict(v, privKey)
	if err == nil || err.Error() != "ledger hash is empty" {
		t.Errorf("expected 'ledger hash is empty' error, got %v", err)
	}
}

func TestSignVerdict_SignerError(t *testing.T) {
	v := testVerdict()
	err := SignVerdict(v, errorSigner{})
	if err == nil || !strings.Contains(err.Error(), "failed to sign verdict") {
		t.Errorf("expected sign error, got: %v", err)
	}
}

func TestVerifyVerdict_Negative(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	tests := []struct {
		name      string
		verdict   *Verdict
		pubKey    *ecdsa.PublicKey
		wantErr   bool
		errString string
	}{
		{
			name: "Nil public key",
			verdict: &Verdict{
				RunID:     "RUN-001",
				Signature: "deadbeef",
			},
			pubKey:    nil,
			wantErr:   true,
			errString: "public key is nil",
		},
		{
			name: "Empty signature",
			verdict: &Verdict{
				RunID:     "RUN-001",
				Signature: "",
			},
			pubKey:    &privKey.PublicKey,
			wantErr:   true,
			errString: "signature is empty",
		},
		{
			name: "Malformed signature",
			verdict: &Verdict{
				RunID:     "RUN-001",
				Signature: "not-a-valid-hex-!@#",
			},
			pubKey:    &privKey.PublicKey,
			wantErr:   true,
			errString: "failed to decode signature",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := VerifyVerdict(tt.verdict, tt.pubKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyVerdict() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && err != nil && !strings.Contains(err.Error(), tt.errString) {
				t.Errorf("expected error containing %q, got: %v", tt.errString, err)
			}
		})
	}
}

func TestVerdictJSONMarshalErrors(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	invalidTime := time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)

	verdictSign := &Verdict{
		RunID:      "RUN-001",
		LedgerHash: "abc123",
		Timestamp:  invalidTime,
	}

	verdictVerify := &Verdict{
		RunID:      "RUN-001",
		LedgerHash: "abc123",
		Timestamp:  invalidTime,
		Signature:  "deadbeef",
	}

	tests := []struct {
		name      string
		operation func() error
		errString string
	}{
		{
			name: "SignVerdict Marshal Error",
			operation: func() error {
				return SignVerdict(verdictSign, privKey)
			},
			errString: "failed to marshal verdict",
		},
		{
			name: "VerifyVerdict Marshal Error",
			operation: func() error {
				_, err := VerifyVerdict(verdictVerify, &privKey.PublicKey)
				return err
			},
			errString: "failed to marshal verdict",
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
