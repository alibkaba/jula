package crypto

import (
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// PolicyBundle represents a signed policy bundle manifest.
// The BundleHash is the SHA-256 of the entire policy tarball file (not individual files).
// Key B signs the bundle; the Evaluator verifies with Key B's public half.
type PolicyBundle struct {
	BundleHash string    `json:"bundle_hash"`
	Timestamp  time.Time `json:"timestamp"`
	Signature  string    `json:"signature"`
}

// SignBundle signs a PolicyBundle using the provided crypto.Signer (Key B).
// The Signature field is excluded from the signing input by zeroing it first.
func SignBundle(bundle *PolicyBundle, signer stdcrypto.Signer) error {
	if signer == nil {
		return fmt.Errorf("signer is nil")
	}

	if bundle.BundleHash == "" {
		return fmt.Errorf("bundle hash is empty")
	}

	// Zero the signature before computing so it is excluded from the hash.
	bundle.Signature = ""

	canonical, err := json.Marshal(bundle)
	if err != nil {
		return fmt.Errorf("failed to marshal bundle: %w", err)
	}

	hash := sha256.Sum256(canonical)
	sigBytes, err := signer.Sign(rand.Reader, hash[:], nil)
	if err != nil {
		return fmt.Errorf("failed to sign bundle: %w", err)
	}

	bundle.Signature = hex.EncodeToString(sigBytes)

	return nil
}

// VerifyBundle verifies the ECDSA signature of a PolicyBundle using Key B's public key.
func VerifyBundle(bundle *PolicyBundle, publicKey *ecdsa.PublicKey) (bool, error) {
	if publicKey == nil {
		return false, fmt.Errorf("public key is nil")
	}

	originalSig := bundle.Signature
	if originalSig == "" {
		return false, fmt.Errorf("signature is empty")
	}

	sigBytes, err := hex.DecodeString(originalSig)
	if err != nil {
		return false, fmt.Errorf("failed to decode signature: %w", err)
	}

	bundle.Signature = ""

	canonical, err := json.Marshal(bundle)
	if err != nil {
		bundle.Signature = originalSig
		return false, fmt.Errorf("failed to marshal bundle: %w", err)
	}

	hash := sha256.Sum256(canonical)
	bundle.Signature = originalSig

	return ecdsa.VerifyASN1(publicKey, hash[:], sigBytes), nil
}
