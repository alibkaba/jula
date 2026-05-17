package crypto

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/alibkaba/jula-evidence-evaluator/pkg/types"
)

// SignManifest computes the ECDSA signature for a Manifest.
// The privateKey MUST come from a securely managed source.
// The Signature field is excluded from the signing input by zeroing it first.
func SignManifest(manifest *types.Manifest, privateKey *ecdsa.PrivateKey) error {
	if privateKey == nil {
		return fmt.Errorf("private key is nil")
	}

	// Zero the signature before computing so it is excluded from the hash.
	manifest.Signature = ""

	canonical, err := json.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("failed to marshal manifest: %w", err)
	}

	hash := sha256.Sum256(canonical)
	sigBytes, err := ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
	if err != nil {
		return fmt.Errorf("failed to sign manifest: %w", err)
	}

	manifest.Signature = hex.EncodeToString(sigBytes)

	return nil
}

// VerifyManifest verifies the ECDSA signature of a Manifest.
func VerifyManifest(manifest *types.Manifest, publicKey *ecdsa.PublicKey) (bool, error) {
	if publicKey == nil {
		return false, fmt.Errorf("public key is nil")
	}

	originalSig := manifest.Signature
	if originalSig == "" {
		return false, fmt.Errorf("signature is empty")
	}

	sigBytes, err := hex.DecodeString(originalSig)
	if err != nil {
		return false, fmt.Errorf("failed to decode signature: %w", err)
	}

	manifest.Signature = ""

	canonical, err := json.Marshal(manifest)
	if err != nil {
		manifest.Signature = originalSig
		return false, fmt.Errorf("failed to marshal manifest: %w", err)
	}

	hash := sha256.Sum256(canonical)
	manifest.Signature = originalSig

	return ecdsa.VerifyASN1(publicKey, hash[:], sigBytes), nil
}

// HashFile computes the SHA-256 hash of a file's content.
func HashFile(content []byte) string {
	h := sha256.Sum256(content)
	return hex.EncodeToString(h[:])
}
