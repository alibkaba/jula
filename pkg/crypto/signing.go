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

	"github.com/alibkaba/jula-core/pkg/types"
)

// SignManifest computes the signature for a Manifest using a standard crypto.Signer.
// The Signer MUST come from a securely managed source.
// The Signature field is excluded from the signing input by zeroing it first.
func SignManifest(manifest *types.Manifest, signer stdcrypto.Signer) error {
	if signer == nil {
		return fmt.Errorf("signer is nil")
	}

	// Zero the signature before computing so it is excluded from the hash.
	manifest.Signature = ""

	canonical, err := json.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("failed to marshal manifest: %w", err)
	}

	hash := sha256.Sum256(canonical)
	sigBytes, err := signer.Sign(rand.Reader, hash[:], nil)
	if err != nil {
		return fmt.Errorf("failed to sign manifest: %w", err)
	}

	manifest.Signature = hex.EncodeToString(sigBytes)

	return nil
}

// VerifyManifest verifies the ECDSA signature of a Manifest.
func VerifyManifest(manifest *types.Manifest, publicKey *ecdsa.PublicKey) (bool, error) {
	if manifest == nil {
		return false, fmt.Errorf("manifest is nil")
	}
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

// Provenance represents metadata about the evidence extraction.
type Provenance struct {
	ErlID              string            `json:"erl_id"`
	Provider           string            `json:"provider"`
	SourceID           string            `json:"source_id"`
	PayloadHash        string            `json:"payload_hash"`
	Timestamp          time.Time         `json:"timestamp"`
	ExtractionMetadata map[string]string `json:"extraction_metadata"`
	Signature          string            `json:"signature"`
}

// SignProvenance signs the provenance metadata.
func SignProvenance(prov *Provenance, signer stdcrypto.Signer) error {
	if signer == nil {
		return fmt.Errorf("signer is nil")
	}
	prov.Signature = ""
	canonical, err := json.Marshal(prov)
	if err != nil {
		return fmt.Errorf("failed to marshal provenance: %w", err)
	}
	hash := sha256.Sum256(canonical)
	sigBytes, err := signer.Sign(rand.Reader, hash[:], nil)
	if err != nil {
		return fmt.Errorf("failed to sign provenance: %w", err)
	}
	prov.Signature = hex.EncodeToString(sigBytes)
	return nil
}

// VerifyProvenance verifies the ECDSA signature of a Provenance object.
func VerifyProvenance(prov *Provenance, publicKey *ecdsa.PublicKey) (bool, error) {
	if publicKey == nil {
		return false, fmt.Errorf("public key is nil")
	}

	originalSig := prov.Signature
	if originalSig == "" {
		return false, fmt.Errorf("signature is empty")
	}

	sigBytes, err := hex.DecodeString(originalSig)
	if err != nil {
		return false, fmt.Errorf("failed to decode signature: %w", err)
	}

	prov.Signature = ""

	canonical, err := json.Marshal(prov)
	if err != nil {
		prov.Signature = originalSig
		return false, fmt.Errorf("failed to marshal provenance: %w", err)
	}

	hash := sha256.Sum256(canonical)
	prov.Signature = originalSig

	return ecdsa.VerifyASN1(publicKey, hash[:], sigBytes), nil
}
