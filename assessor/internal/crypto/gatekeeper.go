package crypto

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"

	eeCrypto "github.com/alibkaba/jula-core/pkg/crypto"
	"github.com/alibkaba/jula-core/pkg/types"
)

// ParseECDSAPublicKey delegates to the canonical implementation in jula-core.
func ParseECDSAPublicKey(pemStr string) (*ecdsa.PublicKey, error) {
	return eeCrypto.ParseECDSAPublicKey(pemStr)
}

// ParseECDSAPrivateKey delegates to the canonical implementation in jula-core.
func ParseECDSAPrivateKey(pemStr string) (*ecdsa.PrivateKey, error) {
	return eeCrypto.ParseECDSAPrivateKey(pemStr)
}


// VerifyManifestSignature leverages the native local crypto verification
// to validate the signature of the Manifest against the given public key.
func VerifyManifestSignature(manifest *types.Manifest, publicKey *ecdsa.PublicKey) error {
	ok, err := eeCrypto.VerifyManifest(manifest, publicKey)
	if err != nil {
		return fmt.Errorf("signature verification error: %w", err)
	}
	if !ok {
		return fmt.Errorf("manifest signature is cryptographically INVALID")
	}
	return nil
}

// VerifyPolicyBundle verifies the policy bundle signature against Key B's public key.
// This enforces that policy bundles are signed by the Governor's dedicated signing key
// and have not been tampered with during transit.
func VerifyPolicyBundle(bundle *eeCrypto.PolicyBundle, publicKey *ecdsa.PublicKey) error {
	ok, err := eeCrypto.VerifyBundle(bundle, publicKey)
	if err != nil {
		return fmt.Errorf("policy bundle signature verification error: %w", err)
	}
	if !ok {
		return fmt.Errorf("POLICY BUNDLE signature is cryptographically INVALID - refusing to load untrusted policies")
	}
	slog.Info("gatekeeper: policy bundle signature verified successfully against JULA_POLICY_PUBLIC_KEY")
	return nil
}

// VerifyPayloads strictly matches the Gatekeeper rule:
// Iterates through the given slice of file checksums, calculates their SHA-256 hash in memory,
// and ensures it matches the hash recorded in the manifest.
// If any file is missing or mismatched, it immediately aborts with a fatal tampering error.
func VerifyPayloads(files []types.FileChecksum, payloads map[string][]byte) error {
	slog.Info("gatekeeper: starting payload integrity check", "expected_files", len(files))

	for _, fileChecksum := range files {
		content, ok := payloads[fileChecksum.Path]
		if !ok {
			return fmt.Errorf("TAMPERING DETECTED: manifest file %q is missing from ingested payloads", fileChecksum.Path)
		}

		// Calculate SHA-256 hash of the ingested payload.
		hash := sha256.Sum256(content)
		calculatedHash := hex.EncodeToString(hash[:])

		if calculatedHash != fileChecksum.SHA256 {
			slog.Error("gatekeeper: hash mismatch detected",
				"file", fileChecksum.Path,
				"expected", fileChecksum.SHA256,
				"actual", calculatedHash,
			)
			return fmt.Errorf("TAMPERING DETECTED: file %q content hash does not match manifest checksum", fileChecksum.Path)
		}

		slog.Debug("gatekeeper: verified file hash", "file", fileChecksum.Path, "hash", calculatedHash)
	}

	slog.Info("gatekeeper: all ingested payloads successfully verified against manifest")
	return nil
}
