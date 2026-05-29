package crypto

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log/slog"

	eeCrypto "github.com/alibkaba/jula-core/pkg/crypto"
	"github.com/alibkaba/jula-core/pkg/types"
)

// ParseECDSAPublicKey parses an ECDSA Public Key from a PEM-encoded string block.
func ParseECDSAPublicKey(pemStr string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKIX public key: %w", err)
	}

	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("parsed key is not of type ECDSA public key")
	}

	return ecdsaPub, nil
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
