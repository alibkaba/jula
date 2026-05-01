package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/alibkaba/jula-evidence-collector/pkg/types"
)

// SignManifest computes the HMAC-SHA256 signature for a Manifest.
// The key MUST come from the JULA_SIGNING_KEY environment variable.
// The Signature field is excluded from the signing input by zeroing it first.
func SignManifest(manifest *types.Manifest, key []byte) error {
	if len(key) == 0 {
		return fmt.Errorf("signing key is empty")
	}

	// Zero the signature before computing so it is excluded from the hash.
	manifest.Signature = ""

	canonical, err := json.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("failed to marshal manifest: %w", err)
	}

	mac := hmac.New(sha256.New, key)
	mac.Write(canonical)
	manifest.Signature = hex.EncodeToString(mac.Sum(nil))

	return nil
}

// VerifyManifest verifies the HMAC-SHA256 signature of a Manifest.
func VerifyManifest(manifest *types.Manifest, key []byte) (bool, error) {
	if len(key) == 0 {
		return false, fmt.Errorf("signing key is empty")
	}

	originalSig := manifest.Signature
	manifest.Signature = ""

	canonical, err := json.Marshal(manifest)
	if err != nil {
		manifest.Signature = originalSig
		return false, fmt.Errorf("failed to marshal manifest: %w", err)
	}

	mac := hmac.New(sha256.New, key)
	mac.Write(canonical)
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	manifest.Signature = originalSig

	return hmac.Equal([]byte(originalSig), []byte(expectedSig)), nil
}

// HashFile computes the SHA-256 hash of a file's content.
func HashFile(content []byte) string {
	h := sha256.Sum256(content)
	return hex.EncodeToString(h[:])
}
