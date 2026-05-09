package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/alibkaba/jula-evidence-collector/pkg/types"
)

// --- Extractor: KMS Key Rotation ---

// kmsLocationsResponse represents the KMS locations listing.
type kmsLocationsResponse struct {
	Locations []struct {
		Name string `json:"name"`
	} `json:"locations"`
}

// kmsKeyRingsResponse represents the KMS key rings listing.
type kmsKeyRingsResponse struct {
	KeyRings []struct {
		Name string `json:"name"`
	} `json:"keyRings"`
}

// kmsCryptoKeysResponse represents the KMS crypto keys listing.
type kmsCryptoKeysResponse struct {
	CryptoKeys []kmsCryptoKey `json:"cryptoKeys"`
}

type kmsCryptoKey struct {
	Name           string `json:"name"`
	Purpose        string `json:"purpose"`
	RotationPeriod string `json:"rotationPeriod,omitempty"`
}

// extractKMSKeyRotation checks whether KMS crypto keys have rotation configured within policy limits.
// Maps to SOC 2 CC6.1 (Cryptographic Controls).
func (p *GCPProvider) extractKMSKeyRotation(ctx context.Context, runID string) ([]types.Finding, error) {
	maxRotationSeconds := int64(p.policy.Policies.KMSRotationMaxDays) * 86400

	// Step 1: List locations.
	locURL := fmt.Sprintf(
		"https://cloudkms.googleapis.com/v1/projects/%s/locations",
		p.projectID,
	)

	locBody, err := p.doRequest(ctx, locURL)
	if err != nil {
		return nil, fmt.Errorf("kms locations list failed: %w", err)
	}

	var locList kmsLocationsResponse
	if err := json.Unmarshal(locBody, &locList); err != nil {
		return nil, fmt.Errorf("parsing kms locations: %w", err)
	}

	var findings []types.Finding
	for _, loc := range locList.Locations {
		// Step 2: List key rings in each location.
		krURL := fmt.Sprintf(
			"https://cloudkms.googleapis.com/v1/%s/keyRings",
			loc.Name,
		)
		krBody, err := p.doRequest(ctx, krURL)
		if err != nil {
			continue // Skip locations we can't access.
		}

		var krList kmsKeyRingsResponse
		if err := json.Unmarshal(krBody, &krList); err != nil {
			continue
		}

		for _, kr := range krList.KeyRings {
			// Step 3: List crypto keys in each key ring.
			ckURL := fmt.Sprintf(
				"https://cloudkms.googleapis.com/v1/%s/cryptoKeys",
				kr.Name,
			)
			ckBody, err := p.doRequest(ctx, ckURL)
			if err != nil {
				continue
			}

			var ckList kmsCryptoKeysResponse
			if err := json.Unmarshal(ckBody, &ckList); err != nil {
				continue
			}

			for _, key := range ckList.CryptoKeys {
				// Only evaluate ENCRYPT_DECRYPT keys.
				if key.Purpose != "ENCRYPT_DECRYPT" {
					continue
				}

				status := "PASS"
				if key.RotationPeriod == "" {
					status = "FAIL"
				} else {
					var rotSeconds int64
					fmt.Sscanf(key.RotationPeriod, "%ds", &rotSeconds)
					if rotSeconds <= 0 || rotSeconds > maxRotationSeconds {
						status = "FAIL"
					}
				}

				if status == "FAIL" {
					if exc, ok := p.policy.IsExcepted("gcp.kms.key_rotation", key.Name); ok {
						status = "EXCEPTION"
						_ = exc
					}
				}

				findings = append(findings, types.Finding{
					ID:          "gcp.kms.key_rotation",
					Provider:    "gcp",
					Resource:    "kms",
					Check:       "key_rotation",
					Status:      status,
					RawPayload:  toRawPayload(key),
					ResourceARN: key.Name,
					Timestamp:   time.Now().UTC(),
					RunID:       runID,
				})
			}
		}
	}

	// If no KMS keys were found, emit a single PASS.
	if len(findings) == 0 {
		findings = append(findings, types.Finding{
			ID:          "gcp.kms.key_rotation",
			Provider:    "gcp",
			Resource:    "kms",
			Check:       "key_rotation",
			Status:      "PASS",
			RawPayload:  map[string]any{"detail": "no KMS crypto keys found"},
			ResourceARN: fmt.Sprintf("projects/%s", p.projectID),
			Timestamp:   time.Now().UTC(),
			RunID:       runID,
		})
	}

	return findings, nil
}
