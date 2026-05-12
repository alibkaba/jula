package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/alibkaba/jula-evidence-collector/pkg/types"
)

// --- Extractor: Cloud Storage Encryption ---

// extractObjectStorageEncryption checks whether GCS buckets have encryption configured.
// Maps to generic functional name 'object_storage' for cross-cloud taxonomy.
func (p *GCPProvider) extractObjectStorageEncryption(ctx context.Context, runID string) ([]types.Finding, error) {
	url := fmt.Sprintf(
		"https://storage.googleapis.com/storage/v1/b?project=%s",
		p.projectID,
	)

	body, err := p.doRequest(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("object storage encryption check failed: %w", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("parsing bucket list: %w", err)
	}

	var findings []types.Finding
	items, ok := payload["items"].([]any)
	if !ok {
		return findings, nil
	}

	findings = make([]types.Finding, 0, len(items))
	for _, it := range items {
		bucket, ok := it.(map[string]any)
		if !ok {
			continue
		}

		name, _ := bucket["name"].(string)

		// GCS always encrypts data at rest by default (Google-managed keys).
		// A CMEK (Customer-Managed Encryption Key) is the stronger posture.
		status := "PASS"
		if encryption, ok := bucket["encryption"].(map[string]any); ok {
			if kmsKey, ok := encryption["defaultKmsKeyName"].(string); ok && kmsKey != "" {
				status = "PASS" // CMEK configured, strongest posture.
			}
		}

		findings = append(findings, types.Finding{
			ID:                 "gcp.object_storage.encryption_enabled",
			Provider:           "gcp",
			Resource:           "object_storage",
			Check:              "encryption_enabled",
			Status:             status,
			RawPayload:         toRawPayload(bucket),
			ResourceIdentifier: fmt.Sprintf("gs://%s", name),
			Timestamp:          time.Now().UTC(),
			RunID:              runID,
		})
	}

	return findings, nil
}
