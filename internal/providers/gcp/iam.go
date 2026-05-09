package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/alibkaba/jula-evidence-collector/pkg/types"
)

// --- Extractor: IAM Service Account Key Age ---

// serviceAccountsListResponse represents the IAM service accounts listing.
type serviceAccountsListResponse struct {
	Accounts []struct {
		Email    string `json:"email"`
		UniqueID string `json:"uniqueId"`
	} `json:"accounts"`
}

// serviceAccountKeysResponse represents the keys for a single service account.
type serviceAccountKeysResponse struct {
	Keys []struct {
		Name            string `json:"name"`
		ValidAfterTime  string `json:"validAfterTime"`
		ValidBeforeTime string `json:"validBeforeTime"`
		KeyType         string `json:"keyType"`
	} `json:"keys"`
}

// extractServiceAccountKeys checks for user-managed service account keys
// that are older than 90 days. Maps to SOC 2 CC6.1 (Logical Access Security).
func (p *GCPProvider) extractServiceAccountKeys(ctx context.Context, runID string) ([]types.Finding, error) {
	listURL := fmt.Sprintf(
		"https://iam.googleapis.com/v1/projects/%s/serviceAccounts",
		p.projectID,
	)

	body, err := p.doRequest(ctx, listURL)
	if err != nil {
		return nil, fmt.Errorf("service account list failed: %w", err)
	}

	var saList serviceAccountsListResponse
	if err := json.Unmarshal(body, &saList); err != nil {
		return nil, fmt.Errorf("parsing service account list: %w", err)
	}

	var findings []types.Finding
	for _, sa := range saList.Accounts {
		keysURL := fmt.Sprintf(
			"https://iam.googleapis.com/v1/projects/%s/serviceAccounts/%s/keys",
			p.projectID, sa.Email,
		)

		keysBody, err := p.doRequest(ctx, keysURL)
		if err != nil {
			return nil, fmt.Errorf("listing keys for %s: %w", sa.Email, err)
		}

		var keysResp serviceAccountKeysResponse
		if err := json.Unmarshal(keysBody, &keysResp); err != nil {
			return nil, fmt.Errorf("parsing keys for %s: %w", sa.Email, err)
		}

		for _, key := range keysResp.Keys {
			// Only evaluate user-managed keys, not system-managed.
			if key.KeyType != "USER_MANAGED" {
				continue
			}

			createdAt, err := time.Parse(time.RFC3339, key.ValidAfterTime)
			if err != nil {
				continue
			}

			status := "PASS"
			if time.Since(createdAt) > 90*24*time.Hour {
				status = "FAIL" // Key older than 90 days.
			}

			findings = append(findings, types.Finding{
				ID:          "gcp.iam.service_account_key_rotation",
				Provider:    "gcp",
				Resource:    "iam",
				Check:       "service_account_key_rotation",
				Status:      status,
				RawPayload:  toRawPayload(key),
				ResourceARN: key.Name,
				Timestamp:   time.Now().UTC(),
				RunID:       runID,
			})
		}
	}

	return findings, nil
}
