package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/alibkaba/jula-evidence-collector/pkg/types"
)

// readBody reads and returns the full response body.
func readBody(resp *http.Response) ([]byte, error) {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}
	return body, nil
}

// --- Extractor: Audit Logging ---

// auditConfigResponse represents the GCP IAM policy audit config response.
type auditConfigResponse struct {
	AuditConfigs []struct {
		Service         string `json:"service"`
		AuditLogConfigs []struct {
			LogType string `json:"logType"`
		} `json:"auditLogConfigs"`
	} `json:"auditConfigs"`
}

// extractAuditLogging checks whether Cloud Audit Logging is enabled for the project.
// Maps to SOC 2 CC2.1 (Quality Information) and CC7.2 (Anomaly Detection).
func (p *GCPProvider) extractAuditLogging(ctx context.Context, runID string) ([]types.Finding, error) {
	url := fmt.Sprintf(
		"https://cloudresourcemanager.googleapis.com/v1/projects/%s:getIamPolicy",
		p.projectID,
	)

	// getIamPolicy requires POST with an empty body.
	token, err := p.tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("obtaining access token: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("audit logging request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := readBody(resp)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("audit logging API returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	var policy auditConfigResponse
	if err := json.Unmarshal(body, &policy); err != nil {
		return nil, fmt.Errorf("parsing audit config response: %w", err)
	}

	// Check if audit logging is configured for all services.
	status := "FAIL"
	for _, cfg := range policy.AuditConfigs {
		if cfg.Service == "allServices" && len(cfg.AuditLogConfigs) > 0 {
			status = "PASS"
			break
		}
	}

	return []types.Finding{
		{
			ID:          "gcp.audit_logging.enabled",
			Provider:    "gcp",
			Resource:    "audit_logging",
			Check:       "enabled",
			Status:      status,
			RawPayload:  toRawPayload(policy),
			ResourceARN: fmt.Sprintf("projects/%s", p.projectID),
			Timestamp:   time.Now().UTC(),
			RunID:       runID,
		},
	}, nil
}

// --- Extractor: Cloud Storage Encryption ---

// bucketsListResponse represents the GCS bucket listing response.
type bucketsListResponse struct {
	Items []struct {
		Name       string `json:"name"`
		Encryption *struct {
			DefaultKmsKeyName string `json:"defaultKmsKeyName"`
		} `json:"encryption,omitempty"`
	} `json:"items"`
}

// extractStorageEncryption checks whether GCS buckets have encryption configured.
// Maps to SOC 2 C1.1 (Confidential Data Protection).
func (p *GCPProvider) extractStorageEncryption(ctx context.Context, runID string) ([]types.Finding, error) {
	url := fmt.Sprintf(
		"https://storage.googleapis.com/storage/v1/b?project=%s",
		p.projectID,
	)

	body, err := p.doRequest(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("storage encryption check failed: %w", err)
	}

	var buckets bucketsListResponse
	if err := json.Unmarshal(body, &buckets); err != nil {
		return nil, fmt.Errorf("parsing bucket list: %w", err)
	}

	var findings []types.Finding
	for _, bucket := range buckets.Items {
		// GCS always encrypts data at rest by default (Google-managed keys).
		// A CMEK (Customer-Managed Encryption Key) is the stronger posture.
		status := "PASS"
		if bucket.Encryption != nil && bucket.Encryption.DefaultKmsKeyName != "" {
			status = "PASS" // CMEK configured, strongest posture.
		}

		findings = append(findings, types.Finding{
			ID:          "gcp.storage.encryption_enabled",
			Provider:    "gcp",
			Resource:    "storage",
			Check:       "encryption_enabled",
			Status:      status,
			RawPayload:  toRawPayload(bucket),
			ResourceARN: fmt.Sprintf("gs://%s", bucket.Name),
			Timestamp:   time.Now().UTC(),
			RunID:       runID,
		})
	}

	return findings, nil
}

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
		Name             string `json:"name"`
		ValidAfterTime   string `json:"validAfterTime"`
		ValidBeforeTime  string `json:"validBeforeTime"`
		KeyType          string `json:"keyType"`
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

// toRawPayload converts any struct to a map[string]any for storage in Finding.RawPayload.
func toRawPayload(v any) map[string]any {
	data, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		return nil
	}
	return result
}
