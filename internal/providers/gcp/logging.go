package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/alibkaba/jula-evidence-collector/pkg/types"
)

// --- Extractor: Audit Logging ---

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

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("parsing audit config response: %w", err)
	}

	// Check if audit logging is configured for all services.
	status := "FAIL"
	if configs, ok := payload["auditConfigs"].([]any); ok {
		for _, c := range configs {
			cfg, ok := c.(map[string]any)
			if !ok {
				continue
			}

			service, _ := cfg["service"].(string)
			logConfigs, _ := cfg["auditLogConfigs"].([]any)

			if service == "allServices" && len(logConfigs) > 0 {
				status = "PASS"
				break
			}
		}
	}

	return []types.Finding{
		{
			ID:          "gcp.audit_logging.enabled",
			Provider:    "gcp",
			Resource:    "audit_logging",
			Check:       "enabled",
			Status:      status,
			RawPayload:  toRawPayload(payload),
			ResourceARN: fmt.Sprintf("projects/%s", p.projectID),
			Timestamp:   time.Now().UTC(),
			RunID:       runID,
		},
	}, nil
}
