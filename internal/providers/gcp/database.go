package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/alibkaba/jula-evidence-collector/pkg/types"
)

// --- Extractor: Cloud SQL Configuration ---

// sqlInstancesListResponse represents the Cloud SQL instances listing response.
type sqlInstancesListResponse struct {
	Items []sqlInstance `json:"items"`
}

type sqlInstance struct {
	Name     string `json:"name"`
	Settings struct {
		BackupConfiguration struct {
			Enabled bool `json:"enabled"`
		} `json:"backupConfiguration"`
		IPConfiguration struct {
			IPv4Enabled bool `json:"ipv4Enabled"`
		} `json:"ipConfiguration"`
	} `json:"settings"`
}

// extractDatabase checks Cloud SQL instance configurations for backup and network security.
// Maps to generic functional name 'database' for cross-cloud taxonomy.
func (p *GCPProvider) extractDatabase(ctx context.Context, runID string) ([]types.Finding, error) {
	url := fmt.Sprintf(
		"https://sqladmin.googleapis.com/v1/projects/%s/instances",
		p.projectID,
	)

	body, err := p.doRequest(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("database list failed: %w", err)
	}

	var sqlList sqlInstancesListResponse
	if err := json.Unmarshal(body, &sqlList); err != nil {
		return nil, fmt.Errorf("parsing database instances: %w", err)
	}

	// If no database instances exist, emit a single PASS.
	if len(sqlList.Items) == 0 {
		return []types.Finding{{
			ID:          "gcp.database.secure_config",
			Provider:    "gcp",
			Resource:    "database",
			Check:       "secure_config",
			Status:      "PASS",
			RawPayload:  map[string]any{"detail": "no Cloud SQL instances found"},
			ResourceARN: fmt.Sprintf("projects/%s", p.projectID),
			Timestamp:   time.Now().UTC(),
			RunID:       runID,
		}}, nil
	}

	var findings []types.Finding
	for _, inst := range sqlList.Items {
		status := "PASS"
		var issues []string

		if p.policy.Policies.SQLRequireBackups && !inst.Settings.BackupConfiguration.Enabled {
			status = "FAIL"
			issues = append(issues, "automated backups disabled")
		}
		if p.policy.Policies.SQLRequirePrivateIP && inst.Settings.IPConfiguration.IPv4Enabled {
			status = "FAIL"
			issues = append(issues, "public IPv4 enabled")
		}

		if status == "FAIL" {
			if exc, ok := p.policy.IsExcepted("gcp.database.secure_config", inst.Name); ok {
				status = "EXCEPTION"
				issues = append(issues, fmt.Sprintf("exception: %s", exc.Reason))
			}
		}

		findings = append(findings, types.Finding{
			ID:       "gcp.database.secure_config",
			Provider: "gcp",
			Resource: "database",
			Check:    "secure_config",
			Status:   status,
			RawPayload: map[string]any{
				"instance": inst.Name,
				"issues":   issues,
			},
			ResourceARN: fmt.Sprintf("projects/%s/instances/%s", p.projectID, inst.Name),
			Timestamp:   time.Now().UTC(),
			RunID:       runID,
		})
	}

	return findings, nil
}
