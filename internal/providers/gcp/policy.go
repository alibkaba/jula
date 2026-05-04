package gcp

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Policy represents the organization's GCP compliance policy configuration.
// It is loaded from configs/gcp_policy.json and drives all extractor thresholds.
type Policy struct {
	Provider   string         `json:"provider"`
	Version    string         `json:"version"`
	Policies   PolicySettings `json:"policies"`
	Exceptions []Exception    `json:"exceptions"`
}

// PolicySettings contains the configurable thresholds for GCP compliance checks.
type PolicySettings struct {
	KMSRotationMaxDays      int   `json:"kms_rotation_max_days"`
	FirewallProhibitedPorts []int `json:"firewall_prohibited_ports"`
	SQLRequirePrivateIP     bool  `json:"sql_require_private_ip"`
	SQLRequireBackups       bool  `json:"sql_require_backups"`
}

// Exception represents an approved deviation from a policy check.
// Exceptions are time-boxed and auditable.
type Exception struct {
	ID         string `json:"id"`
	FindingID  string `json:"finding_id"`
	Resource   string `json:"resource"`
	Reason     string `json:"reason"`
	ApprovedBy string `json:"approved_by"`
	Expires    string `json:"expires"` // RFC 3339 date string (e.g., "2026-12-31").
}

// LoadPolicy reads and parses a GCP policy configuration file.
func LoadPolicy(path string) (*Policy, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("reading policy file %s: %w", path, err)
	}

	var policy Policy
	if err := json.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("parsing policy file: %w", err)
	}

	if policy.Policies.KMSRotationMaxDays <= 0 {
		policy.Policies.KMSRotationMaxDays = 90 // Default to 90 days.
	}

	return &policy, nil
}

// IsExcepted checks whether a specific finding/resource pair has an active exception.
// Returns the exception and true if found and not expired, otherwise nil and false.
func (p *Policy) IsExcepted(findingID, resource string) (*Exception, bool) {
	now := time.Now().UTC()
	for i, exc := range p.Exceptions {
		if exc.FindingID != findingID {
			continue
		}
		// Match either by exact resource name or by wildcard (empty resource = all).
		if exc.Resource != "" && exc.Resource != resource {
			continue
		}

		// Check expiry.
		if exc.Expires != "" {
			expiresAt, err := time.Parse("2006-01-02", exc.Expires)
			if err != nil {
				continue // Skip malformed expiry dates.
			}
			if now.After(expiresAt) {
				continue // Exception has expired.
			}
		}

		return &p.Exceptions[i], true
	}

	return nil, false
}

// IsProhibitedPort checks whether a port number is in the prohibited list.
func (p *Policy) IsProhibitedPort(port int) bool {
	for _, prohibited := range p.Policies.FirewallProhibitedPorts {
		if port == prohibited {
			return true
		}
	}
	return false
}
