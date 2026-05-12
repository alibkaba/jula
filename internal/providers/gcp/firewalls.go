package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/alibkaba/jula-evidence-collector/pkg/types"
)

// --- Extractor: Compute Engine Firewalls ---

// firewallsListResponse represents the Compute Engine firewall listing response.
type firewallsListResponse struct {
	Items []firewallRule `json:"items"`
}

type firewallRule struct {
	Name         string   `json:"name"`
	Direction    string   `json:"direction"`
	SourceRanges []string `json:"sourceRanges"`
	Allowed      []struct {
		IPProtocol string   `json:"IPProtocol"`
		Ports      []string `json:"ports"`
	} `json:"allowed"`
}

// extractComputeFirewalls checks for firewall rules that allow global ingress on prohibited ports.
// Maps to SOC 2 CC6.6 (Boundary Protection).
func (p *GCPProvider) extractComputeFirewalls(ctx context.Context, runID string) ([]types.Finding, error) {
	url := fmt.Sprintf(
		"https://compute.googleapis.com/compute/v1/projects/%s/global/firewalls",
		p.projectID,
	)

	body, err := p.doRequest(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("firewall list failed: %w", err)
	}

	var fwList firewallsListResponse
	if err := json.Unmarshal(body, &fwList); err != nil {
		return nil, fmt.Errorf("parsing firewall list: %w", err)
	}

	var findings []types.Finding
	for _, rule := range fwList.Items {
		if rule.Direction != "INGRESS" {
			continue
		}

		// Check if any source range is globally open.
		globalIngress := false
		for _, sr := range rule.SourceRanges {
			if sr == "0.0.0.0/0" {
				globalIngress = true
				break
			}
		}
		if !globalIngress {
			continue
		}

		// Check if any allowed port is prohibited.
		for _, allowed := range rule.Allowed {
			for _, portRange := range allowed.Ports {
				port := parsePort(portRange)
				if port == 0 || !p.policy.IsProhibitedPort(port) {
					continue
				}

				status := "FAIL"
				if exc, ok := p.policy.IsExcepted("gcp.compute.firewall_ingress", rule.Name); ok {
					status = "EXCEPTION"
					findings = append(findings, types.Finding{
						ID:       "gcp.compute.firewall_ingress",
						Provider: "gcp",
						Resource: "compute",
						Check:    "firewall_ingress",
						Status:   status,
						RawPayload: map[string]any{
							"rule_name":    rule.Name,
							"port":         port,
							"exception_id": exc.ID,
							"reason":       exc.Reason,
						},
						ResourceIdentifier: fmt.Sprintf("projects/%s/global/firewalls/%s", p.projectID, rule.Name),
						Timestamp:          time.Now().UTC(),
						RunID:              runID,
					})
				} else {
					findings = append(findings, types.Finding{
						ID:                 "gcp.compute.firewall_ingress",
						Provider:           "gcp",
						Resource:           "compute",
						Check:              "firewall_ingress",
						Status:             status,
						RawPayload:         toRawPayload(rule),
						ResourceIdentifier: fmt.Sprintf("projects/%s/global/firewalls/%s", p.projectID, rule.Name),
						Timestamp:          time.Now().UTC(),
						RunID:              runID,
					})
				}
			}
		}
	}

	// If no violations were found, emit a PASS.
	if len(findings) == 0 {
		findings = append(findings, types.Finding{
			ID:                 "gcp.compute.firewall_ingress",
			Provider:           "gcp",
			Resource:           "compute",
			Check:              "firewall_ingress",
			Status:             "PASS",
			ResourceIdentifier: fmt.Sprintf("projects/%s", p.projectID),
			Timestamp:          time.Now().UTC(),
			RunID:              runID,
		})
	}

	return findings, nil
}

// parsePort extracts the first port number from a port range string (e.g., "22", "8080-8090").
func parsePort(portRange string) int {
	var port int
	fmt.Sscanf(portRange, "%d", &port)
	return port
}
