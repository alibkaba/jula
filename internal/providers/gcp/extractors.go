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

// --- Extractor: Cloud Storage Encryption ---

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

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("parsing bucket list: %w", err)
	}

	var findings []types.Finding
	if items, ok := payload["items"].([]any); ok {
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
				ID:          "gcp.storage.encryption_enabled",
				Provider:    "gcp",
				Resource:    "storage",
				Check:       "encryption_enabled",
				Status:      status,
				RawPayload:  toRawPayload(bucket),
				ResourceARN: fmt.Sprintf("gs://%s", name),
				Timestamp:   time.Now().UTC(),
				RunID:       runID,
			})
		}
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
						ResourceARN: fmt.Sprintf("projects/%s/global/firewalls/%s", p.projectID, rule.Name),
						Timestamp:   time.Now().UTC(),
						RunID:       runID,
					})
				} else {
					findings = append(findings, types.Finding{
						ID:          "gcp.compute.firewall_ingress",
						Provider:    "gcp",
						Resource:    "compute",
						Check:       "firewall_ingress",
						Status:      status,
						RawPayload:  toRawPayload(rule),
						ResourceARN: fmt.Sprintf("projects/%s/global/firewalls/%s", p.projectID, rule.Name),
						Timestamp:   time.Now().UTC(),
						RunID:       runID,
					})
				}
			}
		}
	}

	// If no violations were found, emit a PASS.
	if len(findings) == 0 {
		findings = append(findings, types.Finding{
			ID:          "gcp.compute.firewall_ingress",
			Provider:    "gcp",
			Resource:    "compute",
			Check:       "firewall_ingress",
			Status:      "PASS",
			ResourceARN: fmt.Sprintf("projects/%s", p.projectID),
			Timestamp:   time.Now().UTC(),
			RunID:       runID,
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

// extractCloudSQL checks Cloud SQL instance configurations for backup and network security.
// Maps to SOC 2 CC6.1 (Logical Access Security) and A1.2 (System Recovery).
func (p *GCPProvider) extractCloudSQL(ctx context.Context, runID string) ([]types.Finding, error) {
	url := fmt.Sprintf(
		"https://sqladmin.googleapis.com/v1/projects/%s/instances",
		p.projectID,
	)

	body, err := p.doRequest(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("cloud sql list failed: %w", err)
	}

	var sqlList sqlInstancesListResponse
	if err := json.Unmarshal(body, &sqlList); err != nil {
		return nil, fmt.Errorf("parsing sql instances: %w", err)
	}

	// If no SQL instances exist, emit a single PASS.
	if len(sqlList.Items) == 0 {
		return []types.Finding{{
			ID:          "gcp.sql.secure_config",
			Provider:    "gcp",
			Resource:    "sql",
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
			if exc, ok := p.policy.IsExcepted("gcp.sql.secure_config", inst.Name); ok {
				status = "EXCEPTION"
				issues = append(issues, fmt.Sprintf("exception: %s", exc.Reason))
			}
		}

		findings = append(findings, types.Finding{
			ID:       "gcp.sql.secure_config",
			Provider: "gcp",
			Resource: "sql",
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

