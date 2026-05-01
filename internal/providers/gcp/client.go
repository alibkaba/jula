package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/alibkaba/jula-evidence-collector/internal/providers"
	"github.com/alibkaba/jula-evidence-collector/pkg/types"
)

// GCPProvider implements the Provider interface for Google Cloud Platform.
type GCPProvider struct {
	projectID   string
	tokenSource *tokenSource
	httpClient  *http.Client
	// baseURL allows overriding API endpoints for testing.
	baseURL string
}

func init() {
	providers.Register(&GCPProvider{})
}

// Name returns the provider identifier.
func (p *GCPProvider) Name() string {
	return "gcp"
}

// Validate ensures all required GCP environment variables are present
// and initializes the authenticated HTTP client.
// Supports two authentication modes:
//   1. Service account JSON key file (JULA_GCP_CREDENTIALS_JSON) for local dev.
//   2. GCP metadata server (Application Default Credentials) for Cloud Run.
func (p *GCPProvider) Validate() error {
	p.projectID = os.Getenv("JULA_GCP_PROJECT_ID")
	if p.projectID == "" {
		return fmt.Errorf("JULA_GCP_PROJECT_ID is required")
	}

	if p.httpClient == nil {
		p.httpClient = &http.Client{}
	}

	credsPath := os.Getenv("JULA_GCP_CREDENTIALS_JSON")
	if credsPath != "" {
		// Mode 1: Explicit JSON key file (local development).
		credsData, err := os.ReadFile(credsPath)
		if err != nil {
			return fmt.Errorf("reading credentials file: %w", err)
		}

		var key serviceAccountKey
		if err := json.Unmarshal(credsData, &key); err != nil {
			return fmt.Errorf("parsing credentials JSON: %w", err)
		}

		ts, err := newTokenSource(&key, p.httpClient)
		if err != nil {
			return fmt.Errorf("initializing token source: %w", err)
		}
		p.tokenSource = ts
	} else {
		// Mode 2: GCP metadata server / Application Default Credentials (Cloud Run).
		p.tokenSource = newMetadataTokenSource(p.httpClient)
	}

	if p.baseURL == "" {
		p.baseURL = "https://compute.googleapis.com"
	}

	return nil
}

// Extract runs all GCP compliance checks and returns aggregated findings.
func (p *GCPProvider) Extract(ctx context.Context, runID string) ([]types.Finding, error) {
	var allFindings []types.Finding

	// Each extractor function returns a slice of findings for a specific check.
	extractors := []struct {
		name string
		fn   func(ctx context.Context, runID string) ([]types.Finding, error)
	}{
		{"audit_logging", p.extractAuditLogging},
		{"storage_encryption", p.extractStorageEncryption},
		{"iam_service_account_keys", p.extractServiceAccountKeys},
	}

	for _, ext := range extractors {
		select {
		case <-ctx.Done():
			return allFindings, fmt.Errorf("context cancelled during %s: %w", ext.name, ctx.Err())
		default:
		}

		findings, err := ext.fn(ctx, runID)
		if err != nil {
			return allFindings, fmt.Errorf("extractor %s failed: %w", ext.name, err)
		}
		allFindings = append(allFindings, findings...)
	}

	return allFindings, nil
}

// doRequest executes an authenticated GET request against a GCP API endpoint.
func (p *GCPProvider) doRequest(ctx context.Context, url string) ([]byte, error) {
	token, err := p.tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("obtaining access token: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	body, err := readBody(resp)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}
