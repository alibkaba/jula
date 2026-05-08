package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/alibkaba/jula-evidence-collector/internal/providers"
	"github.com/alibkaba/jula-evidence-collector/pkg/types"
)

const providerName = "github"

// Provider implements the providers.Provider interface for GitHub.
type Provider struct {
	token      string
	repo       string // Format: owner/repo
	httpClient *http.Client
}

func init() {
	providers.Register(&Provider{
		httpClient: &http.Client{Timeout: 15 * time.Second},
	})
}

// Name returns the provider identifier used in CLI flags and the registry.
func (p *Provider) Name() string {
	return providerName
}

// Validate checks that the necessary environment variables are set.
func (p *Provider) Validate() error {
	p.token = os.Getenv("GITHUB_TOKEN")
	if p.token == "" {
		return fmt.Errorf("github: GITHUB_TOKEN is required")
	}
	p.repo = os.Getenv("GITHUB_REPO")
	if p.repo == "" {
		return fmt.Errorf("github: GITHUB_REPO is required (e.g., owner/repo)")
	}
	return nil
}

// Extract makes calls to the GitHub API to check branch protection rules.
func (p *Provider) Extract(ctx context.Context, runID string) ([]types.Finding, error) {
	var findings []types.Finding

	url := fmt.Sprintf("https://api.github.com/repos/%s/branches/main/protection", p.repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("github: creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+p.token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github: request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var payload map[string]any

	resourceARN := fmt.Sprintf("github:repo:%s:branch:main", p.repo)

	if resp.StatusCode == http.StatusNotFound {
		// Branch protection is NOT enforced.
		findings = append(findings, types.Finding{
			ID:          "github.branch_protection.enforced",
			Provider:    providerName,
			Resource:    "github_branch",
			Check:       "branch_protection",
			Status:      "FAIL",
			RawPayload:  map[string]any{"detail": "Branch protection not found or not enabled on main"},
			ResourceARN: resourceARN,
			Timestamp:   time.Now().UTC(),
			RunID:       runID,
		})
		findings = append(findings, types.Finding{
			ID:          "github.pull_requests.peer_reviewed",
			Provider:    providerName,
			Resource:    "github_branch",
			Check:       "pull_requests",
			Status:      "FAIL",
			RawPayload:  map[string]any{"detail": "Branch protection not found, PRs not required"},
			ResourceARN: resourceARN,
			Timestamp:   time.Now().UTC(),
			RunID:       runID,
		})
		return findings, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github: API returned %d: %s", resp.StatusCode, string(body))
	}

	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("github: parsing response: %w", err)
	}

	// Branch protection is enabled
	findings = append(findings, types.Finding{
		ID:          "github.branch_protection.enforced",
		Provider:    providerName,
		Resource:    "github_branch",
		Check:       "branch_protection",
		Status:      "PASS",
		RawPayload:  payload,
		ResourceARN: resourceARN,
		Timestamp:   time.Now().UTC(),
		RunID:       runID,
	})

	// Check if required pull request reviews is enabled
	prStatus := "FAIL"
	if prReviews, ok := payload["required_pull_request_reviews"].(map[string]any); ok {
		if prReviews != nil {
			prStatus = "PASS"
		}
	}

	findings = append(findings, types.Finding{
		ID:          "github.pull_requests.peer_reviewed",
		Provider:    providerName,
		Resource:    "github_branch",
		Check:       "pull_requests",
		Status:      prStatus,
		RawPayload:  payload,
		ResourceARN: resourceARN,
		Timestamp:   time.Now().UTC(),
		RunID:       runID,
	})

	return findings, nil
}
