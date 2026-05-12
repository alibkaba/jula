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

	resourceARN := fmt.Sprintf("github:repo:%s:branch:main", p.repo)

	// 1. Check Classic Branch Protection
	urlBP := fmt.Sprintf("https://api.github.com/repos/%s/branches/main/protection", p.repo)
	reqBP, err := http.NewRequestWithContext(ctx, http.MethodGet, urlBP, nil)
	if err != nil {
		return nil, fmt.Errorf("github: creating request: %w", err)
	}
	reqBP.Header.Set("Authorization", "Bearer "+p.token)
	reqBP.Header.Set("Accept", "application/vnd.github.v3+json")

	var bpPayload map[string]any
	respBP, errBP := p.httpClient.Do(reqBP)
	if errBP != nil {
		return nil, fmt.Errorf("github: classic protection request failed: %w", errBP)
	}
	defer respBP.Body.Close()
	if respBP.StatusCode == http.StatusOK {
		body, _ := io.ReadAll(respBP.Body)
		if err := json.Unmarshal(body, &bpPayload); err != nil {
			return nil, fmt.Errorf("github: parsing classic protection: %w", err)
		}
	} else if respBP.StatusCode != http.StatusNotFound {
		return nil, fmt.Errorf("github: classic protection API returned %d", respBP.StatusCode)
	}

	// 2. Check Modern Rulesets
	urlRules := fmt.Sprintf("https://api.github.com/repos/%s/rules/branches/main", p.repo)
	reqRules, err := http.NewRequestWithContext(ctx, http.MethodGet, urlRules, nil)
	if err != nil {
		return nil, fmt.Errorf("github: creating rules request: %w", err)
	}
	reqRules.Header.Set("Authorization", "Bearer "+p.token)
	reqRules.Header.Set("Accept", "application/vnd.github+json")

	var rulesPayload []any
	respRules, errRules := p.httpClient.Do(reqRules)
	if errRules != nil {
		return nil, fmt.Errorf("github: rulesets request failed: %w", errRules)
	}
	defer respRules.Body.Close()
	if respRules.StatusCode == http.StatusOK {
		body, _ := io.ReadAll(respRules.Body)
		if err := json.Unmarshal(body, &rulesPayload); err != nil {
			return nil, fmt.Errorf("github: parsing rulesets: %w", err)
		}
	} else if respRules.StatusCode != http.StatusNotFound {
		return nil, fmt.Errorf("github: rulesets API returned %d", respRules.StatusCode)
	}

	// Evaluate results
	bpEnforced := false
	prEnforced := false
	combinedPayload := map[string]any{}

	if bpPayload != nil {
		bpEnforced = true
		combinedPayload["classic_protection"] = bpPayload
		if pr, ok := bpPayload["required_pull_request_reviews"].(map[string]any); ok && pr != nil {
			prEnforced = true
		}
	}

	if len(rulesPayload) > 0 {
		bpEnforced = true
		combinedPayload["rulesets"] = rulesPayload
		for _, r := range rulesPayload {
			if ruleMap, ok := r.(map[string]any); ok {
				if ruleMap["type"] == "pull_request" {
					prEnforced = true
				}
			}
		}
	}

	bpStatus := "FAIL"
	if bpEnforced {
		bpStatus = "PASS"
	} else {
		combinedPayload["detail"] = "Branch protection not found or not enabled on main"
	}

	prStatus := "FAIL"
	if prEnforced {
		prStatus = "PASS"
	} else if bpEnforced {
		combinedPayload["detail"] = "Branch protection found, but pull request reviews are not required"
	}

	findings = append(findings, types.Finding{
		ID:                 "github.branch_protection.enforced",
		Provider:           providerName,
		Resource:           "github_branch",
		Check:              "branch_protection",
		Status:             bpStatus,
		RawPayload:         combinedPayload,
		ResourceIdentifier: resourceARN,
		Timestamp:          time.Now().UTC(),
		RunID:              runID,
	})

	findings = append(findings, types.Finding{
		ID:                 "github.pull_requests.peer_reviewed",
		Provider:           providerName,
		Resource:           "github_branch",
		Check:              "pull_requests",
		Status:             prStatus,
		RawPayload:         combinedPayload,
		ResourceIdentifier: resourceARN,
		Timestamp:          time.Now().UTC(),
		RunID:              runID,
	})

	return findings, nil
}
