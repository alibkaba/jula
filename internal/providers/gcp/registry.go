package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/alibkaba/jula-evidence-collector/pkg/types"
)

// --- Extractor: Artifact Registry Vulnerabilities ---

type repositoryListResponse struct {
	Repositories []struct {
		Name string `json:"name"`
	} `json:"repositories"`
}

type dockerImageListResponse struct {
	DockerImages []struct {
		Name string `json:"name"`
		URI  string `json:"uri"`
	} `json:"dockerImages"`
}

type occurrenceListResponse struct {
	Occurrences []struct {
		Name          string `json:"name"`
		Vulnerability struct {
			EffectiveSeverity string `json:"effectiveSeverity"`
			ShortDescription  string `json:"shortDescription"`
		} `json:"vulnerability"`
	} `json:"occurrences"`
}

// extractRegistry checks for image vulnerabilities in Artifact Registry.
// Maps to generic functional name 'registry' for cross-cloud taxonomy.
func (p *GCPProvider) extractRegistry(ctx context.Context, runID string) ([]types.Finding, error) {
	threshold := os.Getenv("JULA_GCP_REGISTRY_FAIL_THRESHOLD")
	if threshold == "" {
		threshold = "HIGH"
	}

	// 1. List Repositories across all locations
	reposURL := fmt.Sprintf(
		"https://artifactregistry.googleapis.com/v1/projects/%s/locations/-/repositories",
		p.projectID,
	)
	
	body, err := p.doRequest(ctx, reposURL)
	if err != nil {
		return nil, fmt.Errorf("listing artifact repositories: %w", err)
	}

	var repoList repositoryListResponse
	if err := json.Unmarshal(body, &repoList); err != nil {
		return nil, fmt.Errorf("parsing repositories: %w", err)
	}

	var findings []types.Finding
	for _, repo := range repoList.Repositories {
		// 2. List Images in Repository
		imagesURL := fmt.Sprintf(
			"https://artifactregistry.googleapis.com/v1/%s/dockerImages",
			repo.Name,
		)
		
		imgBody, err := p.doRequest(ctx, imagesURL)
		if err != nil {
			continue // Skip repos that might be empty or inaccessible
		}

		var imgList dockerImageListResponse
		if err := json.Unmarshal(imgBody, &imgList); err != nil {
			continue
		}

		for _, img := range imgList.DockerImages {
			// 3. List Vulnerability Occurrences for Image Digest
			// Note: img.URI contains the full path with digest
			filter := fmt.Sprintf("kind=\"VULNERABILITY\" AND resourceUrl=\"https://%s\"", img.URI)
			occURL := fmt.Sprintf(
				"https://containeranalysis.googleapis.com/v1/projects/%s/occurrences?filter=%s",
				p.projectID, url.QueryEscape(filter),
			)

			occBody, err := p.doRequest(ctx, occURL)
			if err != nil {
				continue
			}

			var occResp occurrenceListResponse
			if err := json.Unmarshal(occBody, &occResp); err != nil {
				continue
			}

			for _, occ := range occResp.Occurrences {
				severity := occ.Vulnerability.EffectiveSeverity
				status := "PASS"

				if p.isSeverityAboveThreshold(severity, threshold) {
					status = "FAIL"
				}

				findings = append(findings, types.Finding{
					ID:          fmt.Sprintf("gcp.registry.image_scanned.%s", occ.Name),
					Provider:    "gcp",
					Resource:    "registry",
					Check:       "image_vulnerability_scan",
					Status:      status,
					RawPayload:  toRawPayload(occ),
					ResourceARN: fmt.Sprintf("//artifactregistry.googleapis.com/%s", img.Name),
					Timestamp:   time.Now().UTC(),
					RunID:       runID,
				})
			}
		}
	}

	// If no repositories or findings were found, emit a single PASS finding.
	if len(findings) == 0 {
		findings = append(findings, types.Finding{
			ID:          "gcp.registry.image_scanned.none",
			Provider:    "gcp",
			Resource:    "registry",
			Check:       "image_vulnerability_scan",
			Status:      "PASS",
			ResourceARN: fmt.Sprintf("projects/%s/locations/-/repositories", p.projectID),
			Timestamp:   time.Now().UTC(),
			RunID:       runID,
		})
	}

	return findings, nil
}

// isSeverityAboveThreshold handles the severity-based normalization logic.
func (p *GCPProvider) isSeverityAboveThreshold(severity, threshold string) bool {
	levels := map[string]int{
		"INFORMATIONAL": 0,
		"LOW":           1,
		"MEDIUM":        2,
		"HIGH":          3,
		"CRITICAL":      4,
	}

	sVal := levels[severity]
	tVal := levels[threshold]

	return sVal >= tVal && tVal != 0
}
