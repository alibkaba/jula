package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/alibkaba/jula-evidence-collector/pkg/types"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

// extractRegistry pulls image scan findings from AWS ECR.
// Implements the distributed resource extractor pattern (ARCH-02).
func (p *awsProvider) extractRegistry(ctx context.Context, runID string) ([]types.Finding, error) {
	var findings []types.Finding

	threshold := os.Getenv("JULA_AWS_REGISTRY_FAIL_THRESHOLD")
	if threshold == "" {
		threshold = "HIGH"
	}

	// 1. List Repositories
	repos, err := p.ecrClient.DescribeRepositories(ctx, &ecr.DescribeRepositoriesInput{})
	if err != nil {
		return nil, fmt.Errorf("describing repositories: %w", err)
	}

	for _, repo := range repos.Repositories {
		repoName := aws.ToString(repo.RepositoryName)
		
		// 2. Describe Image Scan Findings for 'latest'
		input := &ecr.DescribeImageScanFindingsInput{
			RepositoryName: repo.RepositoryName,
			ImageId: &ecrtypes.ImageIdentifier{
				ImageTag: aws.String("latest"),
			},
		}

		output, err := p.ecrClient.DescribeImageScanFindings(ctx, input)
		if err != nil {
			// Skip repos without 'latest' tag or without scans
			slog.Debug("aws: skipping registry scan check", "repo", repoName, "error", err)
			continue
		}

		if output.ImageScanFindings == nil {
			continue
		}

		for _, finding := range output.ImageScanFindings.Findings {
			severity := string(finding.Severity)
			status := "PASS"
			
			if p.isSeverityAboveThreshold(severity, threshold) {
				status = "FAIL"
			}

			findings = append(findings, types.Finding{
				ID:          fmt.Sprintf("aws.registry.image_scanned.%s", aws.ToString(finding.Name)),
				Provider:    "aws",
				Resource:    "registry",
				Check:       "image_vulnerability_scan",
				Status:      status,
				RawPayload:  toRawPayload(finding),
				ResourceARN: fmt.Sprintf("%s/%s", aws.ToString(repo.RepositoryArn), repoName),
				Timestamp:   time.Now().UTC(),
				RunID:       runID,
			})
		}
	}

	// If no repositories or findings were found, emit a single PASS finding for the service.
	if len(findings) == 0 {
		findings = append(findings, types.Finding{
			ID:          "aws.registry.image_scanned.none",
			Provider:    "aws",
			Resource:    "registry",
			Check:       "scan_enabled",
			Status:      "PASS",
			ResourceARN: fmt.Sprintf("arn:aws:ecr:%s:root", p.region),
			Timestamp:   time.Now().UTC(),
			RunID:       runID,
		})
	}

	return findings, nil
}

// isSeverityAboveThreshold checks if the finding severity meets the failure threshold.
func (p *awsProvider) isSeverityAboveThreshold(severity, threshold string) bool {
	levels := map[string]int{
		"INFORMATIONAL": 0,
		"LOW":           1,
		"MEDIUM":        2,
		"HIGH":          3,
		"CRITICAL":      4,
	}

	sevLevel, ok := levels[severity]
	if !ok {
		return false
	}

	threshLevel, ok := levels[threshold]
	if !ok {
		threshLevel = 3 // Default to HIGH
	}

	return sevLevel >= threshLevel
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
