package aws

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

// mockECR implements ECRAPI for testing.
type mockECR struct {
	DescribeRepositoriesFunc      func(ctx context.Context, params *ecr.DescribeRepositoriesInput, optFns ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error)
	DescribeImageScanFindingsFunc func(ctx context.Context, params *ecr.DescribeImageScanFindingsInput, optFns ...func(*ecr.Options)) (*ecr.DescribeImageScanFindingsOutput, error)
}

func (m *mockECR) DescribeRepositories(ctx context.Context, params *ecr.DescribeRepositoriesInput, optFns ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error) {
	return m.DescribeRepositoriesFunc(ctx, params, optFns...)
}

func (m *mockECR) DescribeImageScanFindings(ctx context.Context, params *ecr.DescribeImageScanFindingsInput, optFns ...func(*ecr.Options)) (*ecr.DescribeImageScanFindingsOutput, error) {
	return m.DescribeImageScanFindingsFunc(ctx, params, optFns...)
}

func TestExtractRegistry_NoRepos(t *testing.T) {
	m := &mockECR{
		DescribeRepositoriesFunc: func(ctx context.Context, params *ecr.DescribeRepositoriesInput, optFns ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error) {
			return &ecr.DescribeRepositoriesOutput{Repositories: []ecrtypes.Repository{}}, nil
		},
	}
	p := &awsProvider{ecrClient: m}

	findings, err := p.extractRegistry(context.Background(), "test-run")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 || findings[0].Status != "PASS" {
		t.Errorf("expected 1 PASS finding for no repos, got %d", len(findings))
	}
}

func TestExtractRegistry_WithFindings(t *testing.T) {
	m := &mockECR{
		DescribeRepositoriesFunc: func(ctx context.Context, params *ecr.DescribeRepositoriesInput, optFns ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error) {
			return &ecr.DescribeRepositoriesOutput{
				Repositories: []ecrtypes.Repository{
					{RepositoryName: aws.String("test-repo"), RepositoryArn: aws.String("arn:aws:ecr:us-east-1:123:repo/test-repo")},
				},
			}, nil
		},
		DescribeImageScanFindingsFunc: func(ctx context.Context, params *ecr.DescribeImageScanFindingsInput, optFns ...func(*ecr.Options)) (*ecr.DescribeImageScanFindingsOutput, error) {
			return &ecr.DescribeImageScanFindingsOutput{
				ImageScanFindings: &ecrtypes.ImageScanFindings{
					Findings: []ecrtypes.ImageScanFinding{
						{Name: aws.String("CVE-2023-1"), Severity: ecrtypes.FindingSeverityHigh},
					},
				},
			}, nil
		},
	}
	p := &awsProvider{ecrClient: m}

	findings, err := p.extractRegistry(context.Background(), "test-run")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 || findings[0].Status != "FAIL" {
		t.Errorf("expected 1 FAIL finding, got %d (status: %s)", len(findings), findings[0].Status)
	}
}

func TestExtractRegistry_NoScanFindings(t *testing.T) {
	m := &mockECR{
		DescribeRepositoriesFunc: func(ctx context.Context, params *ecr.DescribeRepositoriesInput, optFns ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error) {
			return &ecr.DescribeRepositoriesOutput{
				Repositories: []ecrtypes.Repository{
					{RepositoryName: aws.String("test-repo"), RepositoryArn: aws.String("arn:aws:ecr:us-east-1:123:repo/test-repo")},
				},
			}, nil
		},
		DescribeImageScanFindingsFunc: func(ctx context.Context, params *ecr.DescribeImageScanFindingsInput, optFns ...func(*ecr.Options)) (*ecr.DescribeImageScanFindingsOutput, error) {
			return nil, errors.New("scan not found")
		},
	}
	p := &awsProvider{ecrClient: m}

	findings, err := p.extractRegistry(context.Background(), "test-run")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Error in DescribeImageScanFindings results in skipping findings for that repo, 
	// leading to "none" PASS finding if no other repos have findings.
	if len(findings) != 1 || findings[0].Status != "PASS" {
		t.Errorf("expected PASS finding, got %s", findings[0].Status)
	}
}

func TestIsSeverityAboveThreshold(t *testing.T) {
	p := &awsProvider{}
	tests := []struct {
		severity  string
		threshold string
		expected  bool
	}{
		{"HIGH", "HIGH", true},
		{"CRITICAL", "HIGH", true},
		{"MEDIUM", "HIGH", false},
		{"LOW", "HIGH", false},
		{"INFORMATIONAL", "HIGH", false},
		{"HIGH", "LOW", true},
		{"HIGH", "CRITICAL", false},
	}

	for _, tt := range tests {
		result := p.isSeverityAboveThreshold(tt.severity, tt.threshold)
		if result != tt.expected {
			t.Errorf("isSeverityAboveThreshold(%s, %s) = %v; want %v", tt.severity, tt.threshold, result, tt.expected)
		}
	}
}
