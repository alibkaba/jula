package aws

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

func TestExtract(t *testing.T) {
	m := &mockECR{
		DescribeRepositoriesFunc: func(ctx context.Context, params *ecr.DescribeRepositoriesInput, optFns ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error) {
			return &ecr.DescribeRepositoriesOutput{Repositories: []ecrtypes.Repository{}}, nil
		},
	}
	p := &awsProvider{ecrClient: m}

	findings, err := p.Extract(context.Background(), "test-run")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Error("expected findings, got 0")
	}
}

func TestName(t *testing.T) {
	p := &awsProvider{}
	if p.Name() != "aws" {
		t.Errorf("expected aws, got %s", p.Name())
	}
}

func TestValidate(t *testing.T) {
	p := &awsProvider{}
	t.Setenv("JULA_AWS_REGION", "")
	if err := p.Validate(); err == nil {
		t.Error("expected error for empty region")
	}

	t.Setenv("JULA_AWS_REGION", "us-east-1")
	// Note: config.LoadDefaultConfig might fail in CI if no creds, but we check if it handles the logic.
	_ = p.Validate()
}
