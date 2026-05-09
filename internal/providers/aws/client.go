package aws

import (
	"context"
	"fmt"
	"os"

	"github.com/alibkaba/jula-evidence-collector/internal/providers"
	"github.com/alibkaba/jula-evidence-collector/pkg/types"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
)

type awsProvider struct {
	region    string
	ecrClient *ecr.Client
}

func init() {
	providers.Register(&awsProvider{})
}

func (p *awsProvider) Name() string {
	return "aws"
}

func (p *awsProvider) Validate() error {
	p.region = os.Getenv("JULA_AWS_REGION")
	if p.region == "" {
		return fmt.Errorf("aws: JULA_AWS_REGION is required")
	}

	// Initialize AWS config and client
	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(p.region),
	)
	if err != nil {
		return fmt.Errorf("aws: loading config: %w", err)
	}

	p.ecrClient = ecr.NewFromConfig(cfg)
	return nil
}

func (p *awsProvider) Extract(ctx context.Context, runID string) ([]types.Finding, error) {
	var allFindings []types.Finding

	// Orchestrator: Call Registry Extractor
	registryFindings, err := p.extractRegistry(ctx, runID)
	if err != nil {
		return nil, fmt.Errorf("aws: extracting registry findings: %w", err)
	}

	allFindings = append(allFindings, registryFindings...)

	return allFindings, nil
}
