package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/alibkaba/jula-evidence-collector/pkg/types"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"go.yaml.in/yaml/v4"
)

// ---------------------------------------------------------------------------
// AWS Config Extraction Configuration Types
// ---------------------------------------------------------------------------

// AWSConfigExtraction represents a single declarative extraction block from
// the JSON configuration file. Each block maps an ERL ID to a specific
// AWS Config Advanced Query (SelectResourceConfig SQL expression).
type AWSConfigExtraction struct {
	ErlID string `json:"erl_id" yaml:"erl_id"`

	// Description is a human-readable label for this extraction
	// (e.g., "S3 Bucket Configurations").
	Description string `json:"description" yaml:"description"`

	// Provider identifies the extraction engine (e.g., "aws_config").
	Provider string `json:"provider" yaml:"provider"`

	// Query is the AWS Config SQL expression executed via SelectResourceConfig
	// (e.g., "SELECT configuration WHERE resourceType = 'AWS::S3::Bucket'").
	Query string `json:"query" yaml:"query"`
}

// ---------------------------------------------------------------------------
// Unified AWS Config Provider
// ---------------------------------------------------------------------------

// UnifiedAWSConfigProvider implements the evidence extraction engine using
// AWS Config's SelectResourceConfig API with Advanced Queries. It replaces
// the legacy imperative AWS ECR provider with a single, declarative,
// config-driven extraction surface.
//
// This provider strictly uses the github.com/aws/aws-sdk-go-v2/service/configservice
// package and AWS-native pagination via NewSelectResourceConfigPaginator.
type UnifiedAWSConfigProvider struct {
	client configservice.SelectResourceConfigAPIClient
	region string
}

// NewUnifiedAWSConfigProvider creates a new AWS Config provider with an
// authenticated Config Service client. The client uses the standard AWS SDK v2
// credential chain (env vars, shared config, IMDS, etc.).
func NewUnifiedAWSConfigProvider(ctx context.Context) (*UnifiedAWSConfigProvider, error) {
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = os.Getenv("AWS_DEFAULT_REGION")
	}
	if region == "" {
		return nil, fmt.Errorf("aws_config: AWS_REGION or AWS_DEFAULT_REGION is required")
	}

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("aws_config: loading AWS SDK config: %w", err)
	}

	client := configservice.NewFromConfig(cfg)

	return &UnifiedAWSConfigProvider{
		client: client,
		region: region,
	}, nil
}

// Close is a no-op for the AWS Config provider (HTTP client, no persistent
// gRPC connection to tear down), but is included for interface symmetry
// with the GCP CAI provider.
func (p *UnifiedAWSConfigProvider) Close() error {
	return nil
}

// Extract executes a SelectResourceConfig call for the given ERL ID using
// the provided AWSConfigExtraction. It handles pagination transparently via
// AWS SDK v2's NewSelectResourceConfigPaginator, aggregates all returned
// JSON strings into a single []byte array, and returns the result as a Finding.
//
// AWS Config returns results as an array of JSON strings (not structured
// protobuf objects like GCP). Each string is a complete JSON document
// representing a single resource's configuration. We unmarshal each string
// into a json.RawMessage to preserve the original structure, aggregate them
// into a slice, and marshal the entire slice into the Finding's RawData field.
func (p *UnifiedAWSConfigProvider) Extract(ctx context.Context, erlID string, extraction AWSConfigExtraction, runID string) (types.Finding, error) {
	slog.Info("aws_config: starting extraction",
		"erl_id", erlID,
		"region", p.region,
		"query", extraction.Query,
	)

	// Build the SelectResourceConfig request.
	input := &configservice.SelectResourceConfigInput{
		Expression: &extraction.Query,
	}

	// Use the native AWS SDK v2 paginator for transparent pagination.
	paginator := configservice.NewSelectResourceConfigPaginator(p.client, input)

	var resources []json.RawMessage
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return types.Finding{}, fmt.Errorf("aws_config: querying %s: %w", erlID, err)
		}

		// AWS Config returns results as an array of JSON strings.
		// Each string is a self-contained JSON document for one resource.
		for _, resultStr := range page.Results {
			// Validate the string is valid JSON by unmarshaling into RawMessage.
			var raw json.RawMessage
			if err := json.Unmarshal([]byte(resultStr), &raw); err != nil {
				slog.Warn("aws_config: skipping malformed result",
					"erl_id", erlID,
					"error", err,
				)
				continue
			}
			resources = append(resources, raw)
		}
	}

	slog.Info("aws_config: extraction complete",
		"erl_id", erlID,
		"resource_count", len(resources),
	)

	// Marshal the aggregated resources array into the raw byte payload.
	// An empty result set is valid (marshals to "null" when resources is nil).
	rawData, err := json.Marshal(resources)
	if err != nil {
		return types.Finding{}, fmt.Errorf("aws_config: marshalling aggregated resources for %s: %w", erlID, err)
	}

	return types.Finding{
		ErlID:     erlID,
		Provider:  "aws_config",
		RawData:   rawData,
		Timestamp: time.Now().UTC(),
		RunID:     runID,
	}, nil
}

// ---------------------------------------------------------------------------
// Configuration Loading
// ---------------------------------------------------------------------------

// LoadAWSConfigExtractions reads and parses the declarative extraction
// configuration from a YAML file. The returned map is keyed by ERL ID.
func LoadAWSConfigExtractions(path string) (map[string]AWSConfigExtraction, error) {
	cleanedPath := filepath.Clean(path)
	if strings.Contains(cleanedPath, "..") {
		return nil, fmt.Errorf("aws_config: path traversal detected: %s", path)
	}

	data, err := os.ReadFile(cleanedPath)
	if err != nil {
		return nil, fmt.Errorf("reading AWS Config extraction file %s: %w", cleanedPath, err)
	}

	var configs map[string]AWSConfigExtraction
	if err := yaml.Unmarshal(data, &configs); err != nil {
		return nil, fmt.Errorf("parsing AWS Config extraction file %s: %w", path, err)
	}

	if len(configs) == 0 {
		return nil, fmt.Errorf("AWS Config extraction file %s contains no extraction definitions", path)
	}

	slog.Info("aws_config: loaded extraction configs",
		"path", path,
		"erl_count", len(configs),
	)

	return configs, nil
}
