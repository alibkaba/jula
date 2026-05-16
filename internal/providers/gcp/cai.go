package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	asset "cloud.google.com/go/asset/apiv1"
	"cloud.google.com/go/asset/apiv1/assetpb"
	"google.golang.org/api/iterator"

	"github.com/alibkaba/jula-evidence-collector/pkg/types"
)

// ---------------------------------------------------------------------------
// CAI Configuration Types
// ---------------------------------------------------------------------------

// CAIConfig represents a single declarative extraction block from the
// JSON configuration file. Each block maps an ERL ID to a specific
// GCP Cloud Asset Inventory search query.
type CAIConfig struct {
	// Description is a human-readable label for this extraction
	// (e.g., "Encrypted Database Instances").
	Description string `json:"description"`

	// Provider identifies the extraction engine (e.g., "gcp_cai").
	Provider string `json:"provider"`

	// Scope is the GCP resource scope for the search, supporting
	// template variables like {{GCP_PROJECT_ID}} that are interpolated
	// at runtime from environment variables.
	Scope string `json:"scope"`

	// AssetTypes restricts the search to specific GCP asset types
	// (e.g., ["sqladmin.googleapis.com/Instance"]).
	AssetTypes []string `json:"asset_types"`

	// Query is an optional CAI search query filter (e.g., "state:RUNNING").
	// An empty string means no additional filtering.
	Query string `json:"query"`
}

// ---------------------------------------------------------------------------
// Unified CAI Provider
// ---------------------------------------------------------------------------

// UnifiedCAIProvider implements the evidence extraction engine using
// Google Cloud Asset Inventory's SearchAllResources API. It replaces
// all individual imperative GCP providers (kms.go, firewalls.go, etc.)
// with a single, declarative, config-driven extraction surface.
//
// This provider is not registered via init() because it requires
// explicit configuration loading and client initialization.
// ResourceIterator abstracts the CAI result pagination.
type ResourceIterator interface {
	Next() (*assetpb.ResourceSearchResult, error)
}

// AssetSearcher abstracts the CAI API client.
type AssetSearcher interface {
	SearchAllResources(ctx context.Context, req *assetpb.SearchAllResourcesRequest) ResourceIterator
	Close() error
}

type defaultAssetSearcher struct {
	client *asset.Client
}

func (s *defaultAssetSearcher) SearchAllResources(ctx context.Context, req *assetpb.SearchAllResourcesRequest) ResourceIterator {
	return s.client.SearchAllResources(ctx, req)
}

func (s *defaultAssetSearcher) Close() error {
	return s.client.Close()
}

// UnifiedCAIProvider implements the evidence extraction engine using
// Google Cloud Asset Inventory's SearchAllResources API.
type UnifiedCAIProvider struct {
	client AssetSearcher
}

// NewUnifiedCAIProvider creates a new CAI provider with an authenticated
// Asset Inventory client. The client uses Application Default Credentials
// (ADC), which supports both service account keys and the GCP metadata
// server on Cloud Run.
func NewUnifiedCAIProvider(ctx context.Context) (*UnifiedCAIProvider, error) {
	client, err := asset.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("initializing CAI client: %w", err)
	}
	return &UnifiedCAIProvider{client: &defaultAssetSearcher{client: client}}, nil
}

// Close releases the underlying gRPC connection to the CAI API.
func (p *UnifiedCAIProvider) Close() error {
	if p.client != nil {
		return p.client.Close()
	}
	return nil
}

// Extract executes a SearchAllResources call for the given ERL ID using
// the provided CAIConfig. It handles pagination transparently via the
// iterator pattern, aggregates all raw resource JSON payloads into a
// single []byte array, and returns the result as a Finding.
//
// Template variables in Scope and Query (e.g., {{GCP_PROJECT_ID}}) are
// interpolated from environment variables before the API call.
func (p *UnifiedCAIProvider) Extract(ctx context.Context, erlID string, config CAIConfig, runID string) (types.Finding, error) {
	// Interpolate template variables in scope and query.
	scope := interpolateEnvVars(config.Scope)
	query := interpolateEnvVars(config.Query)

	slog.Info("cai: starting extraction",
		"erl_id", erlID,
		"scope", scope,
		"asset_types", config.AssetTypes,
		"query", query,
	)

	// Build the SearchAllResources request.
	req := &assetpb.SearchAllResourcesRequest{
		Scope:      scope,
		AssetTypes: config.AssetTypes,
		Query:      query,
	}

	// Execute the search and iterate through all pages of results.
	it := p.client.SearchAllResources(ctx, req)

	resources := make([]map[string]any, 0)
	for {
		resource, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return types.Finding{}, fmt.Errorf("iterating CAI results for %s: %w", erlID, err)
		}

		// Convert the protobuf resource to a generic map for raw JSON storage.
		// We marshal to JSON and back to get a clean map[string]any representation
		// that strips protobuf-specific metadata.
		resourceJSON, err := json.Marshal(resource)
		if err != nil {
			slog.Warn("cai: failed to marshal resource, skipping",
				"erl_id", erlID,
				"error", err,
			)
			continue
		}

		var resourceMap map[string]any
		if err := json.Unmarshal(resourceJSON, &resourceMap); err != nil {
			slog.Warn("cai: failed to unmarshal resource map, skipping",
				"erl_id", erlID,
				"error", err,
			)
			continue
		}

		resources = append(resources, resourceMap)
	}

	slog.Info("cai: extraction complete",
		"erl_id", erlID,
		"resource_count", len(resources),
	)

	// Marshal the aggregated resources array into the raw byte payload.
	// An empty result set is valid (marshals to "[]").
	rawData, err := json.Marshal(resources)
	if err != nil {
		return types.Finding{}, fmt.Errorf("marshalling aggregated resources for %s: %w", erlID, err)
	}

	return types.Finding{
		ErlID:     erlID,
		Provider:  "gcp_cai",
		RawData:   rawData,
		Timestamp: time.Now().UTC(),
		RunID:     runID,
	}, nil
}

// ---------------------------------------------------------------------------
// Configuration Loading
// ---------------------------------------------------------------------------

// LoadCAIConfigs reads and parses the declarative extraction configuration
// from a JSON file. The returned map is keyed by ERL ID.
func LoadCAIConfigs(path string) (map[string]CAIConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading CAI config file %s: %w", path, err)
	}

	var configs map[string]CAIConfig
	if err := json.Unmarshal(data, &configs); err != nil {
		return nil, fmt.Errorf("parsing CAI config file %s: %w", path, err)
	}

	if len(configs) == 0 {
		return nil, fmt.Errorf("CAI config file %s contains no extraction definitions", path)
	}

	slog.Info("cai: loaded extraction configs",
		"path", path,
		"erl_count", len(configs),
	)

	return configs, nil
}

// ---------------------------------------------------------------------------
// Template Variable Interpolation
// ---------------------------------------------------------------------------

// interpolateEnvVars replaces {{VAR_NAME}} placeholders in the input string
// with the corresponding environment variable values. If an environment
// variable is not set, the placeholder is replaced with an empty string
// and a warning is logged.
func interpolateEnvVars(input string) string {
	result := input
	for {
		start := strings.Index(result, "{{")
		if start == -1 {
			break
		}
		end := strings.Index(result[start:], "}}")
		if end == -1 {
			break
		}
		end += start + 2 // Adjust to absolute position past "}}"

		varName := result[start+2 : end-2]
		varValue := os.Getenv(varName)

		if varValue == "" {
			slog.Warn("cai: environment variable not set for template interpolation",
				"variable", varName,
			)
		}

		result = result[:start] + varValue + result[end:]
	}
	return result
}
