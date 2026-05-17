package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	asset "cloud.google.com/go/asset/apiv1"
	"cloud.google.com/go/asset/apiv1/assetpb"
	"github.com/alibkaba/jula-evidence-collector/pkg/types"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

// CAIExtractionConfig defines the parameters for a declarative GCP CAI query.
type CAIExtractionConfig struct {
	Description string `json:"description"`
	// Scope defines the GCP resource boundary (e.g., "projects/my-project").
	// Optional in JSON; if omitted, defaults to the JULA_GCP_SCOPE environment variable.
	Scope string `json:"scope,omitempty"`
	// Query is the specific CAI search string.
	// E.g., "state:ACTIVE" or "policy:roles/owner".
	Query string `json:"query"`
	// AssetTypes restricts the search to specific GCP resource types.
	// E.g., ["compute.googleapis.com/Instance"]. Optional.
	AssetTypes []string `json:"asset_types,omitempty"`
}

// CAIConfigMap maps ERL IDs to their corresponding extraction configurations.
type CAIConfigMap map[string]CAIExtractionConfig

// LoadCAIConfigs reads and parses a JSON file containing CAIExtractionConfig definitions.
func LoadCAIConfigs(path string) (CAIConfigMap, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading CAI config file %s: %w", path, err)
	}

	var configs CAIConfigMap
	if err := json.Unmarshal(data, &configs); err != nil {
		return nil, fmt.Errorf("unmarshaling CAI configs: %w", err)
	}

	return configs, nil
}

// ResourceIterator defines the interface for iterating over CAI search results.
type ResourceIterator interface {
	Next() (*assetpb.ResourceSearchResult, error)
}

// defaultResourceIterator wraps the concrete GCP iterator to implement the ResourceIterator interface.
type defaultResourceIterator struct {
	it *asset.ResourceSearchResultIterator
}

func (i *defaultResourceIterator) Next() (*assetpb.ResourceSearchResult, error) {
	return i.it.Next()
}

// AssetClient defines the interface for interacting with the Google Cloud Asset API.
type AssetClient interface {
	SearchAllResources(ctx context.Context, req *assetpb.SearchAllResourcesRequest, opts ...option.ClientOption) ResourceIterator
	Close() error
}

// defaultAssetClient wraps the concrete GCP client to implement the AssetClient interface.
type defaultAssetClient struct {
	c *asset.Client
}

func (c *defaultAssetClient) SearchAllResources(ctx context.Context, req *assetpb.SearchAllResourcesRequest, opts ...option.ClientOption) ResourceIterator {
	// Note: We ignore the opts here for the simple wrapper since the signature doesn't perfectly align with the grpc method without unwrapping.
	// For production we map the grpc options appropriately.
	// We call the underlying grpc method.
	it := c.c.SearchAllResources(ctx, req)
	return &defaultResourceIterator{it: it}
}

func (c *defaultAssetClient) Close() error {
	return c.c.Close()
}

// UnifiedCAIProvider implements the Evidence Extraction paradigm using Google Cloud Asset Inventory.
// It executes declarative searches without evaluating the underlying resources against a framework.
type UnifiedCAIProvider struct {
	client       AssetClient
	defaultScope string
}

// NewUnifiedCAIProvider creates a new provider instance, initializing the GCP Asset client.
// It attempts to authenticate via default credentials but requires JULA_GCP_SCOPE to be set
// if individual configs do not provide a scope.
func NewUnifiedCAIProvider(ctx context.Context) (*UnifiedCAIProvider, error) {
	// Support an optional explicit credentials file via env var (useful for local execution).
	var clientOpts []option.ClientOption
	if credFile := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"); credFile != "" {
		clientOpts = append(clientOpts, option.WithCredentialsFile(credFile))
	}

	client, err := asset.NewClient(ctx, clientOpts...)
	if err != nil {
		return nil, fmt.Errorf("creating asset client: %w", err)
	}

	return &UnifiedCAIProvider{
		client:       &defaultAssetClient{c: client},
		defaultScope: os.Getenv("JULA_GCP_SCOPE"),
	}, nil
}

// Close cleans up the underlying GCP client connections.
func (p *UnifiedCAIProvider) Close() error {
	if p.client != nil {
		return p.client.Close()
	}
	return nil
}

// Extract executes a CAI search for a given ERL ID based on its configuration.
// It returns a unified types.Finding containing the raw JSON response from GCP,
// allowing the orchestrator to hash and route the evidence without knowing its structure.
func (p *UnifiedCAIProvider) Extract(ctx context.Context, erlID string, cfg CAIExtractionConfig, runID string) (types.Finding, error) {
	scope := cfg.Scope
	if scope == "" {
		scope = p.defaultScope
	}
	if scope == "" {
		return types.Finding{}, fmt.Errorf("no scope defined in config and JULA_GCP_SCOPE is unset")
	}

	// Interpolate project ID placeholders.
	projectID := os.Getenv("GCP_PROJECT_ID")
	if projectID != "" {
		scope = strings.ReplaceAll(scope, "{{GCP_PROJECT_ID}}", projectID)
		scope = strings.ReplaceAll(scope, "${GCP_PROJECT_ID}", projectID)
	}

	req := &assetpb.SearchAllResourcesRequest{
		Scope:      scope,
		Query:      cfg.Query,
		AssetTypes: cfg.AssetTypes,
	}

	it := p.client.SearchAllResources(ctx, req)
	var resources []map[string]interface{}

	for {
		resp, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return types.Finding{}, fmt.Errorf("executing CAI search: %w", err)
		}

		// Convert the gRPC response into a generic map for JSON serialization.
		// Since we are "Collector Only", we don't care about strongly-typed fields;
		// we just want to deliver the raw representation to the GRC tool.
		resMap := map[string]interface{}{
			"name":         resp.Name,
			"assetType":    resp.AssetType,
			"project":      resp.Project,
			"location":     resp.Location,
			"state":        resp.State,
			"labels":       resp.Labels,
			"networkTags":  resp.NetworkTags,
			"kmsKey":       resp.KmsKey,
			"folders":      resp.Folders,
			"organization": resp.Organization,
		}

		if resp.CreateTime != nil {
			resMap["createTime"] = resp.CreateTime.AsTime().Format(time.RFC3339)
		}
		if resp.UpdateTime != nil {
			resMap["updateTime"] = resp.UpdateTime.AsTime().Format(time.RFC3339)
		}

		// Attempt to parse the AdditionalAttributes struct if present.
		if resp.AdditionalAttributes != nil {
			attrMap := make(map[string]interface{})
			b, err := resp.AdditionalAttributes.MarshalJSON()
			if err == nil {
				json.Unmarshal(b, &attrMap)
				resMap["additionalAttributes"] = attrMap
			}
		}

		resources = append(resources, resMap)
	}

	// Wrapper to ensure valid JSON even if empty.
	payload := map[string]interface{}{
		"query":     cfg.Query,
		"scope":     scope,
		"resources": resources,
	}

	rawData, err := json.Marshal(payload)
	if err != nil {
		return types.Finding{}, fmt.Errorf("marshaling CAI results: %w", err)
	}

	return types.Finding{
		ErlID:     erlID,
		Provider:  "gcp_cai",
		RawData:   rawData,
		Timestamp: time.Now().UTC(),
		RunID:     runID,
	}, nil
}
