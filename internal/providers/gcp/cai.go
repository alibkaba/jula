package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
	ErlID       string `json:"erl_id"`
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
	// SearchType specifies whether to search resources ("resource") or IAM policies ("iam").
	// Defaults to "resource" if empty.
	SearchType string `json:"search_type,omitempty"`
}

// CAIConfigMap maps ERL IDs to their corresponding extraction configurations.
type CAIConfigMap map[string]CAIExtractionConfig

// LoadCAIConfigs reads and parses a JSON file containing CAIExtractionConfig definitions.
func LoadCAIConfigs(path string) (CAIConfigMap, error) {
	cleanedPath := filepath.Clean(path)
	if strings.Contains(cleanedPath, "..") {
		return nil, fmt.Errorf("gcp_cai: path traversal detected: %s", path)
	}

	data, err := os.ReadFile(cleanedPath)
	if err != nil {
		return nil, fmt.Errorf("reading CAI config file %s: %w", cleanedPath, err)
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

// IamPolicyIterator defines the interface for iterating over CAI IAM search results.
type IamPolicyIterator interface {
	Next() (*assetpb.IamPolicySearchResult, error)
}

// defaultIamPolicyIterator wraps the concrete GCP iterator to implement the IamPolicyIterator interface.
type defaultIamPolicyIterator struct {
	it *asset.IamPolicySearchResultIterator
}

func (i *defaultIamPolicyIterator) Next() (*assetpb.IamPolicySearchResult, error) {
	return i.it.Next()
}

// AssetClient defines the interface for interacting with the Google Cloud Asset API.
type AssetClient interface {
	SearchAllResources(ctx context.Context, req *assetpb.SearchAllResourcesRequest, opts ...option.ClientOption) ResourceIterator
	SearchAllIamPolicies(ctx context.Context, req *assetpb.SearchAllIamPoliciesRequest, opts ...option.ClientOption) IamPolicyIterator
	Close() error
}

// defaultAssetClient wraps the concrete GCP client to implement the AssetClient interface.
type defaultAssetClient struct {
	c *asset.Client
}

func (c *defaultAssetClient) SearchAllResources(ctx context.Context, req *assetpb.SearchAllResourcesRequest, opts ...option.ClientOption) ResourceIterator {
	it := c.c.SearchAllResources(ctx, req)
	return &defaultResourceIterator{it: it}
}

func (c *defaultAssetClient) SearchAllIamPolicies(ctx context.Context, req *assetpb.SearchAllIamPoliciesRequest, opts ...option.ClientOption) IamPolicyIterator {
	it := c.c.SearchAllIamPolicies(ctx, req)
	return &defaultIamPolicyIterator{it: it}
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

	var resources []map[string]interface{}

	if strings.ToLower(cfg.SearchType) == "iam" || strings.ToLower(cfg.SearchType) == "iam_policy" {
		req := &assetpb.SearchAllIamPoliciesRequest{
			Scope:      scope,
			Query:      cfg.Query,
			AssetTypes: cfg.AssetTypes,
		}

		it := p.client.SearchAllIamPolicies(ctx, req)
		for {
			resp, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				return types.Finding{}, fmt.Errorf("executing CAI IAM search: %w", err)
			}

			resMap := map[string]interface{}{
				"resource":     resp.Resource,
				"project":      resp.Project,
				"assetType":    resp.AssetType,
				"folders":      resp.Folders,
				"organization": resp.Organization,
			}

			if resp.Policy != nil {
				policyMap := make(map[string]interface{})
				b, err := json.Marshal(resp.Policy)
				if err == nil {
					json.Unmarshal(b, &policyMap)
					resMap["policy"] = policyMap
				}
			}

			resources = append(resources, resMap)
		}
	} else {
		req := &assetpb.SearchAllResourcesRequest{
			Scope:      scope,
			Query:      cfg.Query,
			AssetTypes: cfg.AssetTypes,
		}

		it := p.client.SearchAllResources(ctx, req)
		for {
			resp, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				return types.Finding{}, fmt.Errorf("executing CAI search: %w", err)
			}

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
