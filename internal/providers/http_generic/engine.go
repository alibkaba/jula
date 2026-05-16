// Package httpgeneric implements a Universal HTTP Engine that can query any
// SaaS API using a declarative JSON configuration. Instead of writing custom
// Go clients for each third-party service, this engine reads endpoint details
// (URL, method, headers, pagination) from a config file and returns the raw
// JSON payloads as types.Finding structs.
package httpgeneric

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/alibkaba/jula-evidence-collector/pkg/types"
)

// ExtractionConfig represents a single SaaS HTTP extraction from the JSON config.
type ExtractionConfig struct {
	Description string            `json:"description"`
	Provider    string            `json:"provider"`
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Headers     map[string]string `json:"headers"`
	JSONPath    string            `json:"json_path"`
	// Pagination defines optional cursor-based pagination settings.
	Pagination *PaginationConfig `json:"pagination,omitempty"`
}

// PaginationConfig defines how the engine should paginate through results.
type PaginationConfig struct {
	// NextURLField is the JSON field in the response body that contains
	// the URL for the next page (e.g., "next", "links.next").
	NextURLField string `json:"next_url_field"`
	// MaxPages limits the maximum number of pages to fetch (safety valve).
	MaxPages int `json:"max_pages"`
}

// envVarPattern matches ${ENV_VAR_NAME} for interpolation.
var envVarPattern = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// InterpolateEnvVars replaces all ${VAR_NAME} tokens in a string with their
// corresponding environment variable values.
func InterpolateEnvVars(input string) string {
	return envVarPattern.ReplaceAllStringFunc(input, func(match string) string {
		varName := match[2 : len(match)-1] // Strip ${ and }
		if val := os.Getenv(varName); val != "" {
			return val
		}
		return match // Leave unresolved vars as-is for debugging.
	})
}

// LoadSaaSConfigs parses the declarative saas_http.json file and returns
// a map of ERL ID to ExtractionConfig.
func LoadSaaSConfigs(path string) (map[string]ExtractionConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading SaaS config %s: %w", path, err)
	}

	var configs map[string]ExtractionConfig
	if err := json.Unmarshal(data, &configs); err != nil {
		return nil, fmt.Errorf("parsing SaaS config %s: %w", path, err)
	}

	return configs, nil
}

// Engine executes HTTP requests based on declarative extraction configs.
type Engine struct {
	client *http.Client
}

// NewEngine creates a new HTTP generic engine with sensible defaults.
func NewEngine() *Engine {
	return &Engine{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// NewEngineWithClient creates an engine with a custom HTTP client (for testing).
func NewEngineWithClient(client *http.Client) *Engine {
	return &Engine{client: client}
}

// Extract executes a single SaaS HTTP extraction and returns a Finding
// containing the raw API response as RawData.
func (e *Engine) Extract(ctx context.Context, erlID string, cfg ExtractionConfig, runID string) (types.Finding, error) {
	// Interpolate environment variables in the URL and headers.
	targetURL := InterpolateEnvVars(cfg.URL)
	headers := make(map[string]string, len(cfg.Headers))
	for k, v := range cfg.Headers {
		headers[k] = InterpolateEnvVars(v)
	}

	// Validate that no unresolved env vars remain in auth headers.
	for k, v := range headers {
		if strings.Contains(v, "${") {
			return types.Finding{}, fmt.Errorf(
				"unresolved environment variable in header %q: %s", k, v,
			)
		}
	}

	method := strings.ToUpper(cfg.Method)
	if method == "" {
		method = "GET"
	}

	var allData json.RawMessage

	if cfg.Pagination != nil && cfg.Pagination.NextURLField != "" {
		// Paginated extraction.
		collected, err := e.fetchPaginated(ctx, method, targetURL, headers, cfg.Pagination)
		if err != nil {
			return types.Finding{}, err
		}
		allData = collected
	} else {
		// Single-page extraction.
		body, err := e.fetchSingle(ctx, method, targetURL, headers)
		if err != nil {
			return types.Finding{}, err
		}
		allData = body
	}

	slog.Debug("http_generic: extraction complete",
		"erl_id", erlID,
		"provider", cfg.Provider,
		"url", cfg.URL,
		"raw_bytes", len(allData),
	)

	return types.Finding{
		ErlID:     erlID,
		Provider:  cfg.Provider,
		RawData:   allData,
		Timestamp: time.Now().UTC(),
		RunID:     runID,
	}, nil
}

// fetchSingle makes a single HTTP request and returns the raw response body.
func (e *Engine) fetchSingle(ctx context.Context, method, url string, headers map[string]string) (json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d from %s: %s", resp.StatusCode, url, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	return json.RawMessage(body), nil
}

// fetchPaginated follows cursor-based pagination by extracting the next URL
// from the response body. It aggregates all pages into a single JSON array.
func (e *Engine) fetchPaginated(ctx context.Context, method, url string, headers map[string]string, pagination *PaginationConfig) (json.RawMessage, error) {
	var allItems []json.RawMessage
	currentURL := url
	maxPages := pagination.MaxPages
	if maxPages <= 0 {
		maxPages = 100 // Safety valve.
	}

	for page := 0; page < maxPages; page++ {
		body, err := e.fetchSingle(ctx, method, currentURL, headers)
		if err != nil {
			return nil, fmt.Errorf("page %d: %w", page+1, err)
		}

		// Try to parse the response as an array and merge items.
		var items []json.RawMessage
		if err := json.Unmarshal(body, &items); err == nil {
			allItems = append(allItems, items...)
		} else {
			// If the response is an object, add it as a single item.
			allItems = append(allItems, body)
		}

		// Extract the next URL from the response.
		nextURL, found := extractNextURL(body, pagination.NextURLField)
		if !found || nextURL == "" {
			break // No more pages.
		}

		slog.Debug("http_generic: following pagination",
			"page", page+1,
			"next_url", nextURL,
		)
		currentURL = nextURL
	}

	// Marshal all collected items into a single JSON array.
	result, err := json.Marshal(allItems)
	if err != nil {
		return nil, fmt.Errorf("marshalling paginated results: %w", err)
	}

	return json.RawMessage(result), nil
}

// extractNextURL traverses a dot-separated field path (e.g., "links.next")
// to find the next page URL in a JSON response body.
func extractNextURL(body json.RawMessage, fieldPath string) (string, bool) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return "", false
	}

	parts := strings.Split(fieldPath, ".")
	current := obj

	for i, part := range parts {
		raw, exists := current[part]
		if !exists {
			return "", false
		}

		if i == len(parts)-1 {
			// Final segment: extract the string value.
			var url string
			if err := json.Unmarshal(raw, &url); err != nil {
				return "", false
			}
			return url, url != ""
		}

		// Intermediate segment: descend into nested object.
		if err := json.Unmarshal(raw, &current); err != nil {
			return "", false
		}
	}

	return "", false
}
