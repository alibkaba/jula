// Package httpgeneric implements a Universal HTTP Engine that can query any
// SaaS API using a declarative JSON configuration. Instead of writing custom
// Go clients for each third-party service, this engine reads endpoint details
// (URL, method, headers, pagination) from a config file and returns the raw
// JSON payloads as types.Finding structs.
package httpgeneric

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/alibkaba/jula-evidence-collector/pkg/types"
)

// ProviderConfig defines a template for a provider's base settings.
type ProviderConfig struct {
	BaseURL string            `json:"base_url"`
	Headers map[string]string `json:"headers"`
	Auth    *AuthConfig       `json:"auth,omitempty"`
}

// String implements fmt.Stringer for ProviderConfig to prevent credential leakage.
func (p ProviderConfig) String() string {
	res, _ := p.MarshalJSON()
	return string(res)
}

// MarshalJSON implements json.Marshaler for ProviderConfig to prevent structured log leaks.
func (p ProviderConfig) MarshalJSON() ([]byte, error) {
	type Alias ProviderConfig
	redacted := Alias(p)
	if redacted.Headers != nil {
		redacted.Headers = make(map[string]string)
		for k, v := range p.Headers {
			if strings.EqualFold(k, "Authorization") {
				redacted.Headers[k] = "*REDACTED*"
			} else {
				redacted.Headers[k] = v
			}
		}
	}
	if redacted.Auth != nil {
		redacted.Auth = redacted.Auth.Redacted()
	}
	return json.Marshal(redacted)
}

// SaaSExtractionConfig defines the simplified ERL configuration structure.
type SaaSExtractionConfig struct {
	ErlID       string            `json:"erl_id"`
	Description string            `json:"description"`
	Provider    string            `json:"provider"`
	Method      string            `json:"method"`
	Path        string            `json:"path"`
	Headers     map[string]string `json:"headers,omitempty"`
	JSONPath    string            `json:"json_path"`
	Pagination  *PaginationConfig `json:"pagination,omitempty"`
}

// ExtractionConfig represents a single fully-hydrated SaaS HTTP extraction configuration.
type ExtractionConfig struct {
	ErlID       string            `json:"erl_id"`
	Description string            `json:"description"`
	Provider    string            `json:"provider"`
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Headers     map[string]string `json:"headers"`
	JSONPath    string            `json:"json_path"`
	Pagination  *PaginationConfig `json:"pagination,omitempty"`
	Auth        *AuthConfig       `json:"auth,omitempty"`
}

// String implements fmt.Stringer for ExtractionConfig to prevent credential leakage.
func (c ExtractionConfig) String() string {
	res, _ := c.MarshalJSON()
	return string(res)
}

// MarshalJSON implements json.Marshaler for ExtractionConfig to prevent structured log leaks.
func (c ExtractionConfig) MarshalJSON() ([]byte, error) {
	type Alias ExtractionConfig
	redacted := Alias(c)
	if redacted.Headers != nil {
		redacted.Headers = make(map[string]string)
		for k, v := range c.Headers {
			if strings.EqualFold(k, "Authorization") {
				redacted.Headers[k] = "*REDACTED*"
			} else {
				redacted.Headers[k] = v
			}
		}
	}
	if redacted.Auth != nil {
		redacted.Auth = redacted.Auth.Redacted()
	}
	return json.Marshal(redacted)
}

// AuthConfig defines OAuth 2.0 client_credentials token exchange settings.
type AuthConfig struct {
	Type            string `json:"type"`
	TokenURL        string `json:"token_url"`
	ClientIDEnv     string `json:"client_id_env"`
	ClientSecretEnv string `json:"client_secret_env"`
}

// String implements fmt.Stringer for AuthConfig to prevent credential leakage.
func (a AuthConfig) String() string {
	res, _ := a.MarshalJSON()
	return string(res)
}

// MarshalJSON implements json.Marshaler for AuthConfig to prevent structured log leaks.
func (a AuthConfig) MarshalJSON() ([]byte, error) {
	type Alias AuthConfig
	redacted := Alias(a)
	redacted.ClientSecretEnv = "*REDACTED*"
	return json.Marshal(redacted)
}

// Redacted returns a copy of AuthConfig with sensitive env var keys redacted.
func (a *AuthConfig) Redacted() *AuthConfig {
	if a == nil {
		return nil
	}
	copy := *a
	copy.ClientSecretEnv = "*REDACTED*"
	return &copy
}

// PaginationConfig defines how the engine should paginate through results.
type PaginationConfig struct {
	NextURLField string `json:"next_url_field"`
	MaxPages     int    `json:"max_pages"`
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

// LoadSaaSConfigs parses the declarative saas_http.json file and the providers.json template file,
// merging them into a unified map of ERL ID to ExtractionConfig while enforcing referential integrity,
// parameter-level URL escaping to prevent SSRF/Path Traversal, and url.JoinPath.
func LoadSaaSConfigs(path string) (map[string]ExtractionConfig, error) {
	// Read saas_http.json ERL configurations
	cleanedPath := filepath.Clean(path)
	if strings.Contains(cleanedPath, "..") {
		return nil, fmt.Errorf("saas_http: path traversal detected: %s", path)
	}

	erlData, err := os.ReadFile(cleanedPath)
	if err != nil {
		return nil, fmt.Errorf("reading SaaS config %s: %w", cleanedPath, err)
	}

	var saasConfigs map[string]SaaSExtractionConfig
	if err := json.Unmarshal(erlData, &saasConfigs); err != nil {
		return nil, fmt.Errorf("parsing SaaS config %s: %w", path, err)
	}

	// Resolve and read providers.json
	providersPath := filepath.Join(filepath.Dir(path), "providers.json")
	provData, err := os.ReadFile(providersPath)
	if err != nil {
		return nil, fmt.Errorf("reading SaaS providers config %s: %w", providersPath, err)
	}

	var providerConfigs map[string]ProviderConfig
	if err := json.Unmarshal(provData, &providerConfigs); err != nil {
		return nil, fmt.Errorf("parsing SaaS providers config %s: %w", providersPath, err)
	}

	// Hydrate ERL configs into fully-qualified ExtractionConfig map
	configs := make(map[string]ExtractionConfig, len(saasConfigs))
	for scfID, saasCfg := range saasConfigs {
		// Strict referential integrity: hard-fail if referenced provider is missing
		prov, exists := providerConfigs[saasCfg.Provider]
		if !exists {
			return nil, fmt.Errorf("referential integrity violation: SCF %s references undefined provider %q", scfID, saasCfg.Provider)
		}

		// Interpolate provider's base URL (no path escape here, since it's the base host/scheme)
		interpolatedBase := envVarPattern.ReplaceAllStringFunc(prov.BaseURL, func(match string) string {
			varName := match[2 : len(match)-1]
			if val := os.Getenv(varName); val != "" {
				return val
			}
			return match
		})

		// SSRF & Path Traversal prevention: PathEscape ONLY the values of individual environment variables
		interpolatedPath := envVarPattern.ReplaceAllStringFunc(saasCfg.Path, func(match string) string {
			varName := match[2 : len(match)-1] // Strip ${ and }
			val := os.Getenv(varName)
			if val != "" {
				return url.PathEscape(val)
			}
			return match
		})

		// Robust URL assembly using net/url to preserve query parameters
		base, err := url.Parse(interpolatedBase)
		if err != nil {
			return nil, fmt.Errorf("parsing base URL for SCF %s: %w", scfID, err)
		}
		rel, err := url.Parse(interpolatedPath)
		if err != nil {
			return nil, fmt.Errorf("parsing path for SCF %s: %w", scfID, err)
		}
		fullURL := base.ResolveReference(rel).String()

		// Merge headers, prioritizing ERL-specific headers
		mergedHeaders := make(map[string]string)
		for k, v := range prov.Headers {
			mergedHeaders[k] = v
		}
		for k, v := range saasCfg.Headers {
			mergedHeaders[k] = v
		}

		configs[scfID] = ExtractionConfig{
			ErlID:       saasCfg.ErlID,
			Description: saasCfg.Description,
			Provider:    saasCfg.Provider,
			Method:      saasCfg.Method,
			URL:         fullURL,
			Headers:     mergedHeaders,
			JSONPath:    saasCfg.JSONPath,
			Pagination:  saasCfg.Pagination,
			Auth:        prov.Auth,
		}
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

	// If OAuth auth is configured, exchange credentials for a bearer token.
	if cfg.Auth != nil && cfg.Auth.Type == "oauth2_client_credentials" {
		token, err := e.resolveAuth(ctx, cfg.Auth)
		if err != nil {
			return types.Finding{}, fmt.Errorf("auth token exchange for %s: %w", erlID, err)
		}
		headers["Authorization"] = "Bearer " + token
	}

	// Validate that no unresolved env vars remain in auth headers.
	for k, v := range headers {
		if strings.Contains(v, "${") {
			return types.Finding{}, fmt.Errorf(
				"unresolved environment variable in header %q", k,
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
		body, resp, err := e.fetchSingle(ctx, method, targetURL, headers)
		if err != nil {
			return types.Finding{}, err
		}

		// Strict Pagination Enforcement: hard-fail if there is a next-page link in standard headers but no pagination instructions
		if hasNextLink(resp.Header.Get("Link")) {
			return types.Finding{}, fmt.Errorf("strict pagination enforcement: response contains pagination link (rel=next) but ERL config lacks pagination instructions")
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

// hasNextLink parses standard RFC 5988 Link header for rel="next" relation.
func hasNextLink(linkHeader string) bool {
	if linkHeader == "" {
		return false
	}
	return strings.Contains(linkHeader, `rel="next"`)
}

// fetchSingle makes an HTTP request with exponential backoff on HTTP 429 rate limiting.
func (e *Engine) fetchSingle(ctx context.Context, method, url string, headers map[string]string) (json.RawMessage, *http.Response, error) {
	const (
		maxRetries  = 3
		baseBackoff = 2 * time.Second
	)

	var body []byte
	var resp *http.Response
	var lastErr error

	currentBackoff := baseBackoff

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			slog.Warn("http_generic: rate limited (HTTP 429), retrying...", "attempt", attempt, "backoff", currentBackoff, "url", url)
			select {
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			case <-time.After(currentBackoff):
			}
			currentBackoff *= 2 // Exponential backoff
		}

		req, err := http.NewRequestWithContext(ctx, method, url, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("creating request: %w", err)
		}

		for k, v := range headers {
			req.Header.Set(k, v)
		}

		resp, err = e.client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("executing request: %w", err)
			continue
		}

		// Catch HTTP 429 rate limit
		if resp.StatusCode == http.StatusTooManyRequests {
			retryAfter := resp.Header.Get("Retry-After")
			if retryAfter != "" {
				if secs, parseErr := strconv.Atoi(retryAfter); parseErr == nil {
					currentBackoff = time.Duration(secs) * time.Second
				}
			}
			resp.Body.Close()
			lastErr = fmt.Errorf("HTTP 429 Too Many Requests")
			continue
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			resp.Body.Close()
			return nil, nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
		}

		body, err = io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, nil, fmt.Errorf("reading response body: %w", err)
		}

		return json.RawMessage(body), resp, nil
	}

	return nil, nil, fmt.Errorf("failed after %d rate-limit retries: %w", maxRetries, lastErr)
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
		body, _, err := e.fetchSingle(ctx, method, currentURL, headers)
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

// resolveAuth performs an OAuth 2.0 client_credentials token exchange.
// It sends a POST request with Basic Auth (client_id:client_secret) to the
// configured token URL and returns the access_token from the response.
func (e *Engine) resolveAuth(ctx context.Context, auth *AuthConfig) (string, error) {
	clientID := os.Getenv(auth.ClientIDEnv)
	clientSecret := os.Getenv(auth.ClientSecretEnv)
	if clientID == "" || clientSecret == "" {
		return "", fmt.Errorf(
			"missing credentials: %s and %s must be set", auth.ClientIDEnv, auth.ClientSecretEnv,
		)
	}

	body := strings.NewReader(`{"grant_type":"client_credentials"}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, auth.TokenURL, body)
	if err != nil {
		return "", fmt.Errorf("creating token request: %w", err)
	}

	// Aikido expects Basic Auth with client_id:client_secret base64-encoded.
	credentials := base64.StdEncoding.EncodeToString([]byte(clientID + ":" + clientSecret))
	req.Header.Set("Authorization", "Basic "+credentials)
	req.Header.Set("Content-Type", "application/json")

	slog.Debug("oauth: exchanging credentials for bearer token",
		"token_url", auth.TokenURL,
		"client_id_env", auth.ClientIDEnv,
	)

	resp, err := e.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("token exchange request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token exchange returned HTTP %d", resp.StatusCode)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return "", fmt.Errorf("parsing token response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("token response missing access_token field")
	}

	slog.Info("oauth: token exchange successful",
		"token_url", auth.TokenURL,
	)

	return tokenResp.AccessToken, nil
}
