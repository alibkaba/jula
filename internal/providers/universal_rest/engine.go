// Package universal_rest implements a blueprint-driven REST engine
// that fetches compliance evidence from SaaS endpoints using OpenAPI-inspired YAML blueprints.
package universal_rest

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
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/alibkaba/jula-core/pkg/types"
)

var envVarPattern = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// InterpolateEnvVars replaces all ${VAR_NAME} tokens in a string with their
// corresponding environment variable values.
func InterpolateEnvVars(input string, escape bool) string {
	return envVarPattern.ReplaceAllStringFunc(input, func(match string) string {
		varName := match[2 : len(match)-1] // Strip ${ and }
		if val := os.Getenv(varName); val != "" {
			if escape {
				return url.PathEscape(val)
			}
			return val
		}
		return match // Leave unresolved vars as-is for debugging.
	})
}

// Engine executes HTTP GET requests based on OpenAPIBlueprint configurations.
type Engine struct {
	client *http.Client
}

// NewEngine creates a new REST engine with sensible default values.
func NewEngine(client *http.Client) *Engine {
	if client == nil {
		client = &http.Client{
			Timeout: 30 * time.Second,
		}
	}
	return &Engine{client: client}
}

// Execute performs HTTP GET requests defined in the blueprint for a specific ERL path.
// For paginated endpoints, it returns multiple findings (one per page) with original body bytes.
func (e *Engine) Execute(ctx context.Context, blueprint *OpenAPIBlueprint, erlPath string, epCfg EndpointConfig, runID string) ([]types.Finding, error) {
	// 1. Clean the path of any virtual query parameters used for uniqueness
	cleanErlPath := CleanPath(erlPath)

	// 2. Interpolate environment variables in the path (escaping variables to prevent SSRF/Path traversal)
	interpolatedPath := InterpolateEnvVars(cleanErlPath, true)

	// 3. Interpolate Base URL without path escaping
	interpolatedBase := InterpolateEnvVars(blueprint.BaseURL, false)

	// 4. Resolve the full request URL
	base, err := url.Parse(interpolatedBase)
	if err != nil {
		return nil, fmt.Errorf("parsing blueprint base URL: %w", err)
	}
	rel, err := url.Parse(interpolatedPath)
	if err != nil {
		return nil, fmt.Errorf("parsing endpoint path: %w", err)
	}
	targetURL := base.ResolveReference(rel).String()

	// 5. Build base headers, interpolating env variables
	headers := make(map[string]string)
	for k, v := range epCfg.Headers {
		headers[k] = InterpolateEnvVars(v, false)
	}

	// 6. Handle authentication
	if err := e.applyAuth(ctx, &blueprint.AuthFlow, headers); err != nil {
		return nil, fmt.Errorf("resolving authentication: %w", err)
	}

	// 7. Validate that no unresolved environment variables remain in header values
	for k, v := range headers {
		if strings.Contains(v, "${") {
			return nil, fmt.Errorf("unresolved environment variable in header %q", k)
		}
	}

	// 8. Execute HTTP requests (single or paginated)
	if epCfg.Pagination != nil && epCfg.Pagination.NextURLField != "" {
		return e.fetchPaginated(ctx, targetURL, headers, epCfg, blueprint.VendorName, runID)
	}

	// Single-page execution
	body, resp, err := e.fetchSingle(ctx, targetURL, headers, epCfg.Allow404)
	if err != nil {
		return nil, err
	}

	// Strict Pagination Enforcement
	if hasNextLink(resp.Header.Get("Link")) {
		return nil, fmt.Errorf("strict pagination enforcement: response contains pagination link (rel=next) but endpoint config lacks pagination instructions")
	}

	finding := types.Finding{
		ErlID:     epCfg.ErlID,
		Provider:  blueprint.VendorName,
		RawData:   body,
		Timestamp: time.Now().UTC(),
		RunID:     runID,
	}

	return []types.Finding{finding}, nil
}

// applyAuth resolves auth credentials and inserts appropriate authorization headers.
func (e *Engine) applyAuth(ctx context.Context, auth *AuthFlowConfig, headers map[string]string) error {
	switch strings.ToLower(auth.Type) {
	case "bearer":
		if auth.TokenEnv == "" {
			return fmt.Errorf("bearer auth requires token_env to be configured")
		}
		token := os.Getenv(auth.TokenEnv)
		if token == "" {
			return fmt.Errorf("missing bearer token: environment variable %s is not set", auth.TokenEnv)
		}
		headers["Authorization"] = "Bearer " + token
	case "oauth2":
		if auth.TokenURL == "" || auth.ClientIDEnv == "" || auth.ClientSecretEnv == "" {
			return fmt.Errorf("oauth2 auth requires token_url, client_id_env, and client_secret_env to be configured")
		}
		clientID := os.Getenv(auth.ClientIDEnv)
		clientSecret := os.Getenv(auth.ClientSecretEnv)
		if clientID == "" || clientSecret == "" {
			return fmt.Errorf("missing oauth2 credentials: %s and %s must be set", auth.ClientIDEnv, auth.ClientSecretEnv)
		}

		body := strings.NewReader(`{"grant_type":"client_credentials"}`)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, auth.TokenURL, body)
		if err != nil {
			return fmt.Errorf("creating token request: %w", err)
		}

		credentials := base64.StdEncoding.EncodeToString([]byte(clientID + ":" + clientSecret))
		req.Header.Set("Authorization", "Basic "+credentials)
		req.Header.Set("Content-Type", "application/json")

		slog.Debug("oauth: exchanging credentials for bearer token",
			"token_url", auth.TokenURL,
			"client_id_env", auth.ClientIDEnv,
		)

		resp, err := e.client.Do(req)
		if err != nil {
			return fmt.Errorf("token exchange request failed: %w", err)
		}
		defer resp.Body.Close()

		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("reading token response: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("token exchange returned HTTP %d", resp.StatusCode)
		}

		var tokenResp struct {
			AccessToken string `json:"access_token"`
		}
		if err := json.Unmarshal(respBody, &tokenResp); err != nil {
			return fmt.Errorf("parsing token response: %w", err)
		}

		if tokenResp.AccessToken == "" {
			return fmt.Errorf("token response missing access_token field")
		}

		slog.Info("oauth: token exchange successful", "token_url", auth.TokenURL)
		headers["Authorization"] = "Bearer " + tokenResp.AccessToken
	}
	return nil
}

// fetchSingle makes an HTTP request with exponential backoff on HTTP 429 rate limiting.
func (e *Engine) fetchSingle(ctx context.Context, targetURL string, headers map[string]string, allow404 bool) ([]byte, *http.Response, error) {
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
			slog.Warn("universal_rest: rate limited (HTTP 429), retrying...", "attempt", attempt, "backoff", currentBackoff, "url", targetURL)
			select {
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			case <-time.After(currentBackoff):
			}
			currentBackoff *= 2 // Exponential backoff
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
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

		// Handle HTTP 429 rate limit
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
			if resp.StatusCode == http.StatusNotFound && allow404 {
				slog.Warn("universal_rest: resource not found (404), proceeding with null payload", "url", targetURL)
				resp.Body.Close()
				return []byte("null"), resp, nil
			}
			resp.Body.Close()
			return nil, nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, targetURL)
		}

		body, err = io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, nil, fmt.Errorf("reading response body: %w", err)
		}

		return body, resp, nil
	}

	return nil, nil, fmt.Errorf("failed after %d rate-limit retries: %w", maxRetries, lastErr)
}

// fetchPaginated traverses pagination cursors and returns findings for each page fetched.
func (e *Engine) fetchPaginated(ctx context.Context, targetURL string, headers map[string]string, epCfg EndpointConfig, vendorName, runID string) ([]types.Finding, error) {
	var findings []types.Finding
	currentURL := targetURL
	maxPages := epCfg.Pagination.MaxPages
	if maxPages <= 0 {
		maxPages = 100 // Safety threshold
	}

	for page := 0; page < maxPages; page++ {
		body, resp, err := e.fetchSingle(ctx, currentURL, headers, epCfg.Allow404)
		if err != nil {
			return nil, fmt.Errorf("page %d: %w", page+1, err)
		}

		findings = append(findings, types.Finding{
			ErlID:     epCfg.ErlID,
			Provider:  vendorName,
			RawData:   body,
			Timestamp: time.Now().UTC(),
			RunID:     runID,
		})

		// Extract pagination token in a read-only manner
		var nextURL string
		var found bool
		if epCfg.Pagination.NextURLField == "header.Link" || epCfg.Pagination.NextURLField == "Link" {
			nextURL = extractNextLinkHeader(resp.Header.Get("Link"))
			found = nextURL != ""
		} else {
			nextURL, found = extractNextURL(body, epCfg.Pagination.NextURLField)
		}

		if !found || nextURL == "" {
			break // Terminate pagination
		}

		// If nextURL is relative, resolve it against the request URL
		parsedNext, err := url.Parse(nextURL)
		if err == nil && !parsedNext.IsAbs() {
			parsedCurrent, err := url.Parse(currentURL)
			if err == nil {
				nextURL = parsedCurrent.ResolveReference(parsedNext).String()
			}
		}

		slog.Debug("universal_rest: following pagination", "page", page+1, "next_url", nextURL)
		currentURL = nextURL
	}

	return findings, nil
}

// hasNextLink parses standard RFC 5988 Link header for rel="next" relation.
func hasNextLink(linkHeader string) bool {
	if linkHeader == "" {
		return false
	}
	return strings.Contains(linkHeader, `rel="next"`)
}

// extractNextLinkHeader parses standard RFC 5988 Link header for rel="next" URL.
func extractNextLinkHeader(linkHeader string) string {
	if linkHeader == "" {
		return ""
	}
	parts := strings.Split(linkHeader, ",")
	for _, part := range parts {
		if strings.Contains(part, `rel="next"`) {
			start := strings.Index(part, "<")
			end := strings.Index(part, ">")
			if start != -1 && end != -1 && start < end {
				return part[start+1 : end]
			}
		}
	}
	return ""
}

// extractNextURL parses the response body into a generic map strictly to find the next page pointer.
func extractNextURL(body []byte, fieldPath string) (string, bool) {
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		return "", false
	}

	parts := strings.Split(fieldPath, ".")
	var current any = obj

	for i, part := range parts {
		m, ok := current.(map[string]any)
		if !ok {
			return "", false
		}

		val, exists := m[part]
		if !exists {
			return "", false
		}

		if i == len(parts)-1 {
			strVal, ok := val.(string)
			return strVal, ok && strVal != ""
		}

		current = val
	}

	return "", false
}
