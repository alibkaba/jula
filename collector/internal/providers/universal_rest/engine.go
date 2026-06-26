// Package universal_rest implements an integration-driven REST engine
// that fetches compliance evidence from SaaS endpoints using declarative YAML integrations.
package universal_rest

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
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

// ErrMissingCredentials is returned when an integration's authentication
// configuration references environment variables that are not set.
// The orchestrator should catch this specific error and skip the integration
// gracefully instead of failing the pipeline.
var ErrMissingCredentials = errors.New("missing auth credentials")

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

// Engine executes HTTP GET requests based on RESTIntegration configurations.
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

// Execute performs HTTP GET requests defined in the integration for a specific Evidence path.
// For paginated endpoints, it returns multiple findings (one per page) with original body bytes.
// If authentication credentials are missing, it returns ErrMissingCredentials to allow
// the orchestrator to skip the integration gracefully.
func (e *Engine) Execute(ctx context.Context, integration *RESTIntegration, erlPath string, epCfg RESTEndpointConfig, runID string) ([]types.Finding, error) {
	targetURL, err := resolveTargetURL(integration.BaseURL, erlPath)
	if err != nil {
		return nil, err
	}

	headers, err := buildHeaders(epCfg.Headers)
	if err != nil {
		return nil, err
	}

	// Handle authentication validation early if possible
	if integration.AuthFlow.Type == "bearer" && os.Getenv(integration.AuthFlow.TokenEnv) == "" {
		slog.Debug("universal_rest: skipping integration due to missing credentials", "vendor", integration.VendorName, "evidence_id", epCfg.EvidenceID)
		return nil, fmt.Errorf("skipping integration %s: %w", integration.VendorName, ErrMissingCredentials)
	}

	// Execute HTTP requests (single or paginated)
	if epCfg.Pagination != nil && epCfg.Pagination.NextURLField != "" {
		return e.fetchPaginated(ctx, targetURL, headers, epCfg, integration, runID)
	}

	// Single-page execution
	body, resp, err := e.fetchSingle(ctx, targetURL, headers, epCfg, integration)
	if err != nil {
		return nil, err
	}

	// Strict Pagination Enforcement
	if hasNextLink(resp.Header.Get("Link")) {
		return nil, fmt.Errorf("strict pagination enforcement: response contains pagination link (rel=next) but endpoint config lacks pagination instructions")
	}

	finding := types.Finding{
		EvidenceID: epCfg.EvidenceID,
		Provider:   integration.VendorName,
		RawData:    body,
		Timestamp:  time.Now().UTC(),
		RunID:      runID,
	}

	return []types.Finding{finding}, nil
}

// resolveTargetURL cleans the path, interpolates environment variables, and parses/resolves the full request URL.
func resolveTargetURL(baseURL, erlPath string) (string, error) {
	cleanErlPath := CleanPath(erlPath)
	interpolatedPath := InterpolateEnvVars(cleanErlPath, true)
	interpolatedBase := InterpolateEnvVars(baseURL, false)

	base, err := url.Parse(interpolatedBase)
	if err != nil {
		return "", fmt.Errorf("parsing integration base URL: %w", err)
	}
	rel, err := url.Parse(interpolatedPath)
	if err != nil {
		return "", fmt.Errorf("parsing endpoint path: %w", err)
	}
	return base.ResolveReference(rel).String(), nil
}

// buildHeaders constructs request headers from endpoint config headers, interpolating env variables
// and validating that no unresolved environment variables remain.
func buildHeaders(epCfgHeaders map[string]string) (map[string]string, error) {
	headers := make(map[string]string)
	for k, v := range epCfgHeaders {
		headers[k] = InterpolateEnvVars(v, false)
	}

	for k, v := range headers {
		if strings.Contains(v, "${") {
			return nil, fmt.Errorf("unresolved environment variable in header %q", k)
		}
	}
	return headers, nil
}

// applyBearerAuth resolves bearer auth credentials and sets the Authorization header.
func applyBearerAuth(req *http.Request, auth *AuthFlowConfig) error {
	if auth.TokenEnv == "" {
		return fmt.Errorf("bearer auth requires token_env to be configured")
	}
	token := os.Getenv(auth.TokenEnv)
	if token == "" {
		return fmt.Errorf("%w: environment variable %s is not set", ErrMissingCredentials, auth.TokenEnv)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return nil
}

// applyOAuth2Auth resolves OAuth2 client credentials, performs the token exchange, and sets the Authorization header.
func (e *Engine) applyOAuth2Auth(ctx context.Context, req *http.Request, auth *AuthFlowConfig) error {
	if auth.TokenURL == "" || auth.ClientIDEnv == "" || auth.ClientSecretEnv == "" {
		return fmt.Errorf("oauth2 auth requires token_url, client_id_env, and client_secret_env to be configured")
	}
	clientID := os.Getenv(auth.ClientIDEnv)
	clientSecret := os.Getenv(auth.ClientSecretEnv)
	if clientID == "" || clientSecret == "" {
		return fmt.Errorf("%w: %s and %s must be set", ErrMissingCredentials, auth.ClientIDEnv, auth.ClientSecretEnv)
	}

	body := strings.NewReader(`{"grant_type":"client_credentials"}`)
	tokenReq, err := http.NewRequestWithContext(ctx, http.MethodPost, auth.TokenURL, body)
	if err != nil {
		return fmt.Errorf("creating token request: %w", err)
	}

	credentials := base64.StdEncoding.EncodeToString([]byte(clientID + ":" + clientSecret))
	tokenReq.Header.Set("Authorization", "Basic "+credentials)
	tokenReq.Header.Set("Content-Type", "application/json")

	resp, err := e.client.Do(tokenReq)
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

	req.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	return nil
}

// applyAuth resolves auth credentials and inserts appropriate authorization headers directly onto the request.
func (e *Engine) applyAuth(ctx context.Context, req *http.Request, auth *AuthFlowConfig, payload []byte) error {
	switch strings.ToLower(auth.Type) {
	case "bearer":
		return applyBearerAuth(req, auth)

	case "oauth2":
		return e.applyOAuth2Auth(ctx, req, auth)

	case "aws_sigv4":
		if err := SignAWSv4(req, payload); err != nil {
			return fmt.Errorf("%w: aws_sigv4 signing failed: %v", ErrMissingCredentials, err)
		}

	case "gcp_adc":
		if err := SignGCPADC(ctx, req); err != nil {
			return fmt.Errorf("%w: gcp_adc signing failed: %v", ErrMissingCredentials, err)
		}

	case "azure_identity":
		if err := SignAzureIdentity(ctx, req); err != nil {
			return fmt.Errorf("%w: azure_identity signing failed: %v", ErrMissingCredentials, err)
		}

	case "oci_cavage":
		if err := SignOCICavage(req, payload); err != nil {
			return fmt.Errorf("%w: oci_cavage signing failed: %v", ErrMissingCredentials, err)
		}

	case "ali_tencent_hmac":
		if err := SignAliTencentHMAC(req, payload); err != nil {
			return fmt.Errorf("%w: ali_tencent_hmac signing failed: %v", ErrMissingCredentials, err)
		}

	case "jws_financial":
		if err := SignJWSFinancial(req, payload); err != nil {
			return fmt.Errorf("%w: jws_financial signing failed: %v", ErrMissingCredentials, err)
		}
	}
	return nil
}

// buildRequest constructs an http.Request with JSON body, headers, and authentication.
func (e *Engine) buildRequest(ctx context.Context, method, targetURL string, headers map[string]string, payload []byte, auth *AuthFlowConfig) (*http.Request, error) {
	var bodyReader io.Reader
	if len(payload) > 0 {
		bodyReader = bytes.NewReader(payload)
	}

	req, err := http.NewRequestWithContext(ctx, method, targetURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	if len(payload) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	if err := e.applyAuth(ctx, req, auth, payload); err != nil {
		return nil, fmt.Errorf("applying authentication: %w", err)
	}

	return req, nil
}

// checkResponseStatus validates response status code and handles Allowed 404 behavior.
func checkResponseStatus(resp *http.Response, allow404 bool, targetURL string) ([]byte, bool, error) {
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if resp.StatusCode == http.StatusNotFound && allow404 {
			slog.Warn("universal_rest: resource not found (404), proceeding with null payload", "url", targetURL)
			return []byte("null"), true, nil
		}
		return nil, false, fmt.Errorf("HTTP %d from %s", resp.StatusCode, targetURL)
	}
	return nil, false, nil
}

// fetchSingle makes an HTTP request with exponential backoff on HTTP 429 rate limiting.
func (e *Engine) fetchSingle(ctx context.Context, targetURL string, headers map[string]string, epCfg RESTEndpointConfig, integration *RESTIntegration) ([]byte, *http.Response, error) {
	const (
		maxRetries  = 3
		baseBackoff = 2 * time.Second
	)

	method := epCfg.Method
	if method == "" {
		method = http.MethodGet
	}

	var payload []byte
	if len(epCfg.Body) > 0 {
		var err error
		payload, err = json.Marshal(epCfg.Body)
		if err != nil {
			return nil, nil, fmt.Errorf("marshaling request body: %w", err)
		}
	}

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

		req, err := e.buildRequest(ctx, method, targetURL, headers, payload, &integration.AuthFlow)
		if err != nil {
			return nil, nil, err
		}

		resp, err = e.client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("executing request: %w", err)
			continue
		}

		// Handle HTTP 429 rate limit and 50x transient server errors
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			if resp.StatusCode == http.StatusTooManyRequests {
				if retryAfter := resp.Header.Get("Retry-After"); retryAfter != "" {
					if secs, parseErr := strconv.Atoi(retryAfter); parseErr == nil {
						currentBackoff = time.Duration(secs) * time.Second
					}
				}
			}
			resp.Body.Close()
			lastErr = fmt.Errorf("HTTP %d error", resp.StatusCode)
			continue
		}

		nullBody, isNull, statusErr := checkResponseStatus(resp, epCfg.Allow404, targetURL)
		if statusErr != nil {
			resp.Body.Close()
			return nil, nil, statusErr
		}
		if isNull {
			return nullBody, resp, nil
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
func (e *Engine) fetchPaginated(ctx context.Context, targetURL string, headers map[string]string, epCfg RESTEndpointConfig, integration *RESTIntegration, runID string) ([]types.Finding, error) {
	var findings []types.Finding
	currentURL := targetURL
	maxPages := epCfg.Pagination.MaxPages
	if maxPages <= 0 {
		maxPages = 100 // Safety threshold
	}

	for page := 0; page < maxPages; page++ {
		body, resp, err := e.fetchSingle(ctx, currentURL, headers, epCfg, integration)
		if err != nil {
			return nil, fmt.Errorf("page %d: %w", page+1, err)
		}

		findings = append(findings, types.Finding{
			EvidenceID: epCfg.EvidenceID,
			Provider:   integration.VendorName,
			RawData:    body,
			Timestamp:  time.Now().UTC(),
			RunID:      runID,
		})

		nextURL, found := extractNextPageURL(resp, body, epCfg.Pagination, currentURL)
		if !found {
			break // Terminate pagination
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

// extractBetweenAngles returns the substring between '<' and '>' characters in s.
func extractBetweenAngles(s string) string {
	start := strings.Index(s, "<")
	end := strings.Index(s, ">")
	if start != -1 && end != -1 && start < end {
		return s[start+1 : end]
	}
	return ""
}

// extractNextLinkHeader parses standard RFC 5988 Link header for rel="next" URL.
func extractNextLinkHeader(linkHeader string) string {
	if linkHeader == "" {
		return ""
	}
	parts := strings.Split(linkHeader, ",")
	for _, part := range parts {
		if strings.Contains(part, `rel="next"`) {
			return extractBetweenAngles(part)
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

// extractNextPageURL determines the URL of the next page of results, resolving relative URLs if needed.
func extractNextPageURL(resp *http.Response, body []byte, pagination *PaginationConfig, currentURL string) (string, bool) {
	if pagination == nil || pagination.NextURLField == "" {
		return "", false
	}

	var nextURL string
	var found bool
	if pagination.NextURLField == "header.Link" || pagination.NextURLField == "Link" {
		nextURL = extractNextLinkHeader(resp.Header.Get("Link"))
		found = nextURL != ""
	} else {
		nextURL, found = extractNextURL(body, pagination.NextURLField)
	}

	if !found || nextURL == "" {
		return "", false
	}

	// If nextURL is relative, resolve it against the request URL
	parsedNext, err := url.Parse(nextURL)
	if err == nil && !parsedNext.IsAbs() {
		parsedCurrent, err := url.Parse(currentURL)
		if err == nil {
			nextURL = parsedCurrent.ResolveReference(parsedNext).String()
		}
	}
	return nextURL, true
}
