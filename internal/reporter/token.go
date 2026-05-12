package reporter

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const metadataTokenURL = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

// metadataTokenProvider fetches access tokens from the GCP metadata server.
// Used on Cloud Run where the container's service account identity provides tokens.
type metadataTokenProvider struct {
	httpClient  *http.Client
	cachedToken string
	tokenExpiry time.Time
	baseURL     string
}

type metadataTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

// NewMetadataTokenProvider creates a TokenProvider backed by the GCP metadata server.
func NewMetadataTokenProvider(httpClient *http.Client) TokenProvider {
	return &metadataTokenProvider{httpClient: httpClient}
}

// Token returns a valid access token, caching it until near-expiry.
func (p *metadataTokenProvider) Token() (string, error) {
	if p.cachedToken != "" && time.Now().Before(p.tokenExpiry) {
		return p.cachedToken, nil
	}

	targetURL := metadataTokenURL
	if p.baseURL != "" {
		targetURL = p.baseURL
	}

	// Validate the URL to prevent SSRF
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return "", fmt.Errorf("invalid metadata URL: %w", err)
	}
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return "", fmt.Errorf("metadata URL must use http or https")
	}
	allowedHosts := map[string]bool{
		"metadata.google.internal": true,
		"localhost":                true,
		"127.0.0.1":                true,
	}
	if !allowedHosts[parsedURL.Hostname()] {
		return "", fmt.Errorf("metadata request blocked: host %q is not in the allowlist", parsedURL.Hostname())
	}

	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		return "", fmt.Errorf("creating metadata request: %w", err)
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("metadata server request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading metadata response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("metadata server returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp metadataTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("parsing metadata token: %w", err)
	}

	p.cachedToken = tokenResp.AccessToken
	p.tokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn)*time.Second - 5*time.Minute)

	return p.cachedToken, nil
}
