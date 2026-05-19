package gcp

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const tokenEndpoint = "https://oauth2.googleapis.com/token"

// serviceAccountKey represents the JSON key file for a GCP service account.
type serviceAccountKey struct {
	Type                    string `json:"type"`
	ProjectID               string `json:"project_id"`
	PrivateKeyID            string `json:"private_key_id"`
	PrivateKey              string `json:"private_key"`
	ClientEmail             string `json:"client_email"`
	ClientID                string `json:"client_id"`
	AuthURI                 string `json:"auth_uri"`
	TokenURI                string `json:"token_uri"`
	AuthProviderX509CertURL string `json:"auth_provider_x509_cert_url"`
	ClientX509CertURL       string `json:"client_x509_cert_url"`
}

// tokenResponse represents the OAuth2 token response from Google.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// tokenSource manages OAuth2 access tokens for GCP API calls.
type tokenSource struct {
	key            *serviceAccountKey
	privateKey     *rsa.PrivateKey
	scopes         []string
	cachedToken    string
	tokenExpiry    time.Time
	httpClient     *http.Client
	tokenURL       string
	metadataSource *metadataTokenSource
}

// newTokenSource creates a token source from a parsed service account key.
func newTokenSource(key *serviceAccountKey, httpClient *http.Client) (*tokenSource, error) {
	block, _ := pem.Decode([]byte(key.PrivateKey))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from private key")
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not RSA")
	}

	tokenURL := tokenEndpoint
	if key.TokenURI != "" {
		tokenURL = key.TokenURI
	}

	return &tokenSource{
		key:        key,
		privateKey: rsaKey,
		scopes:     []string{"https://www.googleapis.com/auth/cloud-platform.read-only"},
		httpClient: httpClient,
		tokenURL:   tokenURL,
	}, nil
}

// Token returns a valid access token, refreshing if necessary.
func (ts *tokenSource) Token() (string, error) {
	// Delegate to metadata server if configured (Cloud Run).
	if ts.metadataSource != nil {
		return ts.metadataSource.Token()
	}
	if ts.cachedToken != "" && time.Now().Before(ts.tokenExpiry) {
		return ts.cachedToken, nil
	}
	return ts.refresh()
}

// refresh exchanges a signed JWT for a new access token.
func (ts *tokenSource) refresh() (string, error) {
	now := time.Now()

	// Build JWT header.
	header := map[string]string{
		"alg": "RS256",
		"typ": "JWT",
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshalling JWT header: %w", err)
	}

	// Build JWT claims.
	claims := map[string]any{
		"iss":   ts.key.ClientEmail,
		"scope": strings.Join(ts.scopes, " "),
		"aud":   ts.tokenURL,
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshalling JWT claims: %w", err)
	}

	// Encode and sign.
	unsigned := base64.RawURLEncoding.EncodeToString(headerJSON) +
		"." +
		base64.RawURLEncoding.EncodeToString(claimsJSON)

	hashed := sha256.Sum256([]byte(unsigned))
	sig, err := rsa.SignPKCS1v15(nil, ts.privateKey, 0, hashed[:])
	if err != nil {
		return "", fmt.Errorf("signing JWT: %w", err)
	}

	jwt := unsigned + "." + base64.RawURLEncoding.EncodeToString(sig)

	// Exchange JWT for access token.
	resp, err := ts.httpClient.PostForm(ts.tokenURL, url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {jwt},
	})
	if err != nil {
		return "", fmt.Errorf("token exchange request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token exchange failed (HTTP %d)", resp.StatusCode)
	}

	var tokenResp tokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("parsing token response: %w", err)
	}

	ts.cachedToken = tokenResp.AccessToken
	// Expire 5 minutes early to avoid edge-case clock skew.
	ts.tokenExpiry = now.Add(time.Duration(tokenResp.ExpiresIn)*time.Second - 5*time.Minute)

	return ts.cachedToken, nil
}

// metadataTokenSource fetches access tokens from the GCP metadata server.
// Used on Cloud Run where the container's service account identity provides tokens.
type metadataTokenSource struct {
	httpClient  *http.Client
	cachedToken string
	tokenExpiry time.Time
}

const metadataURL = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

// newMetadataTokenSource creates a token source backed by the GCP metadata server.
func newMetadataTokenSource(httpClient *http.Client) *tokenSource {
	mts := &metadataTokenSource{httpClient: httpClient}
	return &tokenSource{
		metadataSource: mts,
	}
}

// Token returns a valid access token from the metadata server, caching it.
func (mts *metadataTokenSource) Token() (string, error) {
	if mts.cachedToken != "" && time.Now().Before(mts.tokenExpiry) {
		return mts.cachedToken, nil
	}

	req, err := http.NewRequest(http.MethodGet, metadataURL, nil)
	if err != nil {
		return "", fmt.Errorf("creating metadata request: %w", err)
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := mts.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("metadata server request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading metadata response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("metadata server returned HTTP %d", resp.StatusCode)
	}

	var tokenResp tokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("parsing metadata token response: %w", err)
	}

	mts.cachedToken = tokenResp.AccessToken
	mts.tokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn)*time.Second - 5*time.Minute)

	return mts.cachedToken, nil
}
