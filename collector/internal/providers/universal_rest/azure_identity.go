package universal_rest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type azureTokenCache struct {
	mu        sync.Mutex
	token     string
	expiresAt time.Time
}

var globalAzureCache azureTokenCache

// SignAzureIdentity implements an automated OAuth2 token fetcher using native Go net/http.
// It supports both Azure Instance Metadata Service (IMDS) for managed identities
// and Microsoft Entra ID tenant token endpoints for Service Principals.
// It includes a thread-safe token cache to prevent IMDS rate limiting.
func SignAzureIdentity(ctx context.Context, req *http.Request) error {
	globalAzureCache.mu.Lock()
	defer globalAzureCache.mu.Unlock()

	// Use cache if token is valid and won't expire within 60 seconds
	if globalAzureCache.token != "" && time.Now().Add(60*time.Second).Before(globalAzureCache.expiresAt) {
		req.Header.Set("Authorization", "Bearer "+globalAzureCache.token)
		return nil
	}

	tenantID := os.Getenv("AZURE_TENANT_ID")
	clientID := os.Getenv("AZURE_CLIENT_ID")
	clientSecret := os.Getenv("AZURE_CLIENT_SECRET")

	var token string
	var expiresIn int

	if tenantID != "" && clientID != "" && clientSecret != "" {
		// Service Principal Flow
		endpoint := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantID)
		data := url.Values{}
		data.Set("grant_type", "client_credentials")
		data.Set("client_id", clientID)
		data.Set("client_secret", clientSecret)
		data.Set("scope", "https://management.azure.com/.default")

		tReq, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(data.Encode()))
		if err != nil {
			return fmt.Errorf("creating azure token request: %w", err)
		}
		tReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := http.DefaultClient.Do(tReq)
		if err != nil {
			return fmt.Errorf("executing azure token request: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("azure token request failed with status: %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("reading azure token response: %w", err)
		}

		var result struct {
			AccessToken string `json:"access_token"`
			ExpiresIn   int    `json:"expires_in"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			return fmt.Errorf("parsing azure token response: %w", err)
		}
		token = result.AccessToken
		expiresIn = result.ExpiresIn

	} else {
		// IMDS Flow for managed pod identities
		endpoint := "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F"
		tReq, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
		if err != nil {
			return fmt.Errorf("creating imds token request: %w", err)
		}
		tReq.Header.Set("Metadata", "true")

		resp, err := http.DefaultClient.Do(tReq)
		if err != nil {
			return fmt.Errorf("executing imds token request: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("imds token request failed with status: %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("reading imds token response: %w", err)
		}

		var result map[string]any
		if err := json.Unmarshal(body, &result); err != nil {
			return fmt.Errorf("parsing imds token response: %w", err)
		}

		tok, ok := result["access_token"].(string)
		if !ok || tok == "" {
			return fmt.Errorf("imds token response missing access_token")
		}
		token = tok

		switch v := result["expires_in"].(type) {
		case float64:
			expiresIn = int(v)
		case string:
			parsed, _ := strconv.Atoi(v)
			expiresIn = parsed
		default:
			expiresIn = 3599 // Fallback
		}
	}

	if token == "" {
		return fmt.Errorf("azure identity resolved to empty token")
	}

	// Update Cache
	globalAzureCache.token = token
	globalAzureCache.expiresAt = time.Now().Add(time.Duration(expiresIn) * time.Second)

	req.Header.Set("Authorization", "Bearer "+token)
	return nil
}
