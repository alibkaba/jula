package universal_rest

import (
	"context"
	"fmt"
	"net/http"

	"golang.org/x/oauth2/google"
)

// SignGCPADC uses Google Application Default Credentials to obtain an OAuth2 token
// and attaches it as a Bearer token to the HTTP request. This avoids needing the
// heavy cloud.google.com/go/asset package.
func SignGCPADC(ctx context.Context, req *http.Request) error {
	// The cloud-platform scope is required for most GCP API interactions like CAI.
	creds, err := google.FindDefaultCredentials(ctx, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		return fmt.Errorf("could not find GCP default credentials (check GOOGLE_APPLICATION_CREDENTIALS or metadata server): %w", err)
	}

	token, err := creds.TokenSource.Token()
	if err != nil {
		return fmt.Errorf("failed to exchange GCP credentials for access token: %w", err)
	}

	if token.AccessToken == "" {
		return fmt.Errorf("GCP token exchange returned empty access token")
	}

	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	return nil
}
