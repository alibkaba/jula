package filedrop

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// TokenProvider abstracts how the GCS reader obtains an OAuth2 access token.
type TokenProvider interface {
	Token() (string, error)
}

// GCSReader implements StorageReader using the GCS JSON API via raw HTTP.
type GCSReader struct {
	BucketName    string
	HTTPClient    *http.Client
	TokenProvider TokenProvider
	BaseURL       string // defaults to "https://storage.googleapis.com/storage/v1"
}

func (r *GCSReader) apiBase() string {
	if r.BaseURL != "" {
		return r.BaseURL
	}
	return "https://storage.googleapis.com/storage/v1"
}

// ListFiles returns the keys of all files under the given prefix.
func (r *GCSReader) ListFiles(ctx context.Context, prefix string) ([]string, error) {
	token, err := r.TokenProvider.Token()
	if err != nil {
		return nil, fmt.Errorf("obtaining token: %w", err)
	}

	apiURL := fmt.Sprintf("%s/b/%s/o?prefix=%s", r.apiBase(), url.PathEscape(r.BucketName), url.QueryEscape(prefix))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := r.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GCS list returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	var payload struct {
		Items []struct {
			Name string `json:"name"`
		} `json:"items"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	var keys []string
	for _, item := range payload.Items {
		keys = append(keys, item.Name)
	}

	return keys, nil
}

// GetFile returns the file contents as a reader, along with provider-specific metadata.
func (r *GCSReader) GetFile(ctx context.Context, key string) (io.ReadCloser, map[string]string, error) {
	token, err := r.TokenProvider.Token()
	if err != nil {
		return nil, nil, fmt.Errorf("obtaining token: %w", err)
	}

	apiURL := fmt.Sprintf("%s/b/%s/o/%s?alt=media", r.apiBase(), url.PathEscape(r.BucketName), url.PathEscape(key))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := r.HTTPClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("request failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, nil, fmt.Errorf("GCS get returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	metadata := map[string]string{
		"content_type": resp.Header.Get("Content-Type"),
		"etag":         resp.Header.Get("Etag"),
	}

	return resp.Body, metadata, nil
}
