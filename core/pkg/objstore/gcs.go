package objstore

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	gcsUploadURL   = "https://storage.googleapis.com/upload/storage/v1"
	gcsAPIURL      = "https://storage.googleapis.com/storage/v1"
	gcsMetadataURL = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
)

// gcsStore implements Store for Google Cloud Storage using raw HTTP calls.
// Authentication uses the GCP metadata server (Cloud Run / GCE) or falls back
// to GOOGLE_APPLICATION_CREDENTIALS for local development.
type gcsStore struct {
	bucket     string
	httpClient *http.Client

	// baseURL allows overriding the GCS API endpoint for testing.
	baseURL string

	mu     sync.Mutex
	token  string
	expiry time.Time

	// tokenFetcher is the function used to fetch tokens. Overridable for tests.
	tokenFetcher func(client *http.Client) (string, time.Duration, error)
}

// gcsOption configures gcsStore behavior.
type gcsOption func(*gcsStore)

// withGCSBaseURL overrides the GCS API endpoint (for testing).
func withGCSBaseURL(baseURL string) gcsOption {
	return func(s *gcsStore) {
		s.baseURL = baseURL
	}
}

// withGCSTokenFetcher overrides the default token fetcher (for testing).
func withGCSTokenFetcher(fn func(client *http.Client) (string, time.Duration, error)) gcsOption {
	return func(s *gcsStore) {
		s.tokenFetcher = fn
	}
}

// newgcsStore creates a GCS-backed Store for the given bucket.
func newgcsStore(bucket string, httpClient *http.Client, opts ...gcsOption) *gcsStore {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	s := &gcsStore{
		bucket:       bucket,
		httpClient:   httpClient,
		tokenFetcher: fetchGCSToken,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Bucket returns the GCS bucket name.
func (s *gcsStore) Bucket() string {
	return s.bucket
}

// Put uploads data to the given object key in the bucket.
func (s *gcsStore) Put(ctx context.Context, key string, body io.Reader, contentType string) error {
	token, err := s.resolveToken()
	if err != nil {
		return fmt.Errorf("gcs: obtaining token: %w", err)
	}

	data, err := io.ReadAll(body)
	if err != nil {
		return fmt.Errorf("gcs: reading body: %w", err)
	}

	uploadBase := s.uploadURL()
	uploadEndpoint := fmt.Sprintf("%s/b/%s/o?uploadType=media&name=%s",
		uploadBase,
		url.PathEscape(s.bucket),
		url.QueryEscape(key),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uploadEndpoint, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("gcs: creating upload request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", contentType)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("gcs: upload request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("gcs: upload returned HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// Get retrieves the object identified by key from the bucket.
func (s *gcsStore) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	token, err := s.resolveToken()
	if err != nil {
		return nil, fmt.Errorf("gcs: obtaining token: %w", err)
	}

	apiBase := s.apiURL()
	downloadURL := fmt.Sprintf("%s/b/%s/o/%s?alt=media",
		apiBase,
		url.PathEscape(s.bucket),
		url.PathEscape(key),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return nil, fmt.Errorf("gcs: creating download request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gcs: download request failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("gcs: download returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	return resp.Body, nil
}

// List returns all objects matching the given key prefix.
func (s *gcsStore) List(ctx context.Context, prefix string) ([]Object, error) {
	token, err := s.resolveToken()
	if err != nil {
		return nil, fmt.Errorf("gcs: obtaining token: %w", err)
	}

	apiBase := s.apiURL()
	var objects []Object
	pageToken := ""

	for {
		listURL := fmt.Sprintf("%s/b/%s/o?prefix=%s",
			apiBase,
			url.PathEscape(s.bucket),
			url.QueryEscape(prefix),
		)
		if pageToken != "" {
			listURL += "&pageToken=" + url.QueryEscape(pageToken)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, listURL, nil)
		if err != nil {
			return nil, fmt.Errorf("gcs: creating list request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("gcs: list request failed: %w", err)
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("gcs: reading list response: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("gcs: list returned HTTP %d: %s", resp.StatusCode, string(body))
		}

		var listResp struct {
			Items []struct {
				Name string `json:"name"`
				Size string `json:"size"`
			} `json:"items"`
			NextPageToken string `json:"nextPageToken"`
		}
		if err := json.Unmarshal(body, &listResp); err != nil {
			return nil, fmt.Errorf("gcs: parsing list response: %w", err)
		}

		for _, item := range listResp.Items {
			objects = append(objects, Object{
				Key: item.Name,
			})
		}

		if listResp.NextPageToken == "" {
			break
		}
		pageToken = listResp.NextPageToken
	}

	return objects, nil
}

// resolveToken returns a valid GCS access token, refreshing if expired.
func (s *gcsStore) resolveToken() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.token != "" && time.Now().Before(s.expiry) {
		return s.token, nil
	}

	token, ttl, err := s.tokenFetcher(s.httpClient)
	if err != nil {
		return "", err
	}
	s.token = token
	s.expiry = time.Now().Add(ttl - 5*time.Minute) // refresh 5 min early
	return s.token, nil
}

// fetchGCSToken queries the GCP metadata server for an access token.
func fetchGCSToken(client *http.Client) (string, time.Duration, error) {
	req, err := http.NewRequest(http.MethodGet, gcsMetadataURL, nil)
	if err != nil {
		return "", 0, fmt.Errorf("creating metadata request: %w", err)
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("metadata server unreachable: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, fmt.Errorf("reading metadata response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("metadata server returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", 0, fmt.Errorf("parsing metadata token: %w", err)
	}

	ttl := time.Duration(tokenResp.ExpiresIn) * time.Second
	if ttl == 0 {
		ttl = 1 * time.Hour // default
	}

	return tokenResp.AccessToken, ttl, nil
}

// uploadURL returns the GCS upload API base.
func (s *gcsStore) uploadURL() string {
	if s.baseURL != "" {
		return s.baseURL
	}
	return gcsUploadURL
}

// apiURL returns the GCS metadata/list API base.
func (s *gcsStore) apiURL() string {
	if s.baseURL != "" {
		return s.baseURL
	}
	return gcsAPIURL
}

// parseBucketURL extracts the bucket name and optional prefix from a gs:// or s3:// URI.
func parseBucketURL(bucketURL string) (bucket, prefix string) {
	bucketURL = strings.TrimPrefix(bucketURL, "gs://")
	bucketURL = strings.TrimPrefix(bucketURL, "s3://")
	parts := strings.SplitN(bucketURL, "/", 2)
	bucket = parts[0]
	if len(parts) > 1 {
		prefix = strings.TrimSuffix(parts[1], "/")
	}
	return bucket, prefix
}
