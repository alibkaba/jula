package ingestion

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/alibkaba/jula-evidence-evaluator/pkg/types"
)

const (
	gcsAPIURL     = "https://storage.googleapis.com/storage/v1"
	tokenEndpoint = "https://oauth2.googleapis.com/token"
	metadataURL   = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
)

// GCSReader handles ingestion of compliance artifacts from GCS or local disk.
type GCSReader struct {
	httpClient *http.Client
	token      string
	isLocal    bool
}

// NewGCSReader creates a new GCSReader.
func NewGCSReader(httpClient *http.Client) *GCSReader {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &GCSReader{httpClient: httpClient}
}

// Initialize resolves credentials and checks if we are targetting GCS or local disk.
func (r *GCSReader) Initialize(bucketURL string) error {
	if !strings.HasPrefix(bucketURL, "gs://") {
		r.isLocal = true
		slog.Info("ingestion: target bucket URL is a local directory path", "path", bucketURL)
		return nil
	}

	slog.Info("ingestion: target is Google Cloud Storage", "url", bucketURL)
	token, err := r.resolveToken()
	if err != nil {
		return fmt.Errorf("resolving GCP credentials: %w", err)
	}
	r.token = token
	return nil
}

// ReadManifest fetches and parses the manifest.json file from the bucket run folder.
func (r *GCSReader) ReadManifest(ctx context.Context, bucketURL string) (*types.Manifest, error) {
	if r.isLocal {
		localPath := strings.TrimPrefix(bucketURL, "file://")
		manifestPath := filepath.Join(localPath, "manifest.json")
		slog.Debug("ingestion: reading local manifest", "path", manifestPath)

		data, err := os.ReadFile(manifestPath)
		if err != nil {
			return nil, fmt.Errorf("reading local manifest: %w", err)
		}

		var m types.Manifest
		if err := json.Unmarshal(data, &m); err != nil {
			return nil, fmt.Errorf("parsing local manifest: %w", err)
		}
		return &m, nil
	}

	bucket, folder := parseGCSURL(bucketURL)
	manifestObject := folder + "/manifest.json"
	slog.Info("ingestion: downloading manifest from GCS", "bucket", bucket, "object", manifestObject)

	data, err := r.downloadGCSObject(ctx, bucket, manifestObject)
	if err != nil {
		return nil, fmt.Errorf("downloading GCS manifest: %w", err)
	}

	var m types.Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parsing GCS manifest: %w", err)
	}

	return &m, nil
}

// ReadPayloads downloads the given slice of evidence/provenance files in parallel.
func (r *GCSReader) ReadPayloads(ctx context.Context, bucketURL string, files []types.FileChecksum) (map[string][]byte, error) {
	payloads := make(map[string][]byte)
	var mu sync.Mutex
	var wg sync.WaitGroup

	errs := make(chan error, len(files))
	semaphore := make(chan struct{}, 10) // Limit concurrency to 10 concurrent requests.

	slog.Info("ingestion: launching parallel payload downloads", "file_count", len(files))

	for _, fileChecksum := range files {
		wg.Add(1)
		go func(path string) {
			defer wg.Done()

			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-ctx.Done():
				errs <- ctx.Err()
				return
			}

			var content []byte
			var err error

			if r.isLocal {
				localPath := strings.TrimPrefix(bucketURL, "file://")
				filePath := filepath.Join(localPath, path)
				content, err = os.ReadFile(filePath)
				if err != nil && os.IsNotExist(err) {
					// Fallback: if run folder is duplicated in path, resolve against parent directory
					parentPath := filepath.Dir(localPath)
					filePath = filepath.Join(parentPath, path)
					content, err = os.ReadFile(filePath)
				}
				if err != nil {
					errs <- fmt.Errorf("reading local file %s: %w", path, err)
					return
				}
			} else {
				bucket, _ := parseGCSURL(bucketURL)
				content, err = r.downloadGCSObject(ctx, bucket, path)
				if err != nil {
					errs <- fmt.Errorf("downloading GCS file %s: %w", path, err)
					return
				}
			}

			mu.Lock()
			payloads[path] = content
			mu.Unlock()
		}(fileChecksum.Path)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			return nil, err
		}
	}

	slog.Info("ingestion: successfully ingested all evidence payloads in memory", "count", len(payloads))
	return payloads, nil
}

// downloadGCSObject downloads raw bytes from a GCS object using the GCS JSON API.
func (r *GCSReader) downloadGCSObject(ctx context.Context, bucket string, objectName string) ([]byte, error) {
	downloadURL := fmt.Sprintf("%s/b/%s/o/%s?alt=media",
		gcsAPIURL,
		url.PathEscape(bucket),
		url.PathEscape(objectName),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating GCS HTTP request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+r.token)

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GCS HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GCS API returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	return io.ReadAll(resp.Body)
}

type serviceAccountKey struct {
	Type        string `json:"type"`
	ClientEmail string `json:"client_email"`
	PrivateKey  string `json:"private_key"`
	TokenURI    string `json:"token_uri"`
}

// resolveToken handles local JSON service account credentials or metadata server tokens.
func (r *GCSReader) resolveToken() (string, error) {
	credPath := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	if credPath != "" {
		slog.Info("ingestion: using local service account key file for auth", "path", credPath)
		data, err := os.ReadFile(credPath)
		if err != nil {
			return "", fmt.Errorf("reading service account credentials key: %w", err)
		}

		var key serviceAccountKey
		if err := json.Unmarshal(data, &key); err != nil {
			return "", fmt.Errorf("parsing service account credentials: %w", err)
		}

		block, _ := pem.Decode([]byte(key.PrivateKey))
		if block == nil {
			return "", fmt.Errorf("failed to decode private key PEM block")
		}

		parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("failed to parse PKCS8 key: %w", err)
		}

		rsaKey, ok := parsedKey.(*rsa.PrivateKey)
		if !ok {
			return "", fmt.Errorf("service account key is not an RSA private key")
		}

		tokenURL := tokenEndpoint
		if key.TokenURI != "" {
			tokenURL = key.TokenURI
		}

		return exchangeToken(r.httpClient, &key, rsaKey, tokenURL)
	}

	slog.Info("ingestion: no credential file detected; attempting default metadata server auth")
	return fetchMetadataToken(r.httpClient)
}

// exchangeToken signs a JWT to retrieve an access token from Google OAuth2.
func exchangeToken(client *http.Client, key any, privateKey *rsa.PrivateKey, tokenURL string) (string, error) {
	saKey := key.(*serviceAccountKey)
	now := time.Now()

	header := map[string]string{
		"alg": "RS256",
		"typ": "JWT",
	}
	headerJSON, _ := json.Marshal(header)

	claims := map[string]any{
		"iss":   saKey.ClientEmail,
		"scope": "https://www.googleapis.com/auth/cloud-platform.read-only",
		"aud":   tokenURL,
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	}
	claimsJSON, _ := json.Marshal(claims)

	unsigned := base64.RawURLEncoding.EncodeToString(headerJSON) +
		"." +
		base64.RawURLEncoding.EncodeToString(claimsJSON)

	hashed := sha256.Sum256([]byte(unsigned))
	sig, err := rsa.SignPKCS1v15(nil, privateKey, 0, hashed[:])
	if err != nil {
		return "", fmt.Errorf("signing OAuth JWT: %w", err)
	}

	jwt := unsigned + "." + base64.RawURLEncoding.EncodeToString(sig)

	resp, err := client.PostForm(tokenURL, url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {jwt},
	})
	if err != nil {
		return "", fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading token body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token exchange failed (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("parsing token json: %w", err)
	}

	return tokenResp.AccessToken, nil
}

// fetchMetadataToken queries GCP default metadata server for authentication.
func fetchMetadataToken(client *http.Client) (string, error) {
	req, err := http.NewRequest(http.MethodGet, metadataURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("metadata server unreachable: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("metadata server returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", err
	}

	return tokenResp.AccessToken, nil
}

// parseGCSURL parses bucket and object folder prefix from a gs:// URI.
func parseGCSURL(gcsURL string) (bucket string, folder string) {
	gcsURL = strings.TrimPrefix(gcsURL, "gs://")
	parts := strings.SplitN(gcsURL, "/", 2)
	bucket = parts[0]
	if len(parts) > 1 {
		folder = strings.TrimSuffix(parts[1], "/")
	}
	return bucket, folder
}
