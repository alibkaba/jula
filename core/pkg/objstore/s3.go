package objstore

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// S3Store implements Store for AWS S3 using raw HTTP calls with SigV4 signing.
// No AWS SDK dependency. Authentication uses the ECS task role on Fargate
// or static environment variables for local development.
type S3Store struct {
	bucket string
	region string
	client *http.Client
	creds  CredentialProvider

	// baseURL allows overriding the S3 endpoint for testing or S3-compatible services.
	baseURL string
}

// S3Option configures S3Store behavior.
type S3Option func(*S3Store)

// withS3BaseURL overrides the S3 endpoint (for testing or S3-compatible services).
func withS3BaseURL(baseURL string) S3Option {
	return func(s *S3Store) {
		s.baseURL = baseURL
	}
}

// withS3Credentials overrides the default credential provider.
func withS3Credentials(creds CredentialProvider) S3Option {
	return func(s *S3Store) {
		s.creds = creds
	}
}

// newS3Store creates an S3-backed Store for the given bucket and region.
func newS3Store(bucket, region string, httpClient *http.Client, opts ...S3Option) *S3Store {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	if region == "" {
		region = os.Getenv("AWS_DEFAULT_REGION")
		if region == "" {
			region = os.Getenv("AWS_REGION")
			if region == "" {
				region = "us-east-1"
			}
		}
	}

	s := &S3Store{
		bucket: bucket,
		region: region,
		client: httpClient,
		creds:  newECSCredentialProvider(httpClient),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Bucket returns the S3 bucket name.
func (s *S3Store) Bucket() string {
	return s.bucket
}

// Put uploads data to the given object key in the bucket.
func (s *S3Store) Put(ctx context.Context, key string, body io.Reader, contentType string) error {
	data, err := io.ReadAll(body)
	if err != nil {
		return fmt.Errorf("s3: reading body: %w", err)
	}

	endpoint := s.objectURL(key)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("s3: creating put request: %w", err)
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Content-Length", strconv.Itoa(len(data)))

	payloadHash := hashPayload(data)

	if err := s.sign(req, payloadHash); err != nil {
		return err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("s3: put request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("s3: put returned HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// Get retrieves the object identified by key from the bucket.
func (s *S3Store) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	endpoint := s.objectURL(key)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("s3: creating get request: %w", err)
	}

	// GET requests have an empty body.
	payloadHash := hashPayload(nil)

	if err := s.sign(req, payloadHash); err != nil {
		return nil, err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("s3: get request failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("s3: get returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	return resp.Body, nil
}

// List returns all objects matching the given key prefix.
func (s *S3Store) List(ctx context.Context, prefix string) ([]Object, error) {
	var objects []Object
	continuationToken := ""

	for {
		params := url.Values{
			"list-type": {"2"},
			"prefix":    {prefix},
		}
		if continuationToken != "" {
			params.Set("continuation-token", continuationToken)
		}

		endpoint := s.bucketURL() + "?" + params.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, fmt.Errorf("s3: creating list request: %w", err)
		}

		payloadHash := hashPayload(nil)

		if err := s.sign(req, payloadHash); err != nil {
			return nil, err
		}

		resp, err := s.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("s3: list request failed: %w", err)
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("s3: reading list response: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("s3: list returned HTTP %d: %s", resp.StatusCode, string(body))
		}

		var listResp s3ListResponse
		if err := xml.Unmarshal(body, &listResp); err != nil {
			return nil, fmt.Errorf("s3: parsing list response: %w", err)
		}

		for _, item := range listResp.Contents {
			objects = append(objects, Object{
				Key:  item.Key,
				Size: item.Size,
			})
		}

		if !listResp.IsTruncated {
			break
		}
		continuationToken = listResp.NextContinuationToken
	}

	return objects, nil
}

// s3ListResponse models the S3 ListObjectsV2 XML response.
type s3ListResponse struct {
	XMLName               xml.Name       `xml:"ListBucketResult"`
	IsTruncated           bool           `xml:"IsTruncated"`
	NextContinuationToken string         `xml:"NextContinuationToken"`
	Contents              []s3ListObject `xml:"Contents"`
}

type s3ListObject struct {
	Key  string `xml:"Key"`
	Size int64  `xml:"Size"`
}

// sign resolves credentials and signs the request with SigV4.
func (s *S3Store) sign(req *http.Request, payloadHash string) error {
	creds, err := s.creds.Resolve()
	if err != nil {
		return fmt.Errorf("s3: resolving credentials: %w", err)
	}
	signV4(req, creds, s.region, "s3", payloadHash)
	return nil
}

// objectURL returns the full URL for a specific object key.
func (s *S3Store) objectURL(key string) string {
	base := s.bucketURL()
	// S3 path-style: https://s3.region.amazonaws.com/bucket/key
	return base + "/" + key
}

// bucketURL returns the base URL for the bucket.
func (s *S3Store) bucketURL() string {
	if s.baseURL != "" {
		return strings.TrimSuffix(s.baseURL, "/") + "/" + s.bucket
	}
	return fmt.Sprintf("https://s3.%s.amazonaws.com/%s", s.region, s.bucket)
}
