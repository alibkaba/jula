package objstore

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// FromURL returns the appropriate Store for a bucket URL.
// Supported URL schemes:
//
//	"gs://bucket"             → GCS Store
//	"gs://bucket/prefix"      → GCS Store (prefix is informational, returned separately)
//	"s3://bucket"             → S3 Store
//	"s3://bucket/prefix"      → S3 Store (prefix is informational, returned separately)
//	"file:///path"            → Local filesystem Store
//	"./relative" or "/abs"    → Local filesystem Store
//
// Returns the Store and the prefix (subfolder path) extracted from the URL.
func FromURL(bucketURL string, httpClient *http.Client) (Store, string, error) {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}

	switch {
	case strings.HasPrefix(bucketURL, "gs://"):
		bucket, prefix := parseBucketURL(bucketURL)
		if bucket == "" {
			return nil, "", fmt.Errorf("invalid GCS URL: bucket name is empty")
		}
		return newgcsStore(bucket, httpClient), prefix, nil

	case strings.HasPrefix(bucketURL, "s3://"):
		bucket, prefix := parseBucketURL(bucketURL)
		if bucket == "" {
			return nil, "", fmt.Errorf("invalid S3 URL: bucket name is empty")
		}
		return news3Store(bucket, "", httpClient), prefix, nil

	case strings.HasPrefix(bucketURL, "file://"):
		path := strings.TrimPrefix(bucketURL, "file://")
		return newlocalStorage(path), "", nil

	default:
		// Treat as a local filesystem path.
		return newlocalStorage(bucketURL), "", nil
	}
}
