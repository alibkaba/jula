package ingestion

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"sync"

	"github.com/alibkaba/jula-core/pkg/objstore"
	"github.com/alibkaba/jula-core/pkg/types"
)

// CloudReader handles ingestion of compliance artifacts from any cloud
// object store (GCS, S3, local filesystem) via the objstore.Store interface.
// It replaces the former GCSReader.
type CloudReader struct {
	store  objstore.Store
	prefix string
}

// NewCloudReader creates a CloudReader from a bucket URL.
// The URL scheme determines the backend: gs://, s3://, file://, or local path.
func NewCloudReader(bucketURL string) (*CloudReader, error) {
	store, prefix, err := objstore.FromURL(bucketURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating object store from %q: %w", bucketURL, err)
	}
	return &CloudReader{store: store, prefix: prefix}, nil
}

// ReadManifest fetches and parses the manifest.json file from the bucket.
func (r *CloudReader) ReadManifest(ctx context.Context) (*types.Manifest, error) {
	manifestKey := r.prefix + "/manifest.json"
	if r.prefix == "" {
		manifestKey = "manifest.json"
	}

	slog.Info("ingestion: downloading manifest", "key", manifestKey)

	rc, err := r.store.Get(ctx, manifestKey)
	if err != nil {
		return nil, fmt.Errorf("downloading manifest: %w", err)
	}
	defer rc.Close()

	data, err := io.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("reading manifest: %w", err)
	}

	var m types.Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parsing manifest: %w", err)
	}

	return &m, nil
}

// ReadPayloads downloads the given slice of evidence/provenance files in parallel.
func (r *CloudReader) ReadPayloads(ctx context.Context, files []types.FileChecksum) (map[string][]byte, error) {
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

			rc, err := r.store.Get(ctx, path)
			if err != nil {
				errs <- fmt.Errorf("downloading file %s: %w", path, err)
				return
			}
			defer rc.Close()

			content, err := io.ReadAll(rc)
			if err != nil {
				errs <- fmt.Errorf("reading file %s: %w", path, err)
				return
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

// WriteFile writes the data payload to the object store.
func (r *CloudReader) WriteFile(ctx context.Context, fileName string, data []byte) error {
	key := fileName
	if r.prefix != "" {
		key = r.prefix + "/" + fileName
	}

	slog.Info("ingestion: writing file", "key", key)

	return r.store.Put(ctx, key, io.NopCloser(
		bytes.NewReader(data),
	), "application/json")
}
