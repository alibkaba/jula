// Package objstore defines a cloud-agnostic interface for object storage operations.
// Implementations exist for GCS, S3, and local filesystem. New providers can be
// added by implementing the Store interface and registering a URL scheme in the factory.
package objstore

import (
	"context"
	"io"
)

// Object represents a stored object's metadata.
type Object struct {
	Key  string
	Size int64
}

// Writer uploads objects to cloud storage.
type Writer interface {
	// Put uploads the content from body as an object identified by key.
	Put(ctx context.Context, key string, body io.Reader, contentType string) error
}

// Reader reads objects from cloud storage.
type Reader interface {
	// Get retrieves the object identified by key. The caller must close the returned ReadCloser.
	Get(ctx context.Context, key string) (io.ReadCloser, error)

	// List returns all objects matching the given key prefix.
	List(ctx context.Context, prefix string) ([]Object, error)
}

// Store combines read and write operations on a single bucket or container.
type Store interface {
	Writer
	Reader

	// Bucket returns the bucket or container name this store operates on.
	Bucket() string
}
