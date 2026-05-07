package filedrop

import (
	"context"
	"io"
)

// StorageReader abstracts cloud storage interactions for reading files from
// a bucket. Implementations exist for AWS S3, GCS, and Azure Blob Storage.
type StorageReader interface {
	// ListFiles returns the keys of all files under the given prefix.
	ListFiles(ctx context.Context, prefix string) ([]string, error)

	// GetFile returns the file contents as a reader, along with provider-specific
	// metadata (e.g., content-type, etag). The caller is responsible for closing
	// the returned ReadCloser.
	GetFile(ctx context.Context, key string) (io.ReadCloser, map[string]string, error)
}
