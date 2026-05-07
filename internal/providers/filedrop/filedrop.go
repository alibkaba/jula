package filedrop

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/alibkaba/jula-evidence-collector/internal/providers"
	"github.com/alibkaba/jula-evidence-collector/pkg/types"
)

// hashableExtensions defines file types processed via cryptographic hashing
// (Path B). These files are treated as opaque artifacts whose contents are
// never parsed.
var hashableExtensions = map[string]bool{
	".pdf": true,
	".csv": true,
	".txt": true,
	".md":  true,
}

// parsableExtensions defines file types that are parsed and validated against
// a known schema (Path A).
var parsableExtensions = map[string]bool{
	".json": true,
}

// FileDropProvider implements the providers.Provider interface for Bring Your
// Own Evidence (BYOE) scenarios. It reads files from a cloud storage bucket
// and produces Findings via one of two processing paths:
//
//   - Path A (Parsed): JSON files are decoded and validated against a schema.
//   - Path B (Hashed): PDF, CSV, TXT, and MD files are treated as opaque
//     artifacts. A SHA-256 hash is computed to prove existence and integrity.
type FileDropProvider struct {
	BucketName    string
	Prefix        string
	StorageClient StorageReader
}

// Name returns the provider identifier used in CLI flags and the registry.
func (p *FileDropProvider) Name() string {
	return "filedrop"
}

// Validate checks that the provider is configured correctly.
func (p *FileDropProvider) Validate() error {
	if p.BucketName == "" {
		return fmt.Errorf("filedrop: bucket name is required")
	}
	if p.StorageClient == nil {
		return fmt.Errorf("filedrop: storage client is required")
	}
	return nil
}

// Extract scans the configured bucket prefix, routes each file through the
// appropriate processing path, and returns a slice of Findings.
func (p *FileDropProvider) Extract(ctx context.Context, runID string) ([]types.Finding, error) {
	keys, err := p.StorageClient.ListFiles(ctx, p.Prefix)
	if err != nil {
		return nil, fmt.Errorf("filedrop: listing files in %s/%s: %w", p.BucketName, p.Prefix, err)
	}

	if len(keys) == 0 {
		slog.Warn("filedrop: no files found in bucket prefix",
			"bucket", p.BucketName,
			"prefix", p.Prefix,
		)
		return nil, nil
	}

	var findings []types.Finding

	for _, key := range keys {
		ext := strings.ToLower(filepath.Ext(key))

		switch {
		case parsableExtensions[ext]:
			f, err := p.processJSON(ctx, key, runID)
			if err != nil {
				slog.Error("filedrop: failed to process JSON file",
					"key", key,
					"error", err,
				)
				findings = append(findings, types.Finding{
					ID:        fmt.Sprintf("filedrop.parse_error.%s", filepath.Base(key)),
					Provider:  "filedrop",
					Resource:  key,
					Check:     "byoe.schema_validation",
					Status:    "ERROR",
					Timestamp: time.Now().UTC(),
					RunID:     runID,
				})
				continue
			}
			findings = append(findings, f...)

		case hashableExtensions[ext]:
			f, err := p.processHashable(ctx, key, runID)
			if err != nil {
				slog.Error("filedrop: failed to hash file",
					"key", key,
					"error", err,
				)
				findings = append(findings, types.Finding{
					ID:        fmt.Sprintf("filedrop.hash_error.%s", filepath.Base(key)),
					Provider:  "filedrop",
					Resource:  key,
					Check:     "byoe.file_hash",
					Status:    "ERROR",
					Timestamp: time.Now().UTC(),
					RunID:     runID,
				})
				continue
			}
			findings = append(findings, f)

		default:
			slog.Warn("filedrop: skipping unsupported file extension",
				"key", key,
				"extension", ext,
			)
		}
	}

	return findings, nil
}

// processJSON reads and decodes a JSON file from the bucket, validates its
// basic structure, and returns Findings with the parsed payload.
func (p *FileDropProvider) processJSON(ctx context.Context, key string, runID string) ([]types.Finding, error) {
	reader, _, err := p.StorageClient.GetFile(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("fetching file %s: %w", key, err)
	}
	defer reader.Close()

	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("reading file %s: %w", key, err)
	}

	// Validate that the payload is well-formed JSON.
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("invalid JSON in %s: %w", key, err)
	}

	// Compute hash for integrity regardless of path.
	hash := sha256.Sum256(data)

	// Determine the finding type from the JSON payload if present.
	findingType := "byoe.generic_json"
	if _, ok := payload["scan_id"]; ok {
		findingType = "byoe.vulnerability_scan"
	}

	finding := types.Finding{
		ID:       fmt.Sprintf("filedrop.%s.%s", findingType, filepath.Base(key)),
		Provider: "filedrop",
		Resource: key,
		Check:    findingType,
		Status:   "PASS",
		RawPayload: map[string]any{
			"parsed_data": payload,
			"sha256_hash": hex.EncodeToString(hash[:]),
			"file_size":   len(data),
		},
		Timestamp: time.Now().UTC(),
		RunID:     runID,
	}

	return []types.Finding{finding}, nil
}

// processHashable reads a file from the bucket, computes its SHA-256 hash,
// and returns a Finding that proves the file's existence and integrity
// without parsing or reading the contents semantically.
func (p *FileDropProvider) processHashable(ctx context.Context, key string, runID string) (types.Finding, error) {
	reader, metadata, err := p.StorageClient.GetFile(ctx, key)
	if err != nil {
		return types.Finding{}, fmt.Errorf("fetching file %s: %w", key, err)
	}
	defer reader.Close()

	hasher := sha256.New()
	size, err := io.Copy(hasher, reader)
	if err != nil {
		return types.Finding{}, fmt.Errorf("hashing file %s: %w", key, err)
	}

	hash := hex.EncodeToString(hasher.Sum(nil))

	rawPayload := map[string]any{
		"sha256_hash": hash,
		"file_size":   size,
		"filename":    filepath.Base(key),
	}

	// Carry forward any provider-supplied metadata (e.g., etag, content-type).
	for k, v := range metadata {
		rawPayload[k] = v
	}

	return types.Finding{
		ID:         fmt.Sprintf("filedrop.document.%s", filepath.Base(key)),
		Provider:   "filedrop",
		Resource:   key,
		Check:      "byoe.document_exists",
		Status:     "PASS",
		RawPayload: rawPayload,
		Timestamp:  time.Now().UTC(),
		RunID:      runID,
	}, nil
}

func init() {
	// The FileDropProvider is not registered globally via init() because it
	// requires runtime configuration (bucket name, storage client). It will
	// be instantiated and registered by the engine when the "filedrop" provider
	// is specified in the config. This init() is a placeholder to satisfy the
	// import pattern.
}

// New creates a configured FileDropProvider ready for use.
func New(bucketName, prefix string, client StorageReader) *FileDropProvider {
	return &FileDropProvider{
		BucketName:    bucketName,
		Prefix:        prefix,
		StorageClient: client,
	}
}

// Ensure FileDropProvider satisfies the Provider interface at compile time.
var _ providers.Provider = (*FileDropProvider)(nil)
