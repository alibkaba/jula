package courier

import (
	"bytes"
	context "context"
	stdcrypto "crypto"
	json "encoding/json"
	fmt "fmt"
	"log/slog"
	os "os"
	filepath "path/filepath"
	"strings"
	time "time"

	"github.com/alibkaba/jula-collector/pkg/logging"
	"github.com/alibkaba/jula-core/pkg/crypto"
	"github.com/alibkaba/jula-core/pkg/objstore"
	"github.com/alibkaba/jula-core/pkg/types"
)

// CloudCourier writes evidence artifacts to any cloud object store (GCS, S3, local).
// It replaces the former GCSReporter and LocalReporter by delegating storage
// to an objstore.Writer while keeping all business logic (signing, provenance,
// manifest generation) in this layer.
type CloudCourier struct {
	Store      objstore.Writer
	SigningKey stdcrypto.Signer
	// PathPrefix is prepended to all object keys (e.g. "deploy-abc/2026-01-15").
	PathPrefix string
}

// Name returns the reporter identifier.
func (r *CloudCourier) Name() string {
	return "cloud"
}

// Validate checks that the reporter is properly configured.
func (r *CloudCourier) Validate(_ context.Context) error {
	if r.Store == nil {
		return fmt.Errorf("object store is required")
	}
	if r.SigningKey == nil {
		return fmt.Errorf("JULA_SIGNING_KEY is required for manifest signing")
	}
	return nil
}

// Deliver formats, signs, and uploads evidence to the object store.
// Object path structure: {pathPrefix}/evidence/{control_id}/{evidence_id}_{provider}_{source_id}.json
func (r *CloudCourier) Deliver(ctx context.Context, evidence []types.Evidence, runID string) (*types.Manifest, error) {
	manifest := &types.Manifest{
		RunID:     runID,
		Timestamp: time.Now().UTC(),
	}

	for _, ev := range evidence {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("context cancelled during delivery: %w", ctx.Err())
		default:
		}

		data, err := json.MarshalIndent(ev, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("marshalling evidence for %s: %w", ev.EvidenceID, err)
		}

		sanitizedControlID := filepath.Base(ev.ControlID)
		sanitizedEvidenceID := filepath.Base(ev.EvidenceID)
		sanitizedProvider := filepath.Base(ev.Finding.Provider)
		sanitizedSourceID := filepath.Base(ev.SourceID)

		// Predictable namespace filename.
		fileName := fmt.Sprintf("%s_%s_%s.json", sanitizedEvidenceID, sanitizedProvider, sanitizedSourceID)
		objectKey := fmt.Sprintf("%s/evidence/%s/%s", r.PathPrefix, sanitizedControlID, fileName)

		if err := r.Store.Put(ctx, objectKey, bytes.NewReader(data), "application/json"); err != nil {
			return nil, fmt.Errorf("uploading evidence %s: %w", objectKey, err)
		}

		// Generate, sign, and upload provenance sidecar.
		prov := &crypto.Provenance{
			EvidenceID:  ev.EvidenceID,
			Provider:    ev.Finding.Provider,
			SourceID:    ev.SourceID,
			PayloadHash: ev.PayloadHash,
			Timestamp:   time.Now().UTC(),
			ExtractionMetadata: map[string]string{
				"api_endpoint": ev.Finding.Provider,
			},
		}

		if err := crypto.SignProvenance(prov, r.SigningKey); err != nil {
			return nil, fmt.Errorf("signing provenance for %s: %w", ev.EvidenceID, err)
		}

		provData, err := json.MarshalIndent(prov, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("marshalling provenance for %s: %w", ev.EvidenceID, err)
		}

		provFileName := fmt.Sprintf("%s_%s_%s.prov.json", sanitizedEvidenceID, sanitizedProvider, sanitizedSourceID)
		provObjectKey := fmt.Sprintf("%s/evidence/%s/%s", r.PathPrefix, sanitizedControlID, provFileName)

		if err := r.Store.Put(ctx, provObjectKey, bytes.NewReader(provData), "application/json"); err != nil {
			return nil, fmt.Errorf("uploading provenance %s: %w", provObjectKey, err)
		}

		manifest.EvidenceFiles = append(manifest.EvidenceFiles, types.FileChecksum{
			Path:   objectKey,
			SHA256: crypto.HashFile(data),
		})
		manifest.EvidenceFiles = append(manifest.EvidenceFiles, types.FileChecksum{
			Path:   provObjectKey,
			SHA256: crypto.HashFile(provData),
		})

		slog.Debug("courier: uploaded evidence and provenance",
			"object", objectKey,
			"prov_object", provObjectKey,
			"control_id", sanitizedControlID,
		)
	}

	// Populate manifest metadata.
	providerSet := make(map[string]bool)
	for _, ev := range evidence {
		providerSet[ev.Finding.Provider] = true
	}
	for p := range providerSet {
		manifest.Providers = append(manifest.Providers, p)
	}

	// Capture and upload the execution trace log.
	var logData []byte
	if globalHandler := logging.GetGlobalHandler(); globalHandler != nil {
		var err error
		logData, err = globalHandler.GzipBytes()
		if err != nil {
			slog.Warn("failed to compress execution trace log", "error", err)
		}
	}
	if len(logData) > 0 {
		logKey := fmt.Sprintf("%s/run.log.gz", r.PathPrefix)
		if err := r.Store.Put(ctx, logKey, bytes.NewReader(logData), "application/gzip"); err != nil {
			return nil, fmt.Errorf("uploading execution trace log %s: %w", logKey, err)
		}
		manifest.EvidenceFiles = append(manifest.EvidenceFiles, types.FileChecksum{
			Path:   logKey,
			SHA256: crypto.HashFile(logData),
		})
	}

	// Sign the manifest.
	if err := crypto.SignManifest(manifest, r.SigningKey); err != nil {
		return nil, fmt.Errorf("signing manifest: %w", err)
	}

	// Upload the signed manifest.
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshalling manifest: %w", err)
	}

	manifestKey := fmt.Sprintf("%s/manifest.json", r.PathPrefix)
	if err := r.Store.Put(ctx, manifestKey, bytes.NewReader(manifestData), "application/json"); err != nil {
		return nil, fmt.Errorf("uploading manifest: %w", err)
	}

	slog.Info("courier: delivery complete",
		"run_id", runID,
		"evidence_files", len(manifest.EvidenceFiles),
		"manifest_key", manifestKey,
	)

	return manifest, nil
}

// ParseOutputURL extracts the bucket URL and path prefix from an output URL.
// For gs:// and s3:// URLs, it appends the deployment ID and date.
// For local paths, it returns the path as-is with a date-based subdirectory.
func ParseOutputURL(outputURL string) (bucketURL string, pathPrefix string, err error) {
	deployID := os.Getenv("JULA_DEPLOYMENT_ID")
	if deployID == "" {
		return "", "", fmt.Errorf("JULA_DEPLOYMENT_ID environment variable is required")
	}
	runDate := time.Now().UTC().Format("2006-01-02")

	if strings.HasPrefix(outputURL, "gs://") || strings.HasPrefix(outputURL, "s3://") {
		// Cloud storage: extract bucket name from URL.
		trimmed := strings.TrimPrefix(strings.TrimPrefix(outputURL, "gs://"), "s3://")
		bucket := strings.SplitN(trimmed, "/", 2)[0]
		scheme := outputURL[:5] // "gs://" or "s3://"
		bucketURL = scheme + bucket
		pathPrefix = fmt.Sprintf("deploy-%s/%s", deployID, runDate)
		return bucketURL, pathPrefix, nil
	}

	// Local filesystem.
	bucketURL = outputURL
	pathPrefix = runDate
	return bucketURL, pathPrefix, nil
}
