package reporter

import (
	bytes "bytes"
	context "context"
	stdcrypto "crypto"
	json "encoding/json"
	fmt "fmt"
	"log/slog"
	http "net/http"
	url "net/url"
	os "os"
	filepath "path/filepath"
	strings "strings"
	time "time"

	"github.com/alibkaba/jula-core/pkg/crypto"
	"github.com/alibkaba/jula-evidence-collector/pkg/logging"
	"github.com/alibkaba/jula-core/pkg/types"
)

// TokenProvider abstracts how the GCS reporter obtains an OAuth2 access token.
// This allows injection of the GCP provider's tokenSource or the metadata server.
type TokenProvider interface {
	Token() (string, error)
}

// GCSReporter writes evidence artifacts to a Google Cloud Storage bucket.
type GCSReporter struct {
	BucketName    string
	SigningKey    stdcrypto.Signer
	HTTPClient    *http.Client
	TokenProvider TokenProvider
	// baseURL allows overriding the GCS API endpoint for testing.
	baseURL string
}

const gcsUploadURL = "https://storage.googleapis.com/upload/storage/v1"
const gcsAPIURL = "https://storage.googleapis.com/storage/v1"

// Name returns the reporter identifier.
func (r *GCSReporter) Name() string {
	return "gcs"
}

// Validate checks that the bucket exists and the credentials have write access.
func (r *GCSReporter) Validate(ctx context.Context) error {
	if r.BucketName == "" {
		return fmt.Errorf("bucket name is required")
	}
	if r.SigningKey == nil {
		return fmt.Errorf("JULA_SIGNING_KEY is required for manifest signing")
	}
	if r.TokenProvider == nil {
		return fmt.Errorf("token provider is required")
	}

	// Probe the bucket to verify it exists and the credentials have access.
	apiBase := r.gcsAPIURL()
	bucketURL := fmt.Sprintf("%s/b/%s?fields=name", apiBase, url.PathEscape(r.BucketName))

	token, err := r.TokenProvider.Token()
	if err != nil {
		return fmt.Errorf("obtaining token for bucket validation: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, bucketURL, nil)
	if err != nil {
		return fmt.Errorf("creating bucket probe request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := r.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("bucket probe failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("bucket %q does not exist", r.BucketName)
	}
	if resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("insufficient permissions on bucket %q (ensure the service account has roles/storage.objectAdmin)", r.BucketName)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bucket probe returned HTTP %d", resp.StatusCode)
	}

	slog.Info("gcs: bucket validated", "bucket", r.BucketName)
	return nil
}

// Deliver formats, signs, and uploads evidence to the GCS bucket.
// Object path structure: {runDate}/evidence/{erl_id}/{hash}.json
//
// This routing is purely ERL-based. There are no framework or criteria paths.
func (r *GCSReporter) Deliver(ctx context.Context, evidence []types.Evidence, runID string) (*types.Manifest, error) {
	runDate := time.Now().UTC().Format("2006-01-02")
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
			return nil, fmt.Errorf("marshalling evidence for %s: %w", ev.ErlID, err)
		}

		sanitizedSCFID := filepath.Base(ev.SCFID)
		sanitizedErlID := filepath.Base(ev.ErlID)
		sanitizedProvider := filepath.Base(ev.Finding.Provider)
		sanitizedSourceID := filepath.Base(ev.SourceID)

		// Predictable namespace filename
		fileName := fmt.Sprintf("%s_%s_%s.json", sanitizedErlID, sanitizedProvider, sanitizedSourceID)
		objectName := fmt.Sprintf("%s/evidence/%s/%s", runDate, sanitizedSCFID, fileName)

		if err := r.uploadObject(ctx, objectName, data, "application/json"); err != nil {
			return nil, fmt.Errorf("uploading evidence %s: %w", objectName, err)
		}

		// Generate, sign, and upload provenance sidecar
		prov := &crypto.Provenance{
			ErlID:       ev.ErlID,
			Provider:    ev.Finding.Provider,
			SourceID:    ev.SourceID,
			PayloadHash: ev.PayloadHash,
			Timestamp:   time.Now().UTC(),
			ExtractionMetadata: map[string]string{
				"iam_identity": os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"),
				"api_endpoint": ev.Finding.Provider,
			},
		}

		if err := crypto.SignProvenance(prov, r.SigningKey); err != nil {
			return nil, fmt.Errorf("signing provenance for %s: %w", ev.ErlID, err)
		}

		provData, err := json.MarshalIndent(prov, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("marshalling provenance for %s: %w", ev.ErlID, err)
		}

		provFileName := fmt.Sprintf("%s_%s_%s.prov.json", sanitizedErlID, sanitizedProvider, sanitizedSourceID)
		provObjectName := fmt.Sprintf("%s/evidence/%s/%s", runDate, sanitizedSCFID, provFileName)

		if err := r.uploadObject(ctx, provObjectName, provData, "application/json"); err != nil {
			return nil, fmt.Errorf("uploading provenance %s: %w", provObjectName, err)
		}

		manifest.EvidenceFiles = append(manifest.EvidenceFiles, types.FileChecksum{
			Path:   objectName,
			SHA256: crypto.HashFile(data),
		})

		manifest.EvidenceFiles = append(manifest.EvidenceFiles, types.FileChecksum{
			Path:   provObjectName,
			SHA256: crypto.HashFile(provData),
		})

		slog.Debug("gcs: uploaded evidence and provenance",
			"object", objectName,
			"prov_object", provObjectName,
			"scf_id", sanitizedSCFID,
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
		logObject := fmt.Sprintf("%s/run.log.gz", runDate)
		if err := r.uploadObject(ctx, logObject, logData, "application/gzip"); err != nil {
			return nil, fmt.Errorf("uploading execution trace log %s: %w", logObject, err)
		}
		// Record run.log.gz in manifest.
		manifest.EvidenceFiles = append(manifest.EvidenceFiles, types.FileChecksum{
			Path:   logObject,
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

	manifestObject := fmt.Sprintf("%s/manifest.json", runDate)
	if err := r.uploadObject(ctx, manifestObject, manifestData, "application/json"); err != nil {
		return nil, fmt.Errorf("uploading manifest: %w", err)
	}

	slog.Info("gcs: delivery complete",
		"run_id", runID,
		"bucket", r.BucketName,
		"evidence_files", len(manifest.EvidenceFiles),
		"manifest_object", manifestObject,
	)

	return manifest, nil
}

// uploadObject uploads raw bytes to a GCS object using the JSON API's simple upload.
func (r *GCSReporter) uploadObject(ctx context.Context, objectName string, data []byte, contentType string) error {
	token, err := r.TokenProvider.Token()
	if err != nil {
		return fmt.Errorf("obtaining token: %w", err)
	}

	uploadBase := r.gcsUploadURL()
	uploadURL := fmt.Sprintf("%s/b/%s/o?uploadType=media&name=%s",
		uploadBase,
		url.PathEscape(r.BucketName),
		url.QueryEscape(objectName),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uploadURL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("creating upload request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", contentType)

	resp, err := r.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("upload request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GCS upload returned HTTP %d", resp.StatusCode)
	}

	return nil
}

// gcsUploadURL returns the upload API base, allowing test overrides.
func (r *GCSReporter) gcsUploadURL() string {
	if r.baseURL != "" {
		return r.baseURL
	}
	return gcsUploadURL
}

// gcsAPIURL returns the metadata API base, allowing test overrides.
func (r *GCSReporter) gcsAPIURL() string {
	if r.baseURL != "" {
		return r.baseURL
	}
	return gcsAPIURL
}

// ParseBucketName extracts the bucket name from a gs:// URI or raw name.
func ParseBucketName(path string) string {
	return strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(path), "gs://"), "/")
}
