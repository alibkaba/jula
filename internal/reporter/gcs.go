package reporter

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/alibkaba/jula-evidence-collector/pkg/crypto"
	"github.com/alibkaba/jula-evidence-collector/pkg/types"
)

// TokenProvider abstracts how the GCS reporter obtains an OAuth2 access token.
// This allows injection of the GCP provider's tokenSource or the metadata server.
type TokenProvider interface {
	Token() (string, error)
}

// GCSReporter writes evidence artifacts to a Google Cloud Storage bucket.
type GCSReporter struct {
	BucketName       string
	SigningKey       *ecdsa.PrivateKey
	HTTPClient       *http.Client
	TokenProvider    TokenProvider
	Format           string
	ConsolidatedOnly bool
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
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("bucket probe returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	slog.Info("gcs: bucket validated", "bucket", r.BucketName)
	return nil
}

// Deliver formats, signs, and uploads evidence to the GCS bucket.
// Object path structure: {runDate}/{framework}/{criteria_id}/{finding_id}.json
func (r *GCSReporter) Deliver(ctx context.Context, evidence []types.Evidence, runID string) (*types.Manifest, error) {
	runDate := time.Now().UTC().Format("2006-01-02")
	manifest := &types.Manifest{
		RunID:     runID,
		Timestamp: time.Now().UTC(),
	}

	providerSet := make(map[string]bool)
	frameworkSet := make(map[string]bool)

	for _, ev := range evidence {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("context cancelled during delivery: %w", ctx.Err())
		default:
		}

		providerSet[ev.Finding.Provider] = true
		frameworkSet[ev.Framework] = true

		criteria := ev.Criteria
		if len(criteria) == 0 {
			criteria = []string{"unmapped"}
		}

		if !r.ConsolidatedOnly {
			data, err := json.MarshalIndent(ev, "", "  ")
			if err != nil {
				return nil, fmt.Errorf("marshalling evidence: %w", err)
			}

			for _, criterion := range criteria {
				safeResource := SanitizeResourceID(ev.Finding.ResourceIdentifier)
				objectName := fmt.Sprintf("%s/%s/%s/%s_%s_%s.json", runDate, ev.Framework, criterion, ev.Finding.ID, safeResource, runID)

				if err := r.uploadObject(ctx, objectName, data, "application/json"); err != nil {
					return nil, fmt.Errorf("uploading evidence %s: %w", objectName, err)
				}

				manifest.EvidenceFiles = append(manifest.EvidenceFiles, types.FileChecksum{
					Path:   objectName,
					SHA256: crypto.HashFile(data),
				})

				slog.Debug("gcs: uploaded evidence",
					"object", objectName,
					"finding_id", ev.Finding.ID,
					"criteria", criterion,
				)
			}
		}
	}

	// Generate a consolidated JSON file for each framework
	for f := range frameworkSet {
		var frameworkEvidence []types.Evidence
		for _, ev := range evidence {
			if ev.Framework == f {
				frameworkEvidence = append(frameworkEvidence, ev)
			}
		}

		aggregateData, err := json.MarshalIndent(frameworkEvidence, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("marshalling aggregate evidence: %w", err)
		}

		fileName := fmt.Sprintf("%s_all_controls.json", f)
		objectName := fmt.Sprintf("%s/%s/%s", runDate, f, fileName)
		if err := r.uploadObject(ctx, objectName, aggregateData, "application/json"); err != nil {
			return nil, fmt.Errorf("uploading aggregate evidence %s: %w", objectName, err)
		}

		manifest.EvidenceFiles = append(manifest.EvidenceFiles, types.FileChecksum{
			Path:   objectName,
			SHA256: crypto.HashFile(aggregateData),
		})

		slog.Debug("gcs: uploaded consolidated framework evidence", "object", objectName)
	}

	// Generate CSV Ledger
	csvData, err := FormatCSVReport(evidence, runDate, runID)
	if err != nil {
		return nil, fmt.Errorf("formatting csv report: %w", err)
	}
	csvObjectName := fmt.Sprintf("%s/evidence_ledger.csv", runDate)
	if err := r.uploadObject(ctx, csvObjectName, csvData, "text/csv"); err != nil {
		return nil, fmt.Errorf("uploading csv report: %w", err)
	}
	manifest.EvidenceFiles = append(manifest.EvidenceFiles, types.FileChecksum{
		Path:   csvObjectName,
		SHA256: crypto.HashFile(csvData),
	})

	// Optional: Generate Markdown evidence portfolio.
	if r.Format == "markdown" {
		report, err := FormatMarkdownReport(evidence)
		if err != nil {
			return nil, fmt.Errorf("generating markdown report: %w", err)
		}

		reportObject := fmt.Sprintf("%s/evidence_portfolio.md", runDate)
		if err := r.uploadObject(ctx, reportObject, []byte(report), "text/markdown"); err != nil {
			return nil, fmt.Errorf("uploading markdown report: %w", err)
		}

		manifest.EvidenceFiles = append(manifest.EvidenceFiles, types.FileChecksum{
			Path:   reportObject,
			SHA256: crypto.HashFile([]byte(report)),
		})
	}

	// Populate manifest metadata.
	for p := range providerSet {
		manifest.Providers = append(manifest.Providers, p)
	}
	for f := range frameworkSet {
		manifest.Frameworks = append(manifest.Frameworks, f)
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
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GCS upload returned HTTP %d: %s", resp.StatusCode, string(body))
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
	path = strings.TrimSpace(path)
	path = strings.TrimPrefix(path, "gs://")
	path = strings.TrimSuffix(path, "/")
	return path
}
