package reporter

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/alibkaba/jula-evidence-collector/pkg/crypto"
	"github.com/alibkaba/jula-evidence-collector/pkg/types"
)

// LocalReporter writes evidence artifacts to the local filesystem.
// Intended for development, testing, and local validation.
type LocalReporter struct {
	OutputDir  string
	SigningKey *ecdsa.PrivateKey
}

// Name returns the reporter identifier.
func (r *LocalReporter) Name() string {
	return "local"
}

// Validate checks that the output directory is writable.
func (r *LocalReporter) Validate(ctx context.Context) error {
	if r.OutputDir == "" {
		return fmt.Errorf("output directory is required")
	}
	if r.SigningKey == nil {
		return fmt.Errorf("JULA_SIGNING_KEY is required for manifest signing")
	}
	return nil
}

// Deliver writes each evidence artifact as a JSON file and generates a signed manifest.
// Directory structure: {output_dir}/{run_date}/{framework}/{criteria_id}/{finding_id}.json
func (r *LocalReporter) Deliver(ctx context.Context, evidence []types.Evidence, runID string) (*types.Manifest, error) {
	runDate := time.Now().UTC().Format("2006-01-02")
	manifest := &types.Manifest{
		RunID:     runID,
		Timestamp: time.Now().UTC(),
	}

	// Track unique providers and frameworks for the manifest.
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

		// Write evidence to each criteria directory it maps to.
		criteria := ev.Criteria
		if len(criteria) == 0 {
			criteria = []string{"unmapped"}
		}

		for _, criterion := range criteria {
			dirPath := filepath.Join(r.OutputDir, runDate, ev.Framework, criterion)
			if err := os.MkdirAll(dirPath, 0755); err != nil {
				return nil, fmt.Errorf("creating directory %s: %w", dirPath, err)
			}

			// Use runID to guarantee unique filenames and prevent overwriting
			fileName := fmt.Sprintf("%s_%s.json", ev.Finding.ID, runID)
			filePath := filepath.Join(dirPath, fileName)

			data, err := json.MarshalIndent(ev, "", "  ")
			if err != nil {
				return nil, fmt.Errorf("marshalling evidence: %w", err)
			}

			if err := os.WriteFile(filePath, data, 0644); err != nil {
				return nil, fmt.Errorf("writing evidence file: %w", err)
			}

			// Compute file hash for manifest.
			relativePath := filepath.Join(runDate, ev.Framework, criterion, fileName)
			manifest.EvidenceFiles = append(manifest.EvidenceFiles, types.FileChecksum{
				Path:   relativePath,
				SHA256: crypto.HashFile(data),
			})

			slog.Debug("reporter: wrote evidence file",
				"path", filePath,
				"finding_id", ev.Finding.ID,
				"criteria", criterion,
			)
		}
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

	// Write manifest to the run root.
	manifestPath := filepath.Join(r.OutputDir, runDate, "manifest.json")
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshalling manifest: %w", err)
	}
	if err := os.WriteFile(manifestPath, manifestData, 0644); err != nil {
		return nil, fmt.Errorf("writing manifest: %w", err)
	}

	slog.Info("reporter: delivery complete",
		"run_id", runID,
		"evidence_files", len(manifest.EvidenceFiles),
		"manifest_path", manifestPath,
	)

	return manifest, nil
}
