package reporter

import (
	context "context"
	stdcrypto "crypto"
	json "encoding/json"
	fmt "fmt"
	"log/slog"
	os "os"
	filepath "path/filepath"
	time "time"

	"github.com/alibkaba/jula-evidence-collector/pkg/crypto"
	"github.com/alibkaba/jula-evidence-collector/pkg/types"
)

// LocalReporter writes evidence artifacts to the local filesystem.
// Intended for development, testing, and local validation.
type LocalReporter struct {
	OutputDir  string
	SigningKey stdcrypto.Signer
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
// Directory structure: {output_dir}/{run_date}/evidence/{erl_id}/{hash}.json
//
// This routing is purely ERL-based. There are no framework or criteria directories.
func (r *LocalReporter) Deliver(ctx context.Context, evidence []types.Evidence, runID string) (*types.Manifest, error) {
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

		sanitizedErlID := filepath.Base(ev.ErlID)

		// Build the ERL-based directory path.
		dirPath := filepath.Join(r.OutputDir, runDate, "evidence", sanitizedErlID)
		if err := os.MkdirAll(dirPath, 0700); err != nil {
			return nil, fmt.Errorf("creating directory %s: %w", dirPath, err)
		}

		// Marshal the evidence for storage.
		data, err := json.MarshalIndent(ev, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("marshalling evidence for %s: %w", ev.ErlID, err)
		}

		// Use the payload hash as the filename for immutability.
		sanitizedProvider := filepath.Base(ev.Finding.Provider)
		fileName := fmt.Sprintf("%s_%s.json", sanitizedProvider, ev.PayloadHash)
		filePath := filepath.Join(dirPath, fileName)

		if err := os.WriteFile(filePath, data, 0600); err != nil {
			return nil, fmt.Errorf("writing evidence file: %w", err)
		}

		// Record in manifest.
		relativePath := filepath.Join(runDate, "evidence", sanitizedErlID, fileName)
		manifest.EvidenceFiles = append(manifest.EvidenceFiles, types.FileChecksum{
			Path:   relativePath,
			SHA256: crypto.HashFile(data),
		})

		slog.Debug("reporter: wrote evidence file",
			"path", filePath,
			"erl_id", ev.ErlID,
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
	if err := os.WriteFile(manifestPath, manifestData, 0600); err != nil {
		return nil, fmt.Errorf("writing manifest: %w", err)
	}

	slog.Info("reporter: delivery complete",
		"run_id", runID,
		"evidence_files", len(manifest.EvidenceFiles),
		"manifest_path", manifestPath,
	)

	return manifest, nil
}
