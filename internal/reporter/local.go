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

	"github.com/alibkaba/jula-core/pkg/crypto"
	"github.com/alibkaba/jula-core/pkg/types"
	"github.com/alibkaba/jula-evidence-collector/pkg/logging"
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

		sanitizedSCFID := filepath.Base(ev.SCFID)
		sanitizedErlID := filepath.Base(ev.ErlID)
		sanitizedProvider := filepath.Base(ev.Finding.Provider)
		sanitizedSourceID := filepath.Base(ev.SourceID)

		// Build the SCF-based directory path.
		dirPath := filepath.Join(r.OutputDir, runDate, "evidence", sanitizedSCFID)
		if err := os.MkdirAll(dirPath, 0700); err != nil {
			return nil, fmt.Errorf("creating directory %s: %w", dirPath, err)
		}

		// Marshal the evidence for storage.
		data, err := json.MarshalIndent(ev, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("marshalling evidence for %s: %w", ev.ErlID, err)
		}

		// Predictable namespace filename
		fileName := fmt.Sprintf("%s_%s_%s.json", sanitizedErlID, sanitizedProvider, sanitizedSourceID)
		filePath := filepath.Join(dirPath, fileName)

		if err := os.WriteFile(filePath, data, 0600); err != nil {
			return nil, fmt.Errorf("writing evidence file: %w", err)
		}

		// Generate and sign provenance sidecar
		provFileName := fmt.Sprintf("%s_%s_%s.prov.json", sanitizedErlID, sanitizedProvider, sanitizedSourceID)
		provFilePath := filepath.Join(dirPath, provFileName)

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

		if err := os.WriteFile(provFilePath, provData, 0600); err != nil {
			return nil, fmt.Errorf("writing provenance file: %w", err)
		}

		// Record evidence in manifest.
		relativePath := filepath.Join(runDate, "evidence", sanitizedSCFID, fileName)
		manifest.EvidenceFiles = append(manifest.EvidenceFiles, types.FileChecksum{
			Path:   relativePath,
			SHA256: crypto.HashFile(data),
		})

		// Record provenance in manifest.
		provRelativePath := filepath.Join(runDate, "evidence", sanitizedSCFID, provFileName)
		manifest.EvidenceFiles = append(manifest.EvidenceFiles, types.FileChecksum{
			Path:   provRelativePath,
			SHA256: crypto.HashFile(provData),
		})

		slog.Debug("reporter: wrote evidence and provenance files",
			"path", filePath,
			"prov_path", provFilePath,
			"scf_id", ev.SCFID,
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

	// Capture and write the execution trace log.
	var logData []byte
	if globalHandler := logging.GetGlobalHandler(); globalHandler != nil {
		var err error
		logData, err = globalHandler.GzipBytes()
		if err != nil {
			slog.Warn("failed to compress execution trace log", "error", err)
		}
	}
	if len(logData) > 0 {
		runDir := filepath.Join(r.OutputDir, runDate)
		if err := os.MkdirAll(runDir, 0700); err != nil {
			return nil, fmt.Errorf("creating run root directory: %w", err)
		}
		logPath := filepath.Join(runDir, "run.log.gz")
		if err := os.WriteFile(logPath, logData, 0600); err != nil {
			return nil, fmt.Errorf("writing execution trace log: %w", err)
		}
		// Record run.log.gz in manifest.
		logRelativePath := filepath.Join(runDate, "run.log.gz")
		manifest.EvidenceFiles = append(manifest.EvidenceFiles, types.FileChecksum{
			Path:   logRelativePath,
			SHA256: crypto.HashFile(logData),
		})
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
