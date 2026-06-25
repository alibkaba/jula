// Package main provides a CLI tool for signing pre-collected evidence artifacts.
// This enables the "bring your own collector" workflow: users collect evidence
// using any tool (Steampipe, CloudQuery, manual exports), then run jula-sign-evidence
// to cryptographically hash, sign, and upload the artifacts to an object store.
//
// The tool is schema-agnostic: it signs any files in the input directory without
// interpreting their contents. Content validation is the Assessor's responsibility.
package main

import (
	"bytes"
	"context"
	stdcrypto "crypto"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/alibkaba/jula-core/pkg/crypto"
	"github.com/alibkaba/jula-core/pkg/objstore"
	"github.com/alibkaba/jula-core/pkg/schema"
	"github.com/alibkaba/jula-core/pkg/types"
)

func main() {
	input := flag.String("input", "", "Path to directory containing evidence files to sign")
	output := flag.String("output", "", "Destination URL (gs://, s3://, file://, or local path)")
	keyEnv := flag.String("key-env", "JULA_SIGNING_KEY", "Environment variable containing the PEM-encoded ECDSA private key")
	deploymentID := flag.String("deployment-id", "", "Deployment identifier for path namespacing")
	runID := flag.String("run-id", "", "Unique run identifier (auto-generated if empty)")
	provider := flag.String("provider", "external", "Provider name for provenance metadata (e.g., steampipe, cloudquery)")
	noSchema := flag.Bool("no-schema", false, "Skip schema validation (sign any file without checking structure)")
	flag.Parse()

	if *input == "" {
		log.Fatal("--input is required: path to directory containing evidence files")
	}
	if *output == "" {
		log.Fatal("--output is required: destination URL (gs://, s3://, or local path)")
	}

	// Resolve the input directory.
	inputDir, err := filepath.Abs(*input)
	if err != nil {
		log.Fatalf("failed to resolve input path %q: %v", *input, err)
	}
	info, err := os.Stat(inputDir)
	if err != nil {
		log.Fatalf("input directory %q does not exist: %v", inputDir, err)
	}
	if !info.IsDir() {
		log.Fatalf("input path %q is not a directory", inputDir)
	}

	// Load signing key from environment.
	keyPEM := os.Getenv(*keyEnv)
	if keyPEM == "" {
		log.Fatalf("environment variable %s is not set or empty", *keyEnv)
	}
	privKey, err := crypto.ParseECDSAPrivateKey(keyPEM)
	if err != nil {
		log.Fatalf("failed to parse private key from %s: %v", *keyEnv, err)
	}

	// Generate a run ID if not provided.
	effectiveRunID := *runID
	if effectiveRunID == "" {
		effectiveRunID = fmt.Sprintf("sign-%s-%d", time.Now().UTC().Format("20060102-150405"), time.Now().UnixNano()%10000)
	}

	manifest, err := signDirectory(context.Background(), signConfig{
		inputDir:     inputDir,
		outputURL:    *output,
		signingKey:   privKey,
		runID:        effectiveRunID,
		deploymentID: *deploymentID,
		provider:     *provider,
		noSchema:     *noSchema,
	})
	if err != nil {
		log.Fatalf("signing failed: %v", err)
	}

	fmt.Printf("\n[jula-sign-evidence] Delivery complete\n")
	fmt.Printf("  Run ID:         %s\n", manifest.RunID)
	fmt.Printf("  Evidence files: %d\n", len(manifest.EvidenceFiles)/2) // Each file has an evidence + provenance entry.
	fmt.Printf("  Manifest files: %d (evidence + provenance sidecars)\n", len(manifest.EvidenceFiles))
	fmt.Printf("  Manifest sig:   %s\n", manifest.Signature[:32]+"...")
}

// signConfig holds the configuration for a signing run.
type signConfig struct {
	inputDir     string
	outputURL    string
	signingKey   stdcrypto.Signer
	runID        string
	deploymentID string
	provider     string
	noSchema     bool
}

// signDirectory walks inputDir, hashes and signs every file, creates provenance
// sidecars, builds a signed manifest, and uploads everything to the output store.
// This is the core logic extracted from main() for testability.
func signDirectory(ctx context.Context, cfg signConfig) (*types.Manifest, error) {
	// Build the output path prefix.
	pathPrefix := time.Now().UTC().Format("2006-01-02")
	if cfg.deploymentID != "" {
		pathPrefix = fmt.Sprintf("deploy-%s/%s", cfg.deploymentID, pathPrefix)
	}

	// Initialize the object store.
	store, storePrefix, err := objstore.FromURL(cfg.outputURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating object store from %q: %w", cfg.outputURL, err)
	}
	if storePrefix != "" {
		pathPrefix = storePrefix + "/" + pathPrefix
	}

	// Walk the input directory and collect all files.
	var files []fileEntry
	err = filepath.WalkDir(cfg.inputDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}

		relPath, relErr := filepath.Rel(cfg.inputDir, path)
		if relErr != nil {
			return fmt.Errorf("computing relative path for %q: %w", path, relErr)
		}

		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return fmt.Errorf("reading file %q: %w", path, readErr)
		}

		files = append(files, fileEntry{
			relPath: relPath,
			data:    data,
		})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking input directory: %w", err)
	}

	if len(files) == 0 {
		return nil, fmt.Errorf("input directory %q contains no files", cfg.inputDir)
	}

	fmt.Printf("[jula-sign-evidence] Found %d files in %s\n", len(files), cfg.inputDir)
	fmt.Printf("[jula-sign-evidence] Run ID: %s\n", cfg.runID)

	// Schema validation gate: validate JSON evidence files before signing.
	if !cfg.noSchema {
		for _, f := range files {
			if !strings.HasSuffix(strings.ToLower(f.relPath), ".json") {
				continue
			}
			if err := schema.ValidateEvidence(f.data); err != nil {
				return nil, fmt.Errorf("schema validation failed for %q: %w", f.relPath, err)
			}
			fmt.Printf("  ✓ schema valid: %s\n", f.relPath)
		}
	} else {
		fmt.Println("[jula-sign-evidence] Schema validation skipped (--no-schema)")
	}

	// Build the manifest.
	manifest := &types.Manifest{
		RunID:     cfg.runID,
		Timestamp: time.Now().UTC(),
		Providers: []string{cfg.provider},
	}

	// Process each file: upload evidence + generate and upload provenance sidecar.
	for _, f := range files {
		// Upload the evidence file.
		evidenceKey := fmt.Sprintf("%s/evidence/%s", pathPrefix, f.relPath)
		contentType := detectContentType(f.relPath)

		if putErr := store.Put(ctx, evidenceKey, bytes.NewReader(f.data), contentType); putErr != nil {
			return nil, fmt.Errorf("uploading evidence %q: %w", evidenceKey, putErr)
		}

		evidenceHash := crypto.HashFile(f.data)

		// Generate and sign provenance sidecar.
		prov := &crypto.Provenance{
			EvidenceID:  filepath.Base(f.relPath),
			Provider:    cfg.provider,
			SourceID:    cfg.deploymentID,
			PayloadHash: evidenceHash,
			Timestamp:   time.Now().UTC(),
			ExtractionMetadata: map[string]string{
				"source_tool": cfg.provider,
				"input_path":  f.relPath,
			},
		}

		if signErr := crypto.SignProvenance(prov, cfg.signingKey); signErr != nil {
			return nil, fmt.Errorf("signing provenance for %q: %w", f.relPath, signErr)
		}

		provData, marshalErr := json.MarshalIndent(prov, "", "  ")
		if marshalErr != nil {
			return nil, fmt.Errorf("marshalling provenance for %q: %w", f.relPath, marshalErr)
		}

		provKey := fmt.Sprintf("%s/evidence/%s.prov.json", pathPrefix, f.relPath)
		if putErr := store.Put(ctx, provKey, bytes.NewReader(provData), "application/json"); putErr != nil {
			return nil, fmt.Errorf("uploading provenance %q: %w", provKey, putErr)
		}

		// Add both files to the manifest.
		manifest.EvidenceFiles = append(manifest.EvidenceFiles, types.FileChecksum{
			Path:   evidenceKey,
			SHA256: evidenceHash,
		})
		manifest.EvidenceFiles = append(manifest.EvidenceFiles, types.FileChecksum{
			Path:   provKey,
			SHA256: crypto.HashFile(provData),
		})

		fmt.Printf("  ✓ %s (hash: %s)\n", f.relPath, evidenceHash[:16]+"...")
	}

	// Sign the manifest.
	if err := crypto.SignManifest(manifest, cfg.signingKey); err != nil {
		return nil, fmt.Errorf("signing manifest: %w", err)
	}

	// Upload the signed manifest.
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshalling manifest: %w", err)
	}

	manifestKey := fmt.Sprintf("%s/manifest.json", pathPrefix)
	if err := store.Put(ctx, manifestKey, bytes.NewReader(manifestData), "application/json"); err != nil {
		return nil, fmt.Errorf("uploading manifest: %w", err)
	}

	return manifest, nil
}

// fileEntry holds a file's relative path and content.
type fileEntry struct {
	relPath string
	data    []byte
}

// detectContentType returns a MIME type based on file extension.
func detectContentType(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		return "application/json"
	case ".csv":
		return "text/csv"
	case ".xml":
		return "application/xml"
	case ".pdf":
		return "application/pdf"
	case ".gz":
		return "application/gzip"
	default:
		return "application/octet-stream"
	}
}

