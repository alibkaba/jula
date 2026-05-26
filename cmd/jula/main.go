package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	intCrypto "github.com/alibkaba/jula-evaluator/internal/crypto"
	"github.com/alibkaba/jula-evaluator/internal/evaluation"
	"github.com/alibkaba/jula-evaluator/internal/ingestion"
	pkgCrypto "github.com/alibkaba/jula-core/pkg/crypto"
	"github.com/alibkaba/jula-core/pkg/types"
)

// version is set at build time via -ldflags.
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "run":
		if err := handleRun(os.Args[2:]); err != nil {
			slog.Error("run failed", "error", err)
			os.Exit(1)
		}
	case "serve":
		if err := handleServe(os.Args[2:]); err != nil {
			slog.Error("serve failed", "error", err)
			os.Exit(1)
		}
	case "version":
		fmt.Printf("jula %s\n", version)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(2)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `Usage: jula <command> [flags]

Commands:
  run         Run evaluation pipeline (single-pass, in-memory)
  serve       Start HTTP server for Cloud Run deployment
  version     Print binary version and build metadata`)
}

func handleRun(args []string) error {
	fs := flag.NewFlagSet("jula", flag.ContinueOnError)
	bucketURLFlag := fs.String("bucket-url", "", "The target GCS bucket run URL (e.g. gs://jula-evidence-ledger/2026-05-17/) or local folder path")
	policyURLFlag := fs.String("policy-url", "", "The target OPA policy directory path (e.g. ./jula-policy/)")
	metadataURLFlag := fs.String("metadata-url", "", "The client metadata file URL or path (e.g. ./client_metadata.json)")

	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("flag parse: %w", err)
	}

	// Setup logging structure.
	logHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	slog.SetDefault(slog.New(logHandler))

	// Resolve the target bucket URL.
	bucketURL := *bucketURLFlag
	if bucketURL == "" {
		bucketURL = os.Getenv("JULA_BUCKET_URL")
	}

	if bucketURL == "" {
		return fmt.Errorf("evaluator: missing target path: please specify --bucket-url flag or set JULA_BUCKET_URL env variable")
	}

	// Append today's date if the bucketURL is just the root GCS bucket.
	if strings.HasPrefix(bucketURL, "gs://") && !strings.Contains(bucketURL, "20") { // naive check for YYYY
		if !strings.HasSuffix(bucketURL, "/") {
			bucketURL += "/"
		}
		bucketURL += time.Now().UTC().Format("2006-01-02")
	}

	// Resolve the target policies URL.
	policyURL := *policyURLFlag
	if policyURL == "" {
		policyURL = os.Getenv("JULA_POLICY_URL")
	}

	if policyURL == "" {
		return fmt.Errorf("evaluator: missing policy path: please specify --policy-url flag or set JULA_POLICY_URL env variable")
	}

	slog.Info("evaluator: starting Jula assurance engine", "bucket_url", bucketURL, "policy_url", policyURL)

	// Validate the JULA_PUBLIC_KEY env variable early.
	pubKeyPEM := os.Getenv("JULA_PUBLIC_KEY")
	if pubKeyPEM == "" {
		return fmt.Errorf("evaluator: missing public key: JULA_PUBLIC_KEY environment variable is required for gatekeeper signature verification")
	}

	pubKey, err := intCrypto.ParseECDSAPublicKey(pubKeyPEM)
	if err != nil {
		return fmt.Errorf("evaluator: failed to parse public key PEM: %w", err)
	}

	// Resolve the target metadata URL.
	metadataURL := *metadataURLFlag
	if metadataURL == "" {
		metadataURL = os.Getenv("JULA_METADATA_URL")
	}

	var metadata map[string]interface{}
	if metadataURL != "" {
		slog.Info("evaluator: loading client metadata", "metadata_url", metadataURL)
		var err error
		metadata, err = loadMetadata(metadataURL)
		if err != nil {
			return fmt.Errorf("evaluator: failed to load client metadata: %w", err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// --- Phase 1: Ingestion & The Gatekeeper ---

	// 1. Initialize the ingestion reader.
	reader := ingestion.NewGCSReader(&http.Client{Timeout: 30 * time.Second})
	if err := reader.Initialize(bucketURL); err != nil {
		return fmt.Errorf("evaluator: failed to initialize GCS downloader: %w", err)
	}

	// 2. Download the Manifest.
	manifest, err := reader.ReadManifest(ctx, bucketURL)
	if err != nil {
		return fmt.Errorf("evaluator: failed to download manifest.json: %w", err)
	}

	slog.Info("evaluator: downloaded manifest successfully",
		"run_id", manifest.RunID,
		"timestamp", manifest.Timestamp,
		"providers", manifest.Providers,
		"files_count", len(manifest.EvidenceFiles),
	)

	// 3. Cryptographically verify the manifest signature.
	if err := intCrypto.VerifyManifestSignature(manifest, pubKey); err != nil {
		return fmt.Errorf("evaluator: signature verification failed: %w", err)
	}
	slog.Info("evaluator: manifest signature verified successfully against JULA_PUBLIC_KEY")

	// --- Phase 2: Open Policy Agent (OPA) Setup ---

	// 1. Initialize OPA Evaluator.
	evaluator := evaluation.NewOPAEvaluator()

	// 2. Download and extract policies from GitHub tarball.
	slog.Info("evaluator: fetching policies", "url", policyURL)
	policiesDir, err := downloadPolicies(ctx, policyURL)
	if err != nil {
		return fmt.Errorf("evaluator: failed to download policies: %w", err)
	}

	// 3. Load policy files from target path.
	if err := evaluator.LoadPolicies(policiesDir); err != nil {
		return fmt.Errorf("evaluator: failed to load OPA policies: %w", err)
	}

	// 4. Compile loaded rules in memory and map SCF/Dataset targets.
	if err := evaluator.Compile(ctx); err != nil {
		return fmt.Errorf("evaluator: failed to compile OPA policies: %w", err)
	}

	// --- Phase 3: Unified Global Evaluation Loop ---

	var validFiles []types.FileChecksum
	for _, f := range manifest.EvidenceFiles {
		if strings.HasSuffix(f.Path, ".log.gz") {
			slog.Info("evaluator: skipping non-evidence trace log file in manifest", "path", f.Path)
			continue
		}
		validFiles = append(validFiles, f)
	}

	// Ingest all files into memory
	slog.Info("evaluator: downloading all evidence payloads", "files_count", len(validFiles))
	payloads, err := reader.ReadPayloads(ctx, bucketURL, validFiles)
	if err != nil {
		return fmt.Errorf("evaluator: failed to download evidence payloads: %w", err)
	}

	// Gatekeeper validation: verify raw content hashes against manifest checksums
	if err := intCrypto.VerifyPayloads(validFiles, payloads); err != nil {
		return fmt.Errorf("evaluator: GATEKEEPER FAILURE - file hash mismatch: %w", err)
	}

	// Cryptographically verify provenance sidecars
	var allEvidences []types.Evidence
	for _, f := range validFiles {
		if strings.HasSuffix(f.Path, ".prov.json") {
			continue
		}
		provPath := strings.TrimSuffix(f.Path, ".json") + ".prov.json"
		provBytes, ok := payloads[provPath]
		if !ok {
			slog.Warn("evaluator: missing provenance sidecar for evidence file", "file", f.Path)
			continue
		}
		var prov pkgCrypto.Provenance
		if err := json.Unmarshal(provBytes, &prov); err != nil {
			return fmt.Errorf("evaluator: failed to parse provenance sidecar %s: %w", provPath, err)
		}
		okSignature, err := pkgCrypto.VerifyProvenance(&prov, pubKey)
		if err != nil || !okSignature {
			return fmt.Errorf("evaluator: provenance signature is INVALID for %s: %w", provPath, err)
		}
		var ev types.Evidence
		if err := json.Unmarshal(payloads[f.Path], &ev); err != nil {
			return fmt.Errorf("evaluator: failed to unmarshal evidence payload %s: %w", f.Path, err)
		}
		if prov.PayloadHash != ev.PayloadHash {
			return fmt.Errorf("evaluator: provenance payload hash mismatch for %s: expected %s, got %s", provPath, prov.PayloadHash, ev.PayloadHash)
		}
		allEvidences = append(allEvidences, ev)
		slog.Info("evaluator: successfully verified provenance sidecar", "file", provPath)
	}

	allFindings := make([]evaluation.ControlFinding, 0)
	registeredIDs := evaluator.GetRegisteredControlIDs()
	slog.Info("evaluator: starting sequential control evaluation", "controls_count", len(registeredIDs))

	for _, controlID := range registeredIDs {
		slog.Info("evaluator: sequentially evaluating control", "control_id", controlID)

		findings, err := evaluator.EvaluateControl(ctx, controlID, allEvidences, metadata)
		if err != nil {
			return fmt.Errorf("evaluator: policy evaluation error for control %s: %w", controlID, err)
		}

		allFindings = append(allFindings, findings...)
		runtime.GC()
	}

	// Free global payloads
	payloads = nil
	allEvidences = nil
	runtime.GC()

	// --- Output Results ---
	slog.Info("evaluator: completed compliance evaluation", "findings_count", len(allFindings))

	hasFailures := false
	for _, f := range allFindings {
		if f.Verdict != evaluation.VerdictCompliant {
			hasFailures = true
		}
	}

	// Print standardized compliance ledger findings to stdout in formatted JSON
	fmt.Println("\n================ JULA ASSURANCE FINDINGS LEDGER ================")
	findingsJSON, _ := json.MarshalIndent(allFindings, "", "  ")
	fmt.Println(string(findingsJSON))
	
	if err := reader.WriteFile(ctx, bucketURL, "evaluator_ledger.json", findingsJSON); err != nil {
		slog.Error("evaluator: failed to export evaluator ledger to file", "error", err)
	}

	fmt.Println("================================================================")

	if hasFailures {
		slog.Error("evaluator: compliance audit FAILED - security issues detected!")
		fmt.Println("STATUS: NON_COMPLIANT")
		return fmt.Errorf("compliance audit failed")
	}

	slog.Info("evaluator: compliance audit SUCCESSFUL - system is fully secure!")
	fmt.Println("STATUS: COMPLIANT")
	return nil
}

func loadMetadata(pathOrURL string) (map[string]interface{}, error) {
	if pathOrURL == "" {
		return nil, nil
	}
	var data []byte
	var err error
	if strings.HasPrefix(pathOrURL, "http://") || strings.HasPrefix(pathOrURL, "https://") {
		resp, err := http.Get(pathOrURL)
		if err != nil {
			return nil, fmt.Errorf("fetching metadata URL: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("fetching metadata URL returned status: %s", resp.Status)
		}
		data, err = io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("reading metadata URL response: %w", err)
		}
	} else {
		data, err = os.ReadFile(pathOrURL)
		if err != nil {
			return nil, fmt.Errorf("reading metadata file: %w", err)
		}
	}
	var meta map[string]interface{}
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("parsing metadata JSON: %w", err)
	}
	return meta, nil
}

func downloadPolicies(ctx context.Context, url string) (string, error) {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return url, nil // Already a local path
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}

	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetching policies: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status fetching policies: %s", resp.Status)
	}

	tmpDir, err := os.MkdirTemp("", "jula-policies-*")
	if err != nil {
		return "", fmt.Errorf("creating temp dir: %w", err)
	}

	gzr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return "", fmt.Errorf("creating gzip reader: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("reading tar header: %w", err)
		}

		cleanName := filepath.Clean(header.Name)
		if strings.Contains(cleanName, "..") || filepath.IsAbs(cleanName) {
			return "", fmt.Errorf("invalid file path %s", header.Name)
		}
		target := filepath.Join(tmpDir, cleanName)
		if !strings.HasPrefix(target, filepath.Clean(tmpDir)+string(filepath.Separator)) {
			return "", fmt.Errorf("invalid path: path traversal detected in %s", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return "", err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return "", err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
			if err != nil {
				return "", err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return "", err
			}
			f.Close()
		}
	}

	return tmpDir, nil
}
