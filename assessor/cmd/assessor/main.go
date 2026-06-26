package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	intCrypto "github.com/alibkaba/jula-assessor/internal/crypto"
	"github.com/alibkaba/jula-assessor/internal/evaluation"
	"github.com/alibkaba/jula-assessor/internal/ingestion"
	"github.com/alibkaba/jula-assessor/internal/oscal"
	pkgCrypto "github.com/alibkaba/jula-core/pkg/crypto"
	"github.com/alibkaba/jula-core/pkg/safehttp"
	"github.com/alibkaba/jula-core/pkg/types"
)

// version is set at build time via -ldflags.
var version = "dev"

var (
	newSafeHTTPClient = safehttp.NewClient
)

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
		fmt.Printf("assess %s\n", version)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(2)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `Usage: assess <command> [flags]

Commands:
  run         Run assessment pipeline (single-pass, in-memory)
  serve       Start HTTP server for Cloud Run deployment
  version     Print binary version and build metadata`)
}

type DispatchPayload struct {
	EventType     string                 `json:"event_type"`
	ClientPayload map[string]interface{} `json:"client_payload"`
}

func dispatchDriftAlert(provider, service string, rawPayload interface{}) {
	governorRepo := os.Getenv("JULA_GOVERNOR_REPO")   // e.g., "alibkaba/jula-governor"
	dispatchToken := os.Getenv("JULA_DISPATCH_TOKEN") // Fine-grained personal access token
	
	if governorRepo == "" || dispatchToken == "" {
		slog.Warn("gitops: automated telemetry alert skipped; environmental variables are unconfigured")
		return
	}

	url := fmt.Sprintf("https://api.github.com/repos/%s/dispatches", governorRepo)
	
	payload := DispatchPayload{
		EventType: "schema_drift_detected",
		ClientPayload: map[string]interface{}{
			"provider":         provider,
			"service":          service,
			"breaking_payload": rawPayload,
		},
	}

	bodyBytes, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(bodyBytes))
	if err != nil {
		slog.Error("gitops: failed to build dispatch request schema", "error", err)
		return
	}

	req.Header.Set("Authorization", "Bearer "+dispatchToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("Content-Type", "application/json")

	client := newSafeHTTPClient(10 * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		slog.Error("gitops: failed to route webhook dispatch packet to remote origin", "error", err)
		return
	}
	defer resp.Body.Close()

	slog.Info("gitops: schema drift alert successfully broadcasted to governor endpoint", "status", resp.Status)
}

type runOptions struct {
	bucketURL    string
	policyURL    string
	metadataURL  string
	outputFormat string
}

func parseRunFlags(args []string) (*runOptions, error) {
	fs := flag.NewFlagSet("assess", flag.ContinueOnError)
	bucketURLFlag := fs.String("bucket-url", "", "The target GCS bucket run URL (e.g. gs://jula-ledger/2026-05-17/) or local folder path")
	policyURLFlag := fs.String("policy-url", "", "The target OPA policy directory path (e.g. ./jula-governor/)")
	metadataURLFlag := fs.String("metadata-url", "", "The client metadata file URL or path (e.g. ./client_metadata.json)")
	outputFormatFlag := fs.String("output-format", "", "Output format: 'oscal' to emit NIST OSCAL Assessment Results JSON")

	if err := fs.Parse(args); err != nil {
		return nil, fmt.Errorf("flag parse: %w", err)
	}

	bucketURL := *bucketURLFlag
	if bucketURL == "" {
		bucketURL = os.Getenv("JULA_BUCKET_URL")
	}

	if bucketURL == "" {
		return nil, fmt.Errorf("assessor: missing target path: please specify --bucket-url flag or set JULA_BUCKET_URL env variable")
	}

	// Append deployment prefix and today's date if the bucketURL is a root cloud bucket.
	if (strings.HasPrefix(bucketURL, "gs://") || strings.HasPrefix(bucketURL, "s3://")) && !strings.Contains(bucketURL, "20") { // naive check for YYYY
		if !strings.HasSuffix(bucketURL, "/") {
			bucketURL += "/"
		}
		deployID := os.Getenv("JULA_DEPLOYMENT_ID")
		if deployID == "" {
			return nil, fmt.Errorf("assessor: JULA_DEPLOYMENT_ID environment variable is required")
		}
		bucketURL += fmt.Sprintf("deploy-%s/", deployID)
		bucketURL += time.Now().UTC().Format("2006-01-02")
	}

	policyURL := *policyURLFlag
	if policyURL == "" {
		policyURL = os.Getenv("JULA_POLICY_URL")
	}

	if policyURL == "" {
		return nil, fmt.Errorf("assessor: missing policy path: please specify --policy-url flag or set JULA_POLICY_URL env variable")
	}

	metadataURL := *metadataURLFlag
	if metadataURL == "" {
		metadataURL = os.Getenv("JULA_METADATA_URL")
	}

	outputFormat := *outputFormatFlag
	if outputFormat == "" {
		outputFormat = os.Getenv("JULA_OUTPUT_FORMAT")
	}

	return &runOptions{
		bucketURL:    bucketURL,
		policyURL:    policyURL,
		metadataURL:  metadataURL,
		outputFormat: outputFormat,
	}, nil
}

func handleRun(args []string) error {
	opts, err := parseRunFlags(args)
	if err != nil {
		return err
	}

	// Setup logging structure.
	logHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	slog.SetDefault(slog.New(logHandler))

	return runAssessmentPipeline(opts, time.Now())
}

func runAssessmentPipeline(opts *runOptions, start time.Time) error {
	slog.Info("assessor: starting Jula assurance engine", "bucket_url", opts.bucketURL, "policy_url", opts.policyURL)

	// Validate the JULA_PUBLIC_KEY env variable early.
	pubKeyPEM := os.Getenv("JULA_PUBLIC_KEY")
	if pubKeyPEM == "" {
		return fmt.Errorf("assessor: missing public key: JULA_PUBLIC_KEY environment variable is required for gatekeeper signature verification")
	}

	pubKey, err := pkgCrypto.ParseECDSAPublicKey(pubKeyPEM)
	if err != nil {
		return fmt.Errorf("assessor: failed to parse public key PEM: %w", err)
	}

	var metadata map[string]interface{}
	if opts.metadataURL != "" {
		slog.Info("assessor: loading client metadata", "metadata_url", opts.metadataURL)
		var err error
		metadata, err = loadMetadata(opts.metadataURL)
		if err != nil {
			return fmt.Errorf("assessor: failed to load client metadata: %w", err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// --- Phase 1: Ingestion & The Gatekeeper ---

	// 1. Initialize the cloud-agnostic ingestion reader.
	reader, err := ingestion.NewCloudReader(opts.bucketURL)
	if err != nil {
		return fmt.Errorf("assessor: failed to initialize ingestion reader: %w", err)
	}

	// 2. Download the Manifest.
	manifest, err := reader.ReadManifest(ctx)
	if err != nil {
		return fmt.Errorf("assessor: failed to download manifest.json: %w", err)
	}

	slog.Info("assessor: downloaded manifest successfully",
		"run_id", manifest.RunID,
		"timestamp", manifest.Timestamp,
		"providers", manifest.Providers,
		"files_count", len(manifest.EvidenceFiles),
	)

	// 3. Cryptographically verify the manifest signature.
	if err := intCrypto.VerifyManifestSignature(manifest, pubKey); err != nil {
		return fmt.Errorf("assessor: signature verification failed: %w", err)
	}
	slog.Info("assessor: manifest signature verified successfully against JULA_PUBLIC_KEY")

	// --- Phase 2: Open Policy Agent (OPA) Setup ---

	// 1. Initialize OPA engine.
	engine := evaluation.NewOPAEngine()

	// 2. Download and extract policies from GitHub tarball.
	slog.Info("assessor: fetching policies", "url", opts.policyURL)
	policiesDir, err := downloadPolicies(ctx, opts.policyURL)
	if err != nil {
		return fmt.Errorf("assessor: failed to download policies: %w", err)
	}

	// 3. Verify policy bundle signature (Key B) if JULA_POLICY_PUBLIC_KEY is set.
	policyPubKeyPEM := os.Getenv("JULA_POLICY_PUBLIC_KEY")
	if policyPubKeyPEM != "" {
		slog.Info("assessor: JULA_POLICY_PUBLIC_KEY is set, verifying policy bundle signature")

		policyPubKey, err := pkgCrypto.ParseECDSAPublicKey(policyPubKeyPEM)
		if err != nil {
			return fmt.Errorf("assessor: failed to parse policy public key PEM: %w", err)
		}

		bundleManifestPath := filepath.Join(policiesDir, "bundle-manifest.json")
		bundleManifestData, err := os.ReadFile(bundleManifestPath)
		if err != nil {
			return fmt.Errorf("assessor: bundle-manifest.json not found in policy bundle - refusing to load unsigned policies: %w", err)
		}

		var bundle pkgCrypto.PolicyBundle
		if err := json.Unmarshal(bundleManifestData, &bundle); err != nil {
			return fmt.Errorf("assessor: failed to parse bundle-manifest.json: %w", err)
		}

		if err := intCrypto.VerifyPolicyBundle(&bundle, policyPubKey); err != nil {
			return fmt.Errorf("assessor: POLICY GATE FAILURE - %w", err)
		}

		slog.Info("assessor: policy bundle cryptographic verification passed")
	} else {
		slog.Warn("assessor: JULA_POLICY_PUBLIC_KEY is not set, skipping policy bundle signature verification")
	}

	// 4. Load policy files from target path.
	if err := engine.LoadPolicies(policiesDir); err != nil {
		return fmt.Errorf("assessor: failed to load OPA policies: %w", err)
	}

	// 5. Compile loaded rules in memory and map SCF/Dataset targets.
	if err := engine.Compile(ctx); err != nil {
		return fmt.Errorf("assessor: failed to compile OPA policies: %w", err)
	}

	// --- Phase 3: Unified Global Evaluation Loop ---

	var validFiles []types.FileChecksum
	for _, f := range manifest.EvidenceFiles {
		if strings.HasSuffix(f.Path, ".log.gz") {
			slog.Info("assessor: skipping non-evidence trace log file in manifest", "path", f.Path)
			continue
		}
		validFiles = append(validFiles, f)
	}

	// Ingest all files into memory
	slog.Info("assessor: downloading all evidence payloads", "files_count", len(validFiles))
	payloads, err := reader.ReadPayloads(ctx, validFiles)
	if err != nil {
		return fmt.Errorf("assessor: failed to download evidence payloads: %w", err)
	}

	// Gatekeeper validation: verify raw content hashes against manifest checksums
	if err := intCrypto.VerifyPayloads(validFiles, payloads); err != nil {
		return fmt.Errorf("assessor: GATEKEEPER FAILURE - file hash mismatch: %w", err)
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
			slog.Warn("assessor: missing provenance sidecar for evidence file", "file", f.Path)
			continue
		}
		var prov pkgCrypto.Provenance
		if err := json.Unmarshal(provBytes, &prov); err != nil {
			return fmt.Errorf("assessor: failed to parse provenance sidecar %s: %w", provPath, err)
		}
		okSignature, err := pkgCrypto.VerifyProvenance(&prov, pubKey)
		if err != nil || !okSignature {
			return fmt.Errorf("assessor: provenance signature is INVALID for %s: %w", provPath, err)
		}
		var ev types.Evidence
		if err := json.Unmarshal(payloads[f.Path], &ev); err != nil {
			return fmt.Errorf("assessor: failed to unmarshal evidence payload %s: %w", f.Path, err)
		}
		if prov.PayloadHash != ev.PayloadHash {
			return fmt.Errorf("assessor: provenance payload hash mismatch for %s: expected %s, got %s", provPath, prov.PayloadHash, ev.PayloadHash)
		}
		allEvidences = append(allEvidences, ev)
		slog.Info("assessor: successfully verified provenance sidecar", "file", provPath)
	}

	allFindings := make([]evaluation.ControlFinding, 0)
	registeredIDs := engine.GetRegisteredControlIDs()
	slog.Info("assessor: starting sequential control evaluation", "controls_count", len(registeredIDs))

	for _, controlID := range registeredIDs {
		slog.Info("assessor: sequentially evaluating control", "control_id", controlID)

		findings, err := engine.EvaluateControl(ctx, controlID, allEvidences, metadata)
		if err != nil {
			return fmt.Errorf("assessor: policy evaluation error for control %s: %w", controlID, err)
		}

		for _, finding := range findings {
			if finding.Verdict == "SCHEMA_DRIFT" {
				slog.Warn("CRITICAL: Architectural schema drift detected! Halting loop to route correction patch...")

				// Extract provider prefix dynamically from control string layout (e.g. "CIS-GCP-STORAGE-1")
				idParts := strings.Split(finding.ControlID, "-")
				provider := "gcp"
				if len(idParts) > 1 {
					provider = strings.ToLower(idParts[1])
				}

				// Trigger dynamic alert with zero hardcoding!
				dispatchDriftAlert(provider, finding.TargetService, finding.RawBreakingData)
				os.Exit(0)
			}
		}

		allFindings = append(allFindings, findings...)
		runtime.GC()
	}

	// Free local evaluation data and hint GC.
	runtime.GC()

	// --- Output Results ---
	slog.Info("assessor: completed compliance evaluation", "findings_count", len(allFindings))

	hasFailures := false
	controlsPassed := 0
	controlsFailed := 0
	for _, f := range allFindings {
		if f.Verdict != evaluation.VerdictCompliant {
			hasFailures = true
			controlsFailed++
		} else {
			controlsPassed++
		}
	}

	// Print standardized compliance ledger findings to stdout in formatted JSON
	fmt.Println("\n================ JULA ASSURANCE FINDINGS LEDGER ================")
	findingsJSON, _ := json.MarshalIndent(allFindings, "", "  ")
	fmt.Println(string(findingsJSON))

	if err := reader.WriteFile(ctx, "assessor_ledger.json", findingsJSON); err != nil {
		slog.Error("assessor: failed to export assessor ledger to file", "error", err)
	}

	// 6. Sign the assessment verdict (Key C) if JULA_ASSESSOR_SIGNING_KEY is set.
	var signedVerdict *pkgCrypto.Verdict
	assessorSigningKeyPEM := os.Getenv("JULA_ASSESSOR_SIGNING_KEY")
	if assessorSigningKeyPEM != "" {
		slog.Info("assessor: signing assessment verdict with Key C")

		assessorSigningKey, err := pkgCrypto.ParseECDSAPrivateKey(assessorSigningKeyPEM)
		if err != nil {
			return fmt.Errorf("assessor: failed to parse assessor signing key: %w", err)
		}

		ledgerHash := pkgCrypto.HashFile(findingsJSON)
		signedVerdict = &pkgCrypto.Verdict{
			RunID:          manifest.RunID,
			LedgerHash:     ledgerHash,
			ControlsPassed: controlsPassed,
			ControlsFailed: controlsFailed,
			ControlsTotal:  len(allFindings),
			Timestamp:      time.Now().UTC(),
		}

		if err := pkgCrypto.SignVerdict(signedVerdict, assessorSigningKey); err != nil {
			return fmt.Errorf("assessor: failed to sign verdict: %w", err)
		}

		verdictJSON, err := json.MarshalIndent(signedVerdict, "", "  ")
		if err != nil {
			return fmt.Errorf("assessor: failed to marshal signed verdict: %w", err)
		}

		if err := reader.WriteFile(ctx, "verdict.json", verdictJSON); err != nil {
			slog.Error("assessor: failed to export signed verdict", "error", err)
		} else {
			slog.Info("assessor: signed verdict written successfully",
				"run_id", signedVerdict.RunID,
				"ledger_hash", ledgerHash,
				"controls_passed", controlsPassed,
				"controls_failed", controlsFailed,
			)
		}
	} else {
		slog.Warn("assessor: JULA_ASSESSOR_SIGNING_KEY is not set, skipping verdict signing")
	}

	// 7. Emit OSCAL Assessment Results if requested.
	outputFormat := opts.outputFormat
	if outputFormat == "" {
		outputFormat = os.Getenv("JULA_OUTPUT_FORMAT")
	}
	if strings.EqualFold(outputFormat, "oscal") {
		slog.Info("assessor: generating OSCAL Assessment Results output")

		// Convert evaluation findings to OSCAL input type.
		oscalFindings := make([]oscal.ControlFindingInput, len(allFindings))
		for i, f := range allFindings {
			oscalFindings[i] = oscal.ControlFindingInput{
				ControlID:         f.ControlID,
				CustomerControlID: f.CustomerControlID,
				Verdict:           string(f.Verdict),
				Details:           f.Details,
				Confidence:        f.Confidence,
				AutomationStatus:  f.AutomationStatus,
				EvaluatedAt:       f.EvaluatedAt,
			}
		}

		oscalCfg := oscal.MapConfig{
			RunID:        manifest.RunID,
			Organization: os.Getenv("JULA_ORGANIZATION"),
			Framework:    os.Getenv("JULA_FRAMEWORK"),
			Start:        start,
			Verdict:      signedVerdict,
		}

		ar := oscal.MapToAssessmentResults(oscalFindings, oscalCfg)
		oscalJSON, err := ar.MarshalJSON()
		if err != nil {
			slog.Error("assessor: failed to marshal OSCAL AR", "error", err)
		} else {
			if err := reader.WriteFile(ctx, "assessment-results.json", oscalJSON); err != nil {
				slog.Error("assessor: failed to write OSCAL AR to bucket", "error", err)
			} else {
				slog.Info("assessor: OSCAL Assessment Results written to assessment-results.json")
			}
		}
	}

	fmt.Println("================================================================")

	if hasFailures {
		slog.Error("assessor: compliance audit FAILED - security issues detected!")
		fmt.Println("STATUS: NON_COMPLIANT")
		return fmt.Errorf("compliance audit failed")
	}

	slog.Info("assessor: compliance audit SUCCESSFUL - system is fully secure!")
	fmt.Println("STATUS: COMPLIANT")
	return nil
}

func validateMetadataURL(pathOrURL string) (*url.URL, error) {
	u, err := url.Parse(pathOrURL)
	if err != nil {
		return nil, fmt.Errorf("parsing metadata URL: %w", err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("metadata URL must use HTTPS scheme")
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("metadata URL has empty host")
	}
	if ip := net.ParseIP(host); ip != nil && os.Getenv("JULA_TEST_ENV") != "true" {
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return nil, fmt.Errorf("metadata URL host is an invalid IP address")
		}
	}
	return u, nil
}

func loadMetadata(pathOrURL string) (map[string]interface{}, error) {
	if pathOrURL == "" {
		return nil, nil
	}
	var data []byte
	var err error
	if strings.HasPrefix(pathOrURL, "http://") || strings.HasPrefix(pathOrURL, "https://") {
		u, err := validateMetadataURL(pathOrURL)
		if err != nil {
			return nil, err
		}

		req, err := http.NewRequest(http.MethodGet, u.String(), nil) //nolint:ssrf // URL validated above: HTTPS-only + IP blocking
		if err != nil {
			return nil, fmt.Errorf("creating metadata request: %w", err)
		}
		client := newSafeHTTPClient(15 * time.Second)
		resp, err := client.Do(req)
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

func untarPolicyBundle(body io.Reader, tmpDir string) error {
	gzr, err := gzip.NewReader(body)
	if err != nil {
		return fmt.Errorf("creating gzip reader: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading tar header: %w", err)
		}

		cleanName := filepath.Clean(header.Name)
		if strings.Contains(cleanName, "..") || filepath.IsAbs(cleanName) {
			return fmt.Errorf("invalid file path %s", header.Name)
		}
		target := filepath.Join(tmpDir, cleanName)
		if !strings.HasPrefix(target, filepath.Clean(tmpDir)+string(filepath.Separator)) {
			return fmt.Errorf("invalid path: path traversal detected in %s", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			f.Close()
		}
	}
	return nil
}

func downloadPolicies(ctx context.Context, url string) (string, error) {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return url, nil // Already a local path
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}

	tokenEnvName := os.Getenv("JULA_SOURCE_TOKEN_ENV")
	if tokenEnvName == "" {
		tokenEnvName = "GITHUB_TOKEN"
	}
	if token := os.Getenv(tokenEnvName); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	client := newSafeHTTPClient(30 * time.Second)
	resp, err := client.Do(req)
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

	if err := untarPolicyBundle(resp.Body, tmpDir); err != nil {
		os.RemoveAll(tmpDir)
		return "", err
	}

	return tmpDir, nil
}
