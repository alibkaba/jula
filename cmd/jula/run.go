package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/alibkaba/jula-evidence-collector/internal/engine"
	"github.com/alibkaba/jula-evidence-collector/internal/reporter"
)

func handleRun(args []string) error {
	runCmd := flag.NewFlagSet("run", flag.ContinueOnError)

	targetFlag := runCmd.String("target", os.Getenv("JULA_OUTPUT_TARGET"), "Delivery target: local, gcs")
	pathFlag := runCmd.String("path", os.Getenv("JULA_OUTPUT_PATH"), "Target path or bucket URI")
	urlFlag := runCmd.String("integration-url", os.Getenv("JULA_INTEGRATION_URL"), "URL to fetch integrations.tar.gz")
	concurrencyFlag := runCmd.Int("concurrency", 3, "Max concurrent ERL extraction goroutines")
	timeoutFlag := runCmd.String("timeout", "5m", "Per-ERL extraction timeout duration")

	if err := runCmd.Parse(args); err != nil {
		return fmt.Errorf("parsing run flags: %w", err)
	}

	// Validate target.
	if *targetFlag == "" {
		return fmt.Errorf("target is required: use -target or set JULA_OUTPUT_TARGET")
	}
	if !isValidTarget(*targetFlag) {
		return fmt.Errorf("unknown target: %q", *targetFlag)
	}

	// Validate path.
	if *pathFlag == "" {
		return fmt.Errorf("path is required: use -path or set JULA_OUTPUT_PATH")
	}

	// Parse timeout duration.
	timeout, err := time.ParseDuration(*timeoutFlag)
	if err != nil {
		return fmt.Errorf("parsing timeout: %w", err)
	}

	// Validate signing key early.
	signingKeyStr := os.Getenv("JULA_SIGNING_KEY")
	block, _ := pem.Decode([]byte(signingKeyStr))
	if block == nil {
		return fmt.Errorf("failed to decode PEM block containing the signing key")
	}

	signingKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("parsing JULA_SIGNING_KEY (expected ECPrivateKey PEM): %w", err)
	}

	var integrationMap map[string][]byte
	integrationDir := resolveConfigPath("JULA_INTEGRATION_DIR", "integrations")

	if *urlFlag != "" && (strings.HasPrefix(*urlFlag, "http://") || strings.HasPrefix(*urlFlag, "https://")) {
		slog.Info("run: fetching integrations from URL", "url", *urlFlag)
		var err error
		integrationMap, err = fetchIntegrationsMap(*urlFlag)
		if err != nil {
			return fmt.Errorf("fetching integrations: %w", err)
		}
	}
	runID := fmt.Sprintf("run-%d", time.Now().UnixNano())

	slog.Info("run: pipeline starting",
		"target", *targetFlag,
		"path", *pathFlag,
		"concurrency", *concurrencyFlag,
		"timeout", *timeoutFlag,
		"integration_dir", integrationDir,
		"run_id", runID,
	)

	// --- Step 1: Extract ---
	orch := engine.New(engine.RunConfig{
		Target:         *targetFlag,
		Path:           *pathFlag,
		Concurrency:    *concurrencyFlag,
		Timeout:        timeout,
		RunID:          runID,
		IntegrationDir: integrationDir,
		IntegrationMap: integrationMap,
	})

	ctx := context.Background()
	evidence, err := orch.Extract(ctx)
	if err != nil {
		return fmt.Errorf("extraction failed: %w", err)
	}
	slog.Info("run: extraction and transformation complete", "evidence_count", len(evidence))

	// --- Step 3: Deliver ---
	var rep reporter.Reporter
	switch *targetFlag {
	case "local":
		rep = &reporter.LocalReporter{
			OutputDir:  *pathFlag,
			SigningKey: signingKey,
		}
	case "gcs":
		bucketName := reporter.ParseBucketName(*pathFlag)
		tokenProvider := reporter.NewMetadataTokenProvider(&http.Client{})
		rep = &reporter.GCSReporter{
			BucketName:    bucketName,
			SigningKey:    signingKey,
			HTTPClient:    &http.Client{},
			TokenProvider: tokenProvider,
		}
	default:
		return fmt.Errorf("reporter not implemented for target: %s", *targetFlag)
	}

	if err := rep.Validate(ctx); err != nil {
		return fmt.Errorf("reporter validation failed: %w", err)
	}

	manifest, err := rep.Deliver(ctx, evidence, runID)
	if err != nil {
		return fmt.Errorf("delivery failed: %w", err)
	}

	// --- Step 4: Structured Audit Summary ---
	slog.Info("collection_summary",
		"run_id", runID,
		"timestamp", time.Now().UTC().Format(time.RFC3339),
		"environment", orch.Platform().ID,
		"platform_type", orch.Platform().Type,
		"total_erl_extractions", len(evidence),
		"evidence_files", len(manifest.EvidenceFiles),
		"evidence_location", *pathFlag,
		"signature", manifest.Signature[:16]+"...",
	)

	return nil
}

func isValidTarget(name string) bool {
	switch name {
	case "local", "gcs":
		return true
	default:
		return false
	}
}

// resolveConfigPath resolves a configuration file path by checking the environment variable.
// It falls back to an absolute path ("/" + defaultPath) and then a relative path (defaultPath).
func resolveConfigPath(envKey, defaultPath string) string {
	path := os.Getenv(envKey)
	if path == "" {
		path = "/" + defaultPath
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		path = defaultPath
	}
	return path
}

func fetchIntegrationsMap(urlStr string) (map[string][]byte, error) {
	req, err := http.NewRequest(http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http get: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	gzr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("gzip reader: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	result := make(map[string][]byte)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tar reader: %w", err)
		}

		if header.Typeflag == tar.TypeReg {
			// GitHub tarballs have a top-level directory (e.g., 'alibkaba-jula-compliance-policies-12345/integrations/...').
			// We strip the first path segment to normalize the keys to 'integrations/...'.
			parts := strings.SplitN(header.Name, "/", 2)
			if len(parts) != 2 || !strings.HasPrefix(parts[1], "integrations/") {
				continue // Skip files not under integrations/
			}
			
			// Use the stripped path (e.g., 'integrations/universal_cloud/gcp_cai.yaml')
			normalizedName := parts[1]

			data, err := io.ReadAll(tr)
			if err != nil {
				return nil, fmt.Errorf("reading file %s: %w", header.Name, err)
			}
			result[normalizedName] = data
		}
	}

	return result, nil
}
