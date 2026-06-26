package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"crypto/ecdsa"

	"github.com/alibkaba/jula-collector/internal/engine"
	"github.com/alibkaba/jula-collector/internal/courier"
	"github.com/alibkaba/jula-core/pkg/crypto"
	"github.com/alibkaba/jula-core/pkg/objstore"
	"github.com/alibkaba/jula-core/pkg/safehttp"
	"github.com/alibkaba/jula-core/pkg/types"
)

var newSafeClient = safehttp.NewClient

type collectorOptions struct {
	output         string
	integrationURL string
	provider       string
	concurrency    int
	timeout        time.Duration
	signingKey     *ecdsa.PrivateKey
}

func parseCollectorFlags(args []string) (*collectorOptions, error) {
	runCmd := flag.NewFlagSet("run", flag.ContinueOnError)

	outputFlag := runCmd.String("output", resolveOutputURL(), "Output URL: gs://bucket, s3://bucket, or local path")
	urlFlag := runCmd.String("integration-url", os.Getenv("JULA_INTEGRATION_URL"), "URL to fetch integrations.tar.gz")
	providerFlag := runCmd.String("provider", os.Getenv("JULA_PROVIDER"), "Native provider to collect from (gcp, aws, azure, etc.)")
	concurrencyFlag := runCmd.Int("concurrency", 3, "Max concurrent Evidence extraction goroutines")
	timeoutFlag := runCmd.String("timeout", "5m", "Per-Evidence extraction timeout duration")

	if err := runCmd.Parse(args); err != nil {
		return nil, fmt.Errorf("parsing run flags: %w", err)
	}

	// Validate output.
	if *outputFlag == "" {
		return nil, fmt.Errorf("output is required: use -output or set JULA_OUTPUT_PATH")
	}

	// Parse timeout duration.
	timeout, err := time.ParseDuration(*timeoutFlag)
	if err != nil {
		return nil, fmt.Errorf("parsing timeout: %w", err)
	}

	// Validate signing key early.
	signingKeyStr := os.Getenv("JULA_SIGNING_KEY")
	if signingKeyStr == "" {
		return nil, fmt.Errorf("JULA_SIGNING_KEY environment variable is required")
	}
	signingKey, err := crypto.ParseECDSAPrivateKey(signingKeyStr)
	if err != nil {
		return nil, fmt.Errorf("parsing JULA_SIGNING_KEY: %w", err)
	}

	return &collectorOptions{
		output:         *outputFlag,
		integrationURL: *urlFlag,
		provider:       *providerFlag,
		concurrency:    *concurrencyFlag,
		timeout:        timeout,
		signingKey:     signingKey,
	}, nil
}

func deliverEvidence(ctx context.Context, opts *collectorOptions, evidence []types.Evidence, runID string) (*types.Manifest, error) {
	bucketURL, pathPrefix, err := courier.ParseOutputURL(opts.output)
	if err != nil {
		return nil, fmt.Errorf("parsing output URL: %w", err)
	}

	store, _, err := objstore.FromURL(bucketURL, &http.Client{})
	if err != nil {
		return nil, fmt.Errorf("creating object store: %w", err)
	}

	rep := &courier.CloudCourier{
		Store:      store,
		SigningKey: opts.signingKey,
		PathPrefix: pathPrefix,
	}

	if err := rep.Validate(ctx); err != nil {
		return nil, fmt.Errorf("courier validation failed: %w", err)
	}

	manifest, err := rep.Deliver(ctx, evidence, runID)
	if err != nil {
		return nil, fmt.Errorf("delivery failed: %w", err)
	}

	return manifest, nil
}

func isRemoteURL(urlStr string) bool {
	return urlStr != "" && (strings.HasPrefix(urlStr, "http://") || strings.HasPrefix(urlStr, "https://"))
}

func handleRun(args []string) error {
	opts, err := parseCollectorFlags(args)
	if err != nil {
		return err
	}

	var integrationMap map[string][]byte
	integrationDir := resolveConfigPath("JULA_INTEGRATION_DIR", "integrations")

	if isRemoteURL(opts.integrationURL) {
		slog.Info("run: fetching integrations from URL", "url", opts.integrationURL)
		var err error
		integrationMap, err = fetchIntegrationsMap(opts.integrationURL, opts.provider)
		if err != nil {
			return fmt.Errorf("fetching integrations: %w", err)
		}
	}
	runID := fmt.Sprintf("run-%d", time.Now().UnixNano())

	slog.Info("run: pipeline starting",
		"output", opts.output,
		"concurrency", opts.concurrency,
		"timeout", opts.timeout,
		"provider", opts.provider,
		"integration_dir", integrationDir,
		"run_id", runID,
	)

	// --- Step 1: Extract ---
	orch := engine.New(engine.RunConfig{
		OutputURL:      opts.output,
		Concurrency:    opts.concurrency,
		Timeout:        opts.timeout,
		RunID:          runID,
		Provider:       opts.provider,
		IntegrationDir: integrationDir,
		IntegrationMap: integrationMap,
	})

	ctx := context.Background()
	evidence, err := orch.Extract(ctx)
	if err != nil {
		return fmt.Errorf("extraction failed: %w", err)
	}

	if len(evidence) == 0 {
		slog.Warn("run: no evidence collected (all integrations skipped or returned empty results)")
		return nil
	}

	slog.Info("run: extraction and transformation complete", "evidence_count", len(evidence))

	// --- Step 3: Deliver ---
	manifest, err := deliverEvidence(ctx, opts, evidence, runID)
	if err != nil {
		return err
	}

	// --- Step 4: Structured Audit Summary ---
	slog.Info("collection_summary",
		"run_id", runID,
		"timestamp", time.Now().UTC().Format(time.RFC3339),
		"environment", orch.Platform().ID,
		"platform_type", orch.Platform().Type,
		"total_erl_extractions", len(evidence),
		"evidence_files", len(manifest.EvidenceFiles),
		"evidence_location", opts.output,
		"signature", manifest.Signature[:16]+"...",
	)

	return nil
}

// resolveOutputURL builds the output URL from environment variables.
// Supports JULA_OUTPUT_PATH directly (gs://bucket, s3://bucket, /local/path)
// or the legacy JULA_OUTPUT_TARGET + JULA_OUTPUT_PATH combination.
func resolveOutputURL() string {
	// New: direct URL from env.
	if path := os.Getenv("JULA_OUTPUT_PATH"); path != "" {
		return path
	}
	return ""
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

func processTarEntryPath(name, provider string) (string, bool) {
	// GitHub tarballs have a top-level directory (e.g., 'alibkaba-jula-governor-12345/engine/integrations/...').
	// We strip the prefix to normalize the keys to bare filenames (e.g., 'gcp.yaml').
	parts := strings.SplitN(name, "/", 2)
	if len(parts) != 2 {
		return "", false
	}
	tail := parts[1]

	// Accept files under governor/engine/integrations/ only.
	if !strings.HasPrefix(tail, "governor/engine/integrations/") {
		return "", false
	}

	normalizedName := strings.TrimPrefix(tail, "governor/engine/integrations/")

	// Filter cloud/ provider integrations: only load the YAML matching JULA_PROVIDER.
	// External integrations (root-level) are always loaded.
	if strings.HasPrefix(normalizedName, "cloud/") {
		if provider == "" {
			return "", false // No provider set, skip all cloud integrations.
		}
		expected := "cloud/" + provider + ".yaml"
		if normalizedName != expected {
			return "", false // Skip non-matching cloud providers.
		}
		// Strip the cloud/ prefix so the map key is just "gcp.yaml".
		normalizedName = strings.TrimPrefix(normalizedName, "cloud/")
	}
	return normalizedName, true
}

func extractIntegrationsFromTarGz(body io.Reader, provider string) (map[string][]byte, error) {
	gzr, err := gzip.NewReader(body)
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

		if header.Typeflag != tar.TypeReg {
			continue
		}

		normalizedName, ok := processTarEntryPath(header.Name, provider)
		if !ok {
			continue
		}

		data, err := io.ReadAll(tr)
		if err != nil {
			return nil, fmt.Errorf("reading file %s: %w", header.Name, err)
		}
		result[normalizedName] = data
	}

	return result, nil
}

func validateIntegrationsURL(urlStr string) (*url.URL, error) {
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("invalid integrations URL: %w", err)
	}
	if os.Getenv("JULA_TEST_ENV") != "true" {
		if u.Scheme != "https" {
			return nil, fmt.Errorf("integrations URL must use HTTPS scheme")
		}
		allowedHosts := getAllowedHosts()
		host := strings.ToLower(u.Hostname())
		if !safehttp.IsHostAllowed(host, allowedHosts) {
			return nil, fmt.Errorf("integrations URL host %q is not in the allowed hosts list: %v", host, allowedHosts)
		}
	}
	return u, nil
}

func buildIntegrationsRequest(u *url.URL) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodGet, u.String(), nil) //nolint:ssrf // URL validated above: HTTPS-only + allowlisted hosts
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	tokenEnvName := os.Getenv("JULA_SOURCE_TOKEN_ENV")
	if tokenEnvName == "" {
		tokenEnvName = "GITHUB_TOKEN"
	}
	if token := os.Getenv(tokenEnvName); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req, nil
}

func fetchIntegrationsMap(urlStr string, provider string) (map[string][]byte, error) {
	u, err := validateIntegrationsURL(urlStr)
	if err != nil {
		return nil, err
	}

	req, err := buildIntegrationsRequest(u)
	if err != nil {
		return nil, err
	}

	client := newSafeClient(30 * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http get: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return extractIntegrationsFromTarGz(resp.Body, provider)
}

// getAllowedHosts returns the list of allowed HTTPS hosts for fetching
// integrations. It reads from the JULA_ALLOWED_HOSTS environment variable
// (comma-separated). Falls back to GitHub defaults if unset.
func getAllowedHosts() []string {
	if hosts := os.Getenv("JULA_ALLOWED_HOSTS"); hosts != "" {
		var result []string
		for _, h := range strings.Split(hosts, ",") {
			h = strings.TrimSpace(h)
			if h != "" {
				result = append(result, strings.ToLower(h))
			}
		}
		if len(result) > 0 {
			return result
		}
	}
	return []string{"api.github.com", "github.com"}
}

