package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/alibkaba/jula-evidence-collector/internal/engine"
	"github.com/alibkaba/jula-evidence-collector/internal/reporter"
	"github.com/alibkaba/jula-evidence-collector/pkg/types"
)

func handleRun(args []string) error {
	runCmd := flag.NewFlagSet("run", flag.ContinueOnError)

	targetFlag := runCmd.String("target", os.Getenv("JULA_OUTPUT_TARGET"), "Delivery target: local, gcs")
	pathFlag := runCmd.String("path", os.Getenv("JULA_OUTPUT_PATH"), "Target path or bucket URI")
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

	// Resolve configuration paths.
	caiConfigPath := resolveConfigPath("JULA_CAI_CONFIG_PATH", "configs/extractions/gcp_cai.json")
	awsConfigPath := resolveConfigPath("JULA_AWS_CONFIG_PATH", "configs/extractions/aws_config.json")
	saasConfigPath := resolveConfigPath("JULA_SAAS_CONFIG_PATH", "configs/extractions/saas_http.json")

	// Generate a unique run ID.
	runID := fmt.Sprintf("run-%d", time.Now().UnixNano())

	slog.Info("run: pipeline starting",
		"target", *targetFlag,
		"path", *pathFlag,
		"concurrency", *concurrencyFlag,
		"timeout", *timeoutFlag,
		"cai_config", caiConfigPath,
		"aws_config", awsConfigPath,
		"saas_config", saasConfigPath,
		"run_id", runID,
	)

	// --- Step 1: Extract ---
	orch := engine.New(engine.RunConfig{
		Target:         *targetFlag,
		Path:           *pathFlag,
		Concurrency:    *concurrencyFlag,
		Timeout:        timeout,
		RunID:          runID,
		CAIConfigPath:  caiConfigPath,
		AWSConfigPath:  awsConfigPath,
		SaaSConfigPath: saasConfigPath,
	})

	ctx := context.Background()
	findings, err := orch.Extract(ctx)
	if err != nil {
		return fmt.Errorf("extraction failed: %w", err)
	}
	slog.Info("run: extraction complete", "findings_count", len(findings))

	// --- Step 2: Convert Findings to Evidence (hash raw data) ---
	evidence := make([]types.Evidence, 0, len(findings))
	for _, f := range findings {
		hash := sha256.Sum256(f.RawData)
		evidence = append(evidence, types.Evidence{
			ErlID:       f.ErlID,
			Finding:     f,
			PayloadHash: hex.EncodeToString(hash[:]),
		})
	}

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
		"total_erl_extractions", len(findings),
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
