package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/alibkaba/jula-evidence-collector/internal/engine"
	"github.com/alibkaba/jula-evidence-collector/internal/mappers"
	"github.com/alibkaba/jula-evidence-collector/internal/providers"
	"github.com/alibkaba/jula-evidence-collector/internal/reporter"

	// Import the providers so their init() registers them.
	_ "github.com/alibkaba/jula-evidence-collector/internal/providers/aikido"
	_ "github.com/alibkaba/jula-evidence-collector/internal/providers/gcp"
	_ "github.com/alibkaba/jula-evidence-collector/internal/providers/github"
	"github.com/alibkaba/jula-evidence-collector/internal/providers/filedrop"
)

func handleRun(args []string) error {
	runCmd := flag.NewFlagSet("run", flag.ContinueOnError)

	providerFlag := runCmd.String("provider", os.Getenv("JULA_PROVIDER"), "Comma-separated provider(s) to execute (aws, gcp, github)")
	frameworkFlag := runCmd.String("framework", os.Getenv("JULA_FRAMEWORK"), "Target compliance framework (soc2, iso27001)")
	targetFlag := runCmd.String("target", os.Getenv("JULA_OUTPUT_TARGET"), "Delivery target: local, s3, gcs")
	pathFlag := runCmd.String("path", os.Getenv("JULA_OUTPUT_PATH"), "Target path or bucket URI")
	concurrencyFlag := runCmd.Int("concurrency", 3, "Max concurrent provider goroutines")
	timeoutFlag := runCmd.String("timeout", "5m", "Per-provider timeout duration")
	formatFlag := runCmd.String("format", os.Getenv("JULA_OUTPUT_FORMAT"), "Output format (json, markdown)")

	if err := runCmd.Parse(args); err != nil {
		return fmt.Errorf("parsing run flags: %w", err)
	}

	// Validate provider.
	if *providerFlag == "" {
		return fmt.Errorf("provider is required: use -provider or set JULA_PROVIDER")
	}
	providersList := strings.Split(*providerFlag, ",")
	for _, p := range providersList {
		p = strings.TrimSpace(p)
		if !isValidProvider(p) {
			return fmt.Errorf("unknown provider: %q", p)
		}
	}

	// Validate framework.
	if *frameworkFlag == "" {
		return fmt.Errorf("framework is required: use -framework or set JULA_FRAMEWORK")
	}
	if !isValidFramework(*frameworkFlag) {
		return fmt.Errorf("unknown framework: %q", *frameworkFlag)
	}
	if *frameworkFlag != "soc2" {
		return fmt.Errorf("mapper not implemented for framework: %s", *frameworkFlag)
	}

	// Validate target.
	if *targetFlag == "" {
		return fmt.Errorf("target is required: use -target or set JULA_OUTPUT_TARGET")
	}
	if !isValidTarget(*targetFlag) {
		return fmt.Errorf("unknown target: %q", *targetFlag)
	}
	if *targetFlag == "s3" {
		return fmt.Errorf("reporter not implemented for target: s3")
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

	// Generate a unique run ID.
	runID := fmt.Sprintf("run-%d", time.Now().UnixNano())

	slog.Info("run: full pipeline starting",
		"providers", providersList,
		"framework", *frameworkFlag,
		"target", *targetFlag,
		"path", *pathFlag,
		"concurrency", *concurrencyFlag,
		"timeout", *timeoutFlag,
		"run_id", runID,
	)

	// --- Step 0: Exceptions & Runtime Configs ---
	exceptionsPath := "/configs/exceptions.json"
	if _, err := os.Stat(exceptionsPath); os.IsNotExist(err) {
		exceptionsPath = "configs/exceptions.json"
	}

	hasFiledrop := false
	for _, p := range providersList {
		if p == "filedrop" {
			hasFiledrop = true
			break
		}
	}

	if hasFiledrop {
		bucket := os.Getenv("JULA_FILEDROP_BUCKET")
		prefix := os.Getenv("JULA_FILEDROP_PREFIX")
		if bucket == "" {
			return fmt.Errorf("JULA_FILEDROP_BUCKET is required when using the filedrop provider")
		}
		if prefix == "" {
			prefix = "evidence/byoe/" // fallback
		}
		
		tokenProvider := reporter.NewMetadataTokenProvider(&http.Client{})
		gcsReader := &filedrop.GCSReader{
			BucketName:    bucket,
			HTTPClient:    &http.Client{},
			TokenProvider: tokenProvider,
		}
		
		providers.Register(filedrop.New(bucket, prefix, gcsReader))
	}

	// --- Step 1: Extract ---
	orch := engine.New(engine.RunConfig{
		Providers:      providersList,
		Framework:      *frameworkFlag,
		Target:         *targetFlag,
		Path:           *pathFlag,
		Concurrency:    *concurrencyFlag,
		Timeout:        timeout,
		RunID:          runID,
		ExceptionsPath: exceptionsPath,
	})

	if err := orch.LoadExceptions(); err != nil {
		return fmt.Errorf("loading exceptions: %w", err)
	}

	ctx := context.Background()
	findings, err := orch.Extract(ctx)
	if err != nil {
		return fmt.Errorf("extraction failed: %w", err)
	}
	slog.Info("run: extraction complete", "findings_count", len(findings))

	// --- Step 1.5: Apply Exceptions ---
	findings = orch.ApplyExceptions(findings, time.Now())

	// --- Step 2: Map ---
	var mapper mappers.Mapper
	switch *frameworkFlag {
	case "soc2":
		mapper = &mappers.SOC2Mapper{}
	default:
		return fmt.Errorf("mapper not implemented for framework: %s", *frameworkFlag)
	}

	configPath := fmt.Sprintf("/configs/%s_mapping.json", *frameworkFlag)
	// Fall back to local path for development.
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		configPath = fmt.Sprintf("configs/%s_mapping.json", *frameworkFlag)
	}

	if err := mapper.LoadRules(configPath); err != nil {
		return fmt.Errorf("loading mapping rules: %w", err)
	}

	evidence, err := mapper.Map(findings)
	if err != nil {
		return fmt.Errorf("mapping failed: %w", err)
	}
	slog.Info("run: mapping complete", "evidence_count", len(evidence))

	// --- Step 3: Deliver ---
	var rep reporter.Reporter
	switch *targetFlag {
	case "local":
		rep = &reporter.LocalReporter{
			OutputDir:  *pathFlag,
			SigningKey: signingKey,
			Format:     *formatFlag,
		}
	case "gcs":
		bucketName := reporter.ParseBucketName(*pathFlag)
		tokenProvider := reporter.NewMetadataTokenProvider(&http.Client{})
		rep = &reporter.GCSReporter{
			BucketName:    bucketName,
			SigningKey:    signingKey,
			HTTPClient:    &http.Client{},
			TokenProvider: tokenProvider,
			Format:        *formatFlag,
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
	passed, failed, excepted, errored := 0, 0, 0, 0
	for _, f := range findings {
		switch f.Status {
		case "PASS":
			passed++
		case "FAIL":
			failed++
		case "EXCEPTED":
			excepted++
		case "ERROR":
			errored++
		}
	}

	overallStatus := "PASS"
	if failed > 0 || errored > 0 {
		overallStatus = "FAIL"
	}

	slog.Info("audit_execution_summary",
		"run_id", runID,
		"timestamp", time.Now().UTC().Format(time.RFC3339),
		"environment", os.Getenv("JULA_GCP_PROJECT_ID"),
		"framework", *frameworkFlag,
		"overall_status", overallStatus,
		"total_controls_checked", len(findings),
		"passed", passed,
		"failed", failed,
		"excepted", excepted,
		"errored", errored,
		"evidence_files", len(manifest.EvidenceFiles),
		"evidence_location", *pathFlag,
		"signature", manifest.Signature[:16]+"...",
	)

	return nil
}
