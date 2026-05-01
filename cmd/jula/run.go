package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/alibkaba/jula-evidence-collector/internal/engine"
	"github.com/alibkaba/jula-evidence-collector/internal/mappers"
	"github.com/alibkaba/jula-evidence-collector/internal/reporter"

	// Import the GCP provider so its init() registers it.
	_ "github.com/alibkaba/jula-evidence-collector/internal/providers/gcp"
)

func handleRun(args []string) error {
	runCmd := flag.NewFlagSet("run", flag.ContinueOnError)

	providerFlag := runCmd.String("provider", os.Getenv("JULA_PROVIDER"), "Comma-separated provider(s) to execute (aws, gcp, github)")
	frameworkFlag := runCmd.String("framework", os.Getenv("JULA_FRAMEWORK"), "Target compliance framework (soc2, iso27001)")
	targetFlag := runCmd.String("target", os.Getenv("JULA_OUTPUT_TARGET"), "Delivery target: local, s3, gcs")
	pathFlag := runCmd.String("path", os.Getenv("JULA_OUTPUT_PATH"), "Target path or bucket URI")
	concurrencyFlag := runCmd.Int("concurrency", 3, "Max concurrent provider goroutines")
	timeoutFlag := runCmd.String("timeout", "5m", "Per-provider timeout duration")

	if err := runCmd.Parse(args); err != nil {
		return fmt.Errorf("parsing run flags: %w", err)
	}

	// Validate provider.
	if *providerFlag == "" {
		return fmt.Errorf("provider is required: use -provider or set JULA_PROVIDER")
	}
	providers := strings.Split(*providerFlag, ",")
	for _, p := range providers {
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

	// Generate a unique run ID.
	runID := fmt.Sprintf("run-%d", time.Now().UnixNano())

	slog.Info("run: full pipeline starting",
		"providers", providers,
		"framework", *frameworkFlag,
		"target", *targetFlag,
		"path", *pathFlag,
		"concurrency", *concurrencyFlag,
		"timeout", *timeoutFlag,
		"run_id", runID,
	)

	// --- Step 1: Extract ---
	orch := engine.New(engine.RunConfig{
		Providers:   providers,
		Framework:   *frameworkFlag,
		Target:      *targetFlag,
		Path:        *pathFlag,
		Concurrency: *concurrencyFlag,
		Timeout:     timeout,
		RunID:       runID,
	})

	ctx := context.Background()
	findings, err := orch.Extract(ctx)
	if err != nil {
		return fmt.Errorf("extraction failed: %w", err)
	}
	slog.Info("run: extraction complete", "findings_count", len(findings))

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
	signingKeyHex := strings.TrimSpace(os.Getenv("JULA_SIGNING_KEY"))
	signingKey, err := hex.DecodeString(signingKeyHex)
	if err != nil {
		return fmt.Errorf("decoding JULA_SIGNING_KEY (expected hex): %w", err)
	}

	var rep reporter.Reporter
	switch *targetFlag {
	case "local":
		rep = &reporter.LocalReporter{
			OutputDir:  *pathFlag,
			SigningKey: signingKey,
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

	slog.Info("run: pipeline complete",
		"run_id", runID,
		"evidence_files", len(manifest.EvidenceFiles),
		"signature", manifest.Signature[:16]+"...",
	)

	return nil
}

